"""Artifact-only ingestion of CipherLoop production v2; no runtime or fixture imports.

PASS concerns capture integrity and source locations, never audit/task success or
exploitability. Unavailable validation and observed execution failures return ERROR.
Malformed, unsupported, or uncommitted artifacts raise ProductionArtifactError.
"""

import ast
import hashlib
import json
import math
import uuid
from pathlib import Path

CONTRACT = "cipherloop-production-v2"
RESULT_VERSION = "traceforge-cipherloop-production-v1"


class ProductionArtifactError(ValueError):
    """Fail-closed input error with a stable diagnostic category."""

    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _require(condition, message, code="inconsistent"):
    if not condition:
        raise ProductionArtifactError(code, message)


def _object(value, keys):
    _require(type(value) is dict and set(value) == set(keys.split()), "invalid object fields")


def _integer(value, minimum=0):
    _require(type(value) is int and value >= minimum, "invalid integer")
    return value


def _text(value):
    _require(type(value) is str, "expected text")
    return value


def _parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key", "corrupt")
            result[key] = value
        return result

    def invalid(_value):
        raise ProductionArtifactError("corrupt", "nonfinite JSON number")

    value = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data,
                       object_pairs_hook=pairs, parse_constant=invalid)

    def finite(item):
        if type(item) is float:
            _require(math.isfinite(item), "nonfinite JSON number", "corrupt")
        elif type(item) is dict:
            for child in item.values():
                finite(child)
        elif type(item) is list:
            for child in item:
                finite(child)

    finite(value)
    return value


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _ref(rows, reference, kind, before):
    _integer(reference, 1)
    _require(reference < before, "forward or dangling reference")
    row = rows[reference - 1]
    _require(row["step_type"] == kind, f"reference must point to {kind}")
    return row["payload"]


def _summary(text):
    if not text.startswith("["):
        return None
    severity, sep, remainder = text[1:].partition("] ")
    location, separator, description = remainder.partition(" - ")
    path, colon, line = location.rpartition(":")
    if not (sep and separator and colon and line.isdigit()):
        return None
    return severity, path, int(line), description


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _check_finding(finding, parsed, read, span):
    """Independent AST location checks; deliberately no taint/detection oracle."""
    _object(finding, "id vulnerability_class severity source sink taint_path "
            "evidence_snippet confidence status")
    severity, path, line, description = parsed
    _require(finding["status"] == "VERIFIED", "invalid upstream finding status")
    _require(finding["id"] == f"VULN-{path.replace('/', '_')}-{line}", "finding ID mismatch")
    _require(finding["vulnerability_class"] == description, "finding description mismatch")
    expected = severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "MEDIUM"
    _require(finding["severity"] == expected, "finding severity mismatch")
    _require(type(finding["confidence"]) in (int, float)
             and finding["confidence"] == 0.9, "invalid upstream confidence")
    symbols = set()
    for node in ast.walk(ast.parse(read["text"])):
        symbol = _dotted(node)
        if symbol:
            symbols.add((node.lineno, symbol))
    endpoints = []
    for key in ("source", "sink"):
        location = finding[key]
        _object(location, "file line symbol")
        _integer(location["line"], 1)
        _text(location["symbol"])
        _require(location["file"] == path, "finding file mismatch")
        endpoints.append(f"{path}:{location['line']}:{location['symbol']}")
    _require(finding["sink"]["line"] == line, "candidate sink mismatch")
    trace = finding["taint_path"]
    _require(type(trace) is list and len(trace) >= 2, "missing path")
    _require([trace[0], trace[-1]] == endpoints, "path endpoint mismatch")
    lines = []
    for item in trace:
        filename, number, symbol = _text(item).rsplit(":", 2)
        number = int(number)
        _require(filename == path and (number, symbol) in symbols,
                 "path location absent from analyzed source")
        lines.append(number)
    _require(span["start_line"] == min(lines) and span["end_line"] == max(lines),
             "verified slice does not cover exact path")
    _require(finding["evidence_snippet"] == "AST-verified taint path: " + " -> ".join(trace),
             "finding evidence description mismatch")


def _compression(payload, raw):
    unavailable = None
    finding = payload["finding"]
    _require(type(finding) is dict, "invalid compression")
    for key in ("raw_char_count", "compressed_char_count"):
        _integer(finding[key])
    base = {k: v for k, v in finding.items()
            if k not in {"raw_char_count", "compressed_char_count"}}
    _require(finding["raw_char_count"] == len(raw["content"]), "raw count mismatch")
    _require(finding["compressed_char_count"] == len(
        json.dumps(base, ensure_ascii=False, sort_keys=True)), "compressed count mismatch")
    tool = raw["tool_name"]
    _require(finding["tool"] == ("run_semgrep" if "semgrep" in tool.lower() else tool),
             "compression tool mismatch")
    if "semgrep" in tool.lower() and "error" not in finding:
        _object(base, "tool total_findings critical_findings_count top_findings summary_note")
        try:
            data = _parse(raw["content"])
        except ProductionArtifactError:
            # Raw output is an observed string, not an artifact JSON object.
            # Recompute the producer's permissive parse independently, while
            # refusing to call ambiguous scanner output a clean observation.
            data = json.loads(raw["content"])
            unavailable = "ambiguous_scanner_json"
        if (data.get("error") or data.get("errors") or data.get("status") == "crash"
                or data.get("returncode", 0) not in (0, 1)):
            unavailable = "scanner_reported_error"
        results = data.get("results", [])
        critical = [r for r in results if r.get("extra", {}).get("severity", "").upper()
                    in {"WARNING", "ERROR"}]
        critical.sort(key=lambda r: r["extra"]["severity"].upper() != "ERROR")
        summaries = [f"[{r['extra']['severity']}] {r.get('path', 'Unknown')}:"
                     f"{r.get('start', {}).get('line', '?')} - "
                     f"{r['extra'].get('message', 'No description')}" for r in critical[:5]]
        _integer(finding["total_findings"])
        _integer(finding["critical_findings_count"])
        _require(finding["total_findings"] == len(results)
                 and finding["critical_findings_count"] == len(critical)
                 and finding["top_findings"] == summaries, "scanner selection/count mismatch")
        _require(finding["summary_note"] == (f"Found {len(results)} total issues. Showing top 5 critical."
                                             if len(results) > 5 else ""), "summary note mismatch")
    elif "semgrep" in tool.lower():
        unavailable = "malformed_scanner_json"
        _object(base, "tool error snippet")
        try:
            json.loads(raw["content"])
        except json.JSONDecodeError:
            pass
        else:
            raise ProductionArtifactError("inconsistent", "JSON parse failure claimed for valid JSON")
        _require(base["error"] == "Failed to parse JSON." and base["snippet"] == raw["content"][:250],
                 "invalid compression failure evidence")
    else:
        _object(base, "tool snippet truncated")
        text = raw["content"]
        if text.startswith(("Tool Execution Error", "System Error:")):
            unavailable = "tool_reported_error"
        lines = text.split("\n", 15)
        if len(text) > 3000:
            preview = text[:3000] + "\n... [TRUNCATED: Output exceeded 3000 characters. Refine search.]"
        else:
            preview = "\n".join(lines[:15])
            if len(lines) > 15:
                preview += "\n... [TRUNCATED: Output exceeded 15 lines. Refine search query.]"
        _require(type(base["truncated"]) is bool and base["truncated"] == (len(text) > 3000 or len(lines) > 15)
                 and base["snippet"] == preview, "generic compression mismatch")
    return unavailable


def _load(folder, run_id):
    _require(str(uuid.UUID(run_id)) == run_id, "invalid run UUID")
    folder = Path(folder)
    _require(not folder.is_symlink(), "symlinked run directory")
    ledger_path = folder / f"trajectory_{run_id}.jsonl"
    metadata_path = folder / f"metadata_{run_id}.json"
    _require(not ledger_path.is_symlink() and not metadata_path.is_symlink(),
             "symlinked artifact")
    _require(metadata_path.exists(), "missing final commitment", "incomplete")
    metadata_bytes = metadata_path.read_bytes()
    metadata = _parse(metadata_bytes)
    _require(metadata.get("contract_version") == CONTRACT, "unsupported contract", "unsupported")
    _object(metadata, "contract_version run_id target_directory final_plan total_retries "
            "compressed_findings_count trajectory_file total_raw_char_count "
            "total_compressed_char_count compression_ratio start_ref finish_ref "
            "execution_status ledger_sha256 event_count evidence_status report_ref "
            "final_finding_refs final_compression_refs")
    ledger = ledger_path.read_bytes()
    _require(ledger.endswith(b"\n"), "torn ledger", "corrupt")
    _require(_sha(ledger) == metadata["ledger_sha256"], "ledger hash mismatch", "corrupt")
    rows = [_parse(line) for line in ledger.split(b"\n")[:-1]]
    _integer(metadata["event_count"], 2)
    _require(metadata["event_count"] == len(rows), "event count mismatch")
    for index, row in enumerate(rows, 1):
        _object(row, "contract_version run_id seq timestamp step_type payload")
        _require(row["contract_version"] == CONTRACT, "mixed/unsupported version", "unsupported")
        _integer(row["seq"], 1)
        _require(row["seq"] == index and row["run_id"] == run_id, "event identity mismatch")
        _require(type(row["timestamp"]) in (int, float), "invalid timestamp")
        _require(type(row["payload"]) is dict, "invalid payload")
    _require(rows[0]["step_type"] == "run.started"
             and rows[-1]["step_type"] == "run.finished", "missing lifecycle boundaries")
    start, finish = rows[0]["payload"], rows[-1]["payload"]
    _object(start, "task target_directory tool_capture_boundary models")
    _object(start["task"], "description")
    _text(start["task"]["description"])
    _text(start["target_directory"])
    _require(start["tool_capture_boundary"] == "compressor_observed" and start["models"] is None,
             "unsupported observation/provenance boundary")
    _object(finish, "execution_status error")
    status = finish["execution_status"]
    _require(status in {"completed", "failed", "interrupted"}, "invalid lifecycle status")
    completed = status == "completed"
    if completed:
        _require(finish["error"] is None, "completed run has error")
    else:
        _object(finish["error"], "stage type message")
        for value in finish["error"].values():
            _text(value)
    for key in ("start_ref", "finish_ref"):
        _integer(metadata[key], 1)
    _require(metadata["run_id"] == run_id and metadata["start_ref"] == 1
             and metadata["finish_ref"] == len(rows) and metadata["execution_status"] == status,
             "metadata lifecycle mismatch")
    _require(metadata["evidence_status"] == "complete" and metadata["report_ref"] is None,
             "unsupported evidence/report status")
    _require(metadata["target_directory"] in (None, start["target_directory"]),
             "target mismatch")
    if metadata["final_plan"] is not None:
        _text(metadata["final_plan"])
    _text(metadata["trajectory_file"])  # Historical provenance, never an input path.
    _integer(metadata["total_retries"])

    calls, results, compressions, decisions = {}, {}, [], []
    consumed_results, reads, candidates, decided = set(), {}, {}, set()
    active, cycle_count, verified_count = None, 0, 0
    validated_compression_count = 0
    input_verified_count = 0
    eligible, attempts, cycle_decisions, retained = [], [], [], []
    boundaries, diagnostics, steps = {0}, [], []
    for row in rows[1:-1]:
        seq, kind, p = row["seq"], row["step_type"], row["payload"]
        if kind == "message":
            _require(active is None, "tool observation during validation")
            if p["type"] == "AIMessage":
                _object(p, "type role content tool_calls")
                _require(p["role"] == "assistant" and type(p["tool_calls"]) is list
                         and p["tool_calls"], "invalid assistant observation")
                _require(type(p["content"]) in (str, list), "invalid message content")
                for index, call in enumerate(p["tool_calls"]):
                    _require(set(call) in ({"id", "name", "args"}, {"id", "name", "args", "type"}),
                             "invalid tool call fields")
                    _require(call.get("type", "tool_call") == "tool_call", "invalid call type")
                    identifier = _text(call["id"])
                    _require(identifier and identifier not in calls, "duplicate/invalid call ID")
                    _require(_text(call["name"]) and type(call["args"]) is dict, "invalid call")
                    calls[identifier] = call["name"]
                    steps.append({"type": "tool_call", "event_ref": seq, "call_index": index,
                                  "tool_call_id": identifier, "tool_name": call["name"],
                                  "arguments": call["args"]})
            else:
                _object(p, "type role content tool_name tool_call_id")
                _require(p["type"] == "ToolMessage" and p["role"] == "tool", "unknown message")
                identifier = _text(p["tool_call_id"])
                _require(identifier and identifier not in results, "duplicate/invalid result ID")
                _require(bool(_text(p["tool_name"])), "missing tool name")
                _text(p["content"])
                results[identifier] = p["tool_name"]
                steps.append({"type": "tool_result", "event_ref": seq,
                              "tool_call_id": identifier, "tool_name": p["tool_name"]})
        elif kind == "compression":
            _require(active is None, "compression during validation")
            _object(p, "raw_result_ref state_index finding")
            raw = _ref(rows, p["raw_result_ref"], "message", seq)
            _require(raw["type"] == "ToolMessage" and p["raw_result_ref"] not in consumed_results,
                     "duplicate/orphan compression")
            _integer(p["state_index"])
            _require(p["state_index"] == len(compressions), "compression index gap")
            unavailable = _compression(p, raw)
            consumed_results.add(p["raw_result_ref"])
            compressions.append(row)
            if unavailable:
                diagnostics.append({"code": "tool_output_unavailable", "event_ref": seq,
                                    "reason": unavailable})
        elif kind == "validation.started":
            _object(p, "cycle compressed_findings_count verified_findings_count")
            for value in p.values():
                _integer(value)
            cycle_count += 1
            _require(active is None and p["cycle"] == cycle_count, "overlapping/gapped cycle")
            _require(p["compressed_findings_count"] == len(compressions)
                     and p["verified_findings_count"] == verified_count, "cycle state mismatch")
            active = seq
            validated_compression_count = len(compressions)
            input_verified_count = verified_count
            eligible = [(c["seq"], i) for c in compressions
                        for i, _ in enumerate(c["payload"]["finding"].get("top_findings", []))]
            attempts, cycle_decisions = [], []
        elif kind == "validation.candidate":
            _object(p, "cycle cycle_ref compression_ref summary_index summary")
            _integer(p["cycle"], 1)
            _ref(rows, p["cycle_ref"], "validation.started", seq)
            _require(p["cycle_ref"] == active and p["cycle"] == cycle_count, "candidate cycle mismatch")
            compressed = _ref(rows, p["compression_ref"], "compression", seq)
            _integer(p["summary_index"])
            _text(p["summary"])
            pair = (p["compression_ref"], p["summary_index"])
            _require(len(attempts) < len(eligible) and pair == eligible[len(attempts)],
                     "duplicate/orphan/out-of-order candidate")
            _require(p["summary"] == compressed["finding"]["top_findings"][p["summary_index"]],
                     "candidate summary mismatch")
            _require(len(cycle_decisions) == len(attempts), "candidate before previous decision")
            attempts.append(pair)
            candidates[seq] = p
        elif kind == "source.read":
            _object(p, "candidate_ref arguments status text text_sha256 error")
            candidate = _ref(rows, p["candidate_ref"], "validation.candidate", seq)
            _require(candidate["cycle_ref"] == active and p["candidate_ref"] not in reads
                     and p["candidate_ref"] not in decided, "duplicate/orphan source read")
            parsed = _summary(candidate["summary"])
            _require(parsed is not None, "source read for skipped candidate")
            _object(p["arguments"], "filepath start_line end_line")
            _integer(p["arguments"]["start_line"], 1)
            _integer(p["arguments"]["end_line"], 1)
            _require(p["arguments"] == {"filepath": parsed[1], "start_line": 1, "end_line": 1_000_000},
                     "source request mismatch")
            if p["status"] == "returned":
                _text(p["text"])
                _require(p["text_sha256"] == _sha(p["text"].encode()) and p["error"] is None,
                         "source hash/error mismatch")
            else:
                _require(p["status"] == "error" and p["text"] is None
                         and p["text_sha256"] is None, "invalid source status")
                _object(p["error"], "stage type message")
                for value in p["error"].values():
                    _text(value)
                _require(p["error"]["stage"] == "validation_read", "invalid source error stage")
            reads[p["candidate_ref"]] = seq
        elif kind == "validation.decision":
            _object(p, "candidate_ref disposition reason source_read_ref finding source_slice")
            candidate = _ref(rows, p["candidate_ref"], "validation.candidate", seq)
            _require(candidate["cycle_ref"] == active and p["candidate_ref"] not in decided,
                     "duplicate/orphan decision")
            parsed = _summary(candidate["summary"])
            span, reason, disposition = p["source_slice"], p["reason"], p["disposition"]
            if parsed is None:
                _require(disposition == "skipped" and reason == "malformed_summary"
                         and p["source_read_ref"] is None and span is None and p["finding"] is None,
                         "invalid skipped decision")
            else:
                read = _ref(rows, p["source_read_ref"], "source.read", seq)
                _require(reads.get(p["candidate_ref"]) == p["source_read_ref"], "decision read mismatch")
                expected_error = "read_exception" if read["status"] == "error" else (
                    "read_error_marker" if any(marker in read["text"]
                                               for marker in ("Tool Execution Error", "System Error"))
                    else None)
                if span is not None:
                    _object(span, "source_read_ref start_line end_line")
                    _integer(span["source_read_ref"], 1)
                    _integer(span["start_line"], 1)
                    _integer(span["end_line"], 1)
                    _require(span["source_read_ref"] == p["source_read_ref"] and read["status"] == "returned"
                             and span["start_line"] <= span["end_line"] <= len(read["text"].splitlines()),
                             "invalid source slice")
                if disposition == "verified":
                    _require(expected_error is None and reason is None and span is not None,
                             "verified claim lacks source")
                    _check_finding(p["finding"], parsed, read, span)
                else:
                    _require(disposition == "rejected" and p["finding"] is None, "invalid rejection")
                    if expected_error:
                        _require(reason == expected_error and span is None, "read failure disguised as rejection")
                    else:
                        _require(reason in {"syntax_error", "no_taint_trace"}, "invalid rejection reason")
                        try:
                            ast.parse(read["text"])
                        except SyntaxError:
                            _require(reason == "syntax_error", "syntax failure disguised as no trace")
                        else:
                            _require(reason == "no_taint_trace", "syntax failure claimed for valid source")
                        expected_span = {"source_read_ref": p["source_read_ref"], "start_line": 1,
                                         "end_line": len(read["text"].splitlines())} if read["text"] else None
                        _require(span == expected_span, "rejection slice mismatch")
            if reason in {"malformed_summary", "read_exception", "read_error_marker", "syntax_error"}:
                diagnostics.append({"code": "validation_unavailable", "reason": reason, "event_ref": seq})
            decided.add(p["candidate_ref"])
            decisions.append(row)
            cycle_decisions.append(row)
        elif kind == "validation":
            _object(p, "cycle cycle_ref total_candidates verified_count rejected_count candidate_to_verified_ratio")
            _ref(rows, p["cycle_ref"], "validation.started", seq)
            for key in ("cycle", "total_candidates", "verified_count", "rejected_count"):
                _integer(p[key])
            _require(active == p["cycle_ref"] and p["cycle"] == cycle_count, "aggregate cycle mismatch")
            _require(attempts == eligible and len(cycle_decisions) == len(attempts), "incomplete cycle")
            verified = [d for d in cycle_decisions if d["payload"]["disposition"] == "verified"]
            rejected = sum(d["payload"]["disposition"] == "rejected" for d in cycle_decisions)
            total = len(verified) + rejected
            ratio = total / len(verified) if verified else None
            _require(p["total_candidates"] == total and p["verified_count"] == len(verified)
                     and p["rejected_count"] == rejected and p["candidate_to_verified_ratio"] == ratio,
                     "validation arithmetic mismatch")
            _require(p["candidate_to_verified_ratio"] is None
                     or type(p["candidate_to_verified_ratio"]) in (int, float), "invalid ratio")
            retained.extend(d["seq"] for d in verified)
            verified_count += len(verified)
            boundaries.add(verified_count)
            active = None
        else:
            raise ProductionArtifactError("unsupported", f"unknown event: {kind}")

    for identifier in calls.keys() & results.keys():
        _require(calls[identifier] == results[identifier], "call/result name mismatch")
    if completed:
        _require(calls == results and len(consumed_results) == len(results), "unpaired tool evidence")
        _require(active is None and len(decided) == len(candidates), "unfinished validation")
        _require(validated_compression_count == len(compressions), "unvalidated compressed observations")
        _require(cycle_count > 0, "completed run lacks observed validation")
    else:
        diagnostics.append({"code": f"execution_{status}", "error": finish["error"]})

    final_refs, compression_refs = metadata["final_finding_refs"], metadata["final_compression_refs"]
    _require(type(final_refs) is list and type(compression_refs) is list, "invalid final references")
    for ref in final_refs:
        _ref(rows, ref, "validation.decision", len(rows))
    for ref in compression_refs:
        _ref(rows, ref, "compression", len(rows))
    _require(len(final_refs) in boundaries and final_refs == retained[:len(final_refs)],
             "final finding references are not a retained state prefix")
    _require(compression_refs == [c["seq"] for c in compressions[:len(compression_refs)]],
             "final compression reference mismatch")
    _require(len(compression_refs) >= validated_compression_count
             and len(final_refs) >= input_verified_count,
             "final state omits an observed validation input state")
    if completed:
        _require(final_refs == retained and len(compression_refs) == len(compressions),
                 "completed final state omitted evidence")
    captured = [c["payload"]["finding"] for c in compressions[:len(compression_refs)]]
    raw_count = sum(f["raw_char_count"] for f in captured)
    compressed_count = sum(f["compressed_char_count"] for f in captured)
    for key, expected in (("compressed_findings_count", len(captured)),
                          ("total_raw_char_count", raw_count),
                          ("total_compressed_char_count", compressed_count)):
        _integer(metadata[key])
        _require(metadata[key] == expected, "final count mismatch")
    _require(metadata["compression_ratio"] is None
             or type(metadata["compression_ratio"]) in (int, float), "invalid compression ratio")
    _require(metadata["compression_ratio"] == (raw_count / compressed_count if compressed_count else None),
             "final ratio mismatch")
    return {
        "format_version": RESULT_VERSION,
        "status": "ERROR" if diagnostics else "PASS",
        "scope": "capture_integrity_and_source_locations",
        "run_id": run_id,
        "task": start["task"],
        "execution_status": status,
        "diagnostics": diagnostics,
        "steps": steps,
        "final_findings": [{"decision_ref": ref, "finding": rows[ref - 1]["payload"]["finding"]}
                           for ref in final_refs],
        "provenance": {"producer_contract": CONTRACT, "ledger_sha256": _sha(ledger),
                       "metadata_sha256": _sha(metadata_bytes),
                       "adapter_sha256": _sha(Path(__file__).read_bytes())},
        "unavailable": ["task_success", "detection_accuracy", "exploitability", "models", "report"],
    }


def ingest_run(folder, run_id):
    """Read only the two named artifacts from a quiescent copied run directory.

    Never follows metadata's original target/ledger paths or loads CipherLoop.
    No output file is published; callers receive a result or an explicit error.
    """
    try:
        return _load(folder, run_id)
    except ProductionArtifactError:
        raise
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError,
            OverflowError, RecursionError, SyntaxError) as exc:
        raise ProductionArtifactError("corrupt", f"invalid production evidence: {exc}") from exc

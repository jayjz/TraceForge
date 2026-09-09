"""Strict adapter for the two-case v1 capture contract. Never imports CipherLoop."""

import json
import math
from datetime import datetime, timezone

from jsonschema import Draft202012Validator, FormatChecker

from traceforge.evaluation.baseline_contract import (
    ROOT,
    ArtifactError,
    canonical_artifact,
    digest,
    parse,
    provenance,
    read,
    require,
    sha,
)


def match_messages(rows, run_id):
    """Expand calls in ledger order; reject duplicates, orphans and partial calls."""
    steps, events, calls, results = [], [], {}, set()
    for number, row in enumerate(rows, 1):
        ref = {"artifact": f"trajectory_{run_id}.jsonl", "row": number}
        require(row["run_id"] == run_id, f"row {number}: run_id mismatch")
        timestamp = row["timestamp"]
        require(
            type(timestamp) in (int, float) and math.isfinite(timestamp),
            f"row {number}: invalid timestamp",
        )
        stamp = (
            datetime.fromtimestamp(timestamp, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        payload = row["payload"]
        if row["step_type"] == "validation":
            require(not calls.keys() - results, "validation before all tool results")
            events.append({"payload": payload, "reference": ref})
            continue
        require(row["step_type"] == "message", f"row {number}: unknown event")
        require(not events, "message after validation")
        mapped = []
        if payload["type"] == "AIMessage" and payload["role"] == "assistant":
            require(payload["tool_calls"], "empty tool calls")
            for call in payload["tool_calls"]:
                call_id = call["id"]
                require(
                    isinstance(call_id, str) and call_id and call_id not in calls,
                    "duplicate or invalid tool call ID",
                )
                require(
                    isinstance(call["name"], str) and isinstance(call["args"], dict),
                    "invalid tool call",
                )
                calls[call_id] = call["name"]
                mapped.append(
                    {
                        "type": "tool_call",
                        "tool_call_id": call_id,
                        "tool_name": call["name"],
                        "arguments": call["args"],
                        "content": payload["content"],
                    }
                )
        elif payload["type"] == "ToolMessage" and payload["role"] == "tool":
            call_id = payload["tool_call_id"]
            require(call_id in calls, "orphan tool result")
            require(call_id not in results, "duplicate tool result")
            require(payload["tool_name"] == calls[call_id], "tool result name mismatch")
            require(
                isinstance(payload["content"], str), "tool result must contain text"
            )
            results.add(call_id)
            mapped.append(
                {
                    "type": "tool_result",
                    "tool_call_id": call_id,
                    "tool_name": payload["tool_name"],
                    "result": payload["content"],
                }
            )
        else:
            raise ArtifactError(f"row {number}: unsupported message")
        for step in mapped:
            steps.append(
                {
                    "step_id": len(steps) + 1,
                    **step,
                    "timestamp": stamp,
                    "cipherloop_reference": ref,
                }
            )
    require(set(calls) == results, "missing tool result")
    require(len(events) == 1, "exactly one validation cycle required")
    return steps, events


def validate_normalized(trajectory):
    schema = read(ROOT / "schemas/trajectory.schema.json")
    Draft202012Validator.check_schema(schema)
    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            trajectory
        )
    )
    require(not errors, "schema: " + "; ".join(e.message for e in errors))
    steps = trajectory["steps"]
    require(
        [s["step_id"] for s in steps] == list(range(1, len(steps) + 1)),
        "step IDs must be ordered and unique",
    )


def _load_case(folder, case):
    case_id = case["id"]
    index = read(folder.parent / "index.json")
    require(index["provenance"] == provenance(), "incompatible provenance")
    require(set(index["cases"]) == {"toy", "safe"}, "incomplete case index")
    source = (folder / "source.py").read_bytes()
    require(
        sha(source)
        == case["source_sha256"]
        == index["cases"][case_id]["source_sha256"],
        "source hash mismatch",
    )
    rows = [
        parse(line)
        for line in (folder / f"trajectory_{case_id}.jsonl").read_text().splitlines()
    ]
    metadata = read(folder / f"metadata_{case_id}.json")
    capture = read(folder / "capture.json")
    for name, value in (("ledger", rows), ("metadata", metadata), ("capture", capture)):
        require(
            digest(canonical_artifact(name, value))
            == index["cases"][case_id][f"{name}_sha256"],
            f"{name} hash mismatch",
        )
    steps, events = match_messages(rows, case_id)
    require(
        len(rows) == 3 and len(steps) == 2,
        "baseline requires one call/result pair and one validation event",
    )
    require(
        steps[0]["tool_name"] == "run_semgrep"
        and steps[0]["arguments"] == {"target_path": "app.py"},
        "unexpected scanner call",
    )
    require(steps[0]["tool_call_id"] == f"{case_id}-scan", "unexpected scanner call ID")
    raw = steps[1]["result"]
    require(
        parse(raw) == {"results": [case["candidate"]]},
        "scanner input differs from manifest",
    )
    require(
        capture["scanner_input_sha256"] == sha(raw.encode()),
        "scanner input hash mismatch",
    )
    require(
        capture["run_id"] == metadata["run_id"] == case_id, "artifact run_id mismatch"
    )
    require(
        capture["execution_status"] == "completed"
        and capture["synthetic_scanner"] is True,
        "capture incomplete or not synthetic",
    )
    require(
        capture["unavailable"]
        == [
            "original_agent_task",
            "final_report",
            "models",
            "recovery",
            "safety",
            "cost",
            "tokens",
            "rubric_scores",
        ],
        "unsupported information must remain unavailable",
    )
    require(
        capture["source_sha256"] == case["source_sha256"],
        "capture source hash mismatch",
    )
    require(
        capture["references"]
        == {"raw_result_row": 2, "validation_row": 3, "source": "source.py"},
        "invalid evidence references",
    )
    require(
        capture["validation_reads"]
        == [
            {
                "arguments": {
                    "filepath": "app.py",
                    "start_line": 1,
                    "end_line": 1_000_000,
                },
                "status": "ok",
                "source_sha256": case["source_sha256"],
            }
        ],
        "missing or failed validation read",
    )
    require(
        capture["removed_message_ids"] == [f"{case_id}-ai", f"{case_id}-tool"]
        and capture["remaining_messages"] == 0,
        "incomplete message shearing",
    )
    span = case["slice"]
    text = "".join(
        source.decode().splitlines(keepends=True)[
            span["start_line"] - 1 : span["end_line"]
        ]
    )
    require(
        capture["source_slice"] == {**span, "file": "app.py", "text": text},
        "source slice mismatch",
    )

    # Independently reconcile the narrow single-candidate compression contract.
    candidate = case["candidate"]
    base = {
        "tool": "run_semgrep",
        "total_findings": 1,
        "critical_findings_count": 1,
        "top_findings": [
            f"[ERROR] app.py:{candidate['start']['line']} - Command injection"
        ],
        "summary_note": "",
    }
    compressed_size = len(json.dumps(base, ensure_ascii=False, sort_keys=True))
    require(
        capture["compressed_findings"]
        == [
            {
                **base,
                "raw_char_count": len(raw),
                "compressed_char_count": compressed_size,
            }
        ],
        "compressor output/count mismatch",
    )
    require(
        canonical_artifact("metadata", metadata)
        == {
            "run_id": case_id,
            "target_directory": "/workspace/target_repo",
            "final_plan": None,
            "total_retries": 0,
            "compressed_findings_count": 1,
            "total_raw_char_count": len(raw),
            "total_compressed_char_count": compressed_size,
            "compression_ratio": len(raw) / compressed_size,
        },
        "recorder metadata/count mismatch",
    )
    require(
        isinstance(metadata["trajectory_file"], str)
        and metadata["trajectory_file"].endswith(f"/trajectory_{case_id}.jsonl"),
        "invalid recorder ledger path",
    )
    findings = capture["verified_findings"]
    require(
        isinstance(findings, list) and len(findings) <= 1,
        "duplicate or excess findings",
    )
    for finding in findings:
        require(finding["status"] == "VERIFIED", "finding not verified")
        require(
            finding["id"] == f"VULN-app.py-{candidate['start']['line']}",
            "finding ID mismatch",
        )
        require(
            finding["vulnerability_class"] == candidate["extra"]["message"]
            and finding["severity"] == "MEDIUM",
            "finding candidate mismatch",
        )
        require(
            type(finding["confidence"]) in (int, float)
            and 0 <= finding["confidence"] <= 1,
            "invalid upstream confidence",
        )
        for key in ("source", "sink"):
            location = finding[key]
            require(
                location["file"] == "app.py"
                and type(location["line"]) is int
                and span["start_line"] <= location["line"] <= span["end_line"],
                "finding outside source slice",
            )
            require(
                isinstance(location["symbol"], str)
                and location["symbol"]
                in source.decode().splitlines()[location["line"] - 1],
                "finding symbol absent from source",
            )
        require(
            finding["sink"]["line"] == candidate["start"]["line"],
            "finding sink does not match candidate",
        )
        path = finding["taint_path"]
        require(isinstance(path, list) and len(path) >= 2, "missing taint path")
        for key, item in (("source", path[0]), ("sink", path[-1])):
            loc = finding[key]
            require(
                item == f"{loc['file']}:{loc['line']}:{loc['symbol']}",
                "path endpoint mismatch",
            )
        for item in path:
            file, line, symbol = item.split(":")
            require(
                file == "app.py"
                and span["start_line"] <= int(line) <= span["end_line"]
                and symbol in source.decode().splitlines()[int(line) - 1],
                "path not backed by source slice",
            )
        require(
            finding["evidence_snippet"]
            == "AST-verified taint path: " + " -> ".join(path),
            "AST evidence mismatch",
        )
    count = len(findings)
    require(
        all(
            type(events[0]["payload"][key]) is int
            for key in ("total_candidates", "verified_count", "rejected_count")
        ),
        "validation counts must be integers",
    )
    require(
        events[0]["payload"]
        == {
            "total_candidates": 1,
            "verified_count": count,
            "rejected_count": 1 - count,
            "candidate_to_verified_ratio": 1 / count if count else None,
        },
        "validation count mismatch",
    )
    return steps, events, metadata, capture, index["provenance"]


def load_case(folder, case):
    """Return checked evidence; all malformed input becomes an explicit error."""
    try:
        return _load_case(folder, case)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError,
        AttributeError,
    ) as exc:
        raise ArtifactError(f"{case['id']}: {exc}") from exc

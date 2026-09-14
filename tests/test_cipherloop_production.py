"""Independent contract fixtures plus adversarial production-ingestion checks.

The six actual producer smoke bundles are checked separately by the documented
cross-repository command; these tests require no CipherLoop installation or target.
"""

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from traceforge.adapters.cipherloop_production import (
    CONTRACT,
    ProductionArtifactError,
    ingest_run,
)

RUN_ID = "00000000-0000-4000-8000-000000000001"
SOURCE = "import os\nx = input()\nos.system(x)\n"


def _hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _fixture(kind="verified"):
    source = SOURCE if kind != "rejected" else "import os\nx = 'safe'\nos.system(x)\n"
    raw = json.dumps({"results": [] if kind == "zero" else [{
        "path": "app.py", "start": {"line": 3},
        "extra": {"severity": "ERROR", "message": "Command injection"},
    }]})
    base = {"tool": "run_semgrep", "total_findings": int(kind != "zero"),
            "critical_findings_count": int(kind != "zero"),
            "top_findings": [] if kind == "zero" else ["[ERROR] app.py:3 - Command injection"],
            "summary_note": ""}
    compressed = {**base, "raw_char_count": len(raw),
                  "compressed_char_count": len(json.dumps(base, ensure_ascii=False, sort_keys=True))}
    finding = {"id": "VULN-app.py-3", "vulnerability_class": "Command injection", "severity": "MEDIUM",
               "source": {"file": "app.py", "line": 2, "symbol": "input"},
               "sink": {"file": "app.py", "line": 3, "symbol": "os.system"},
               "taint_path": ["app.py:2:input", "app.py:2:x", "app.py:3:os.system"],
               "evidence_snippet": "AST-verified taint path: app.py:2:input -> app.py:2:x -> app.py:3:os.system",
               "confidence": 0.9, "status": "VERIFIED"}
    events = [
        ("run.started", {"task": {"description": "Independent contract fixture"}, "target_directory": "/gone",
                         "tool_capture_boundary": "compressor_observed", "models": None}),
        ("message", {"type": "AIMessage", "role": "assistant", "content": "", "tool_calls": [
            {"id": "scan", "name": "run_semgrep", "args": {"target_path": "app.py"}, "type": "tool_call"}]}),
        ("message", {"type": "ToolMessage", "role": "tool", "content": raw,
                     "tool_name": "run_semgrep", "tool_call_id": "scan"}),
        ("compression", {"raw_result_ref": 3, "state_index": 0, "finding": compressed}),
        ("validation.started", {"cycle": 1, "compressed_findings_count": 1, "verified_findings_count": 0}),
    ]
    if kind != "zero":
        events.extend([
            ("validation.candidate", {"cycle": 1, "cycle_ref": 5, "compression_ref": 4,
                                      "summary_index": 0, "summary": base["top_findings"][0]}),
            ("source.read", {"candidate_ref": 6, "arguments": {"filepath": "app.py", "start_line": 1,
                                                              "end_line": 1_000_000},
                             "status": "returned", "text": source, "text_sha256": _hash(source), "error": None}),
            ("validation.decision", {"candidate_ref": 6, "disposition": "rejected" if kind == "rejected" else "verified",
                                     "reason": "no_taint_trace" if kind == "rejected" else None,
                                     "source_read_ref": 7, "finding": None if kind == "rejected" else finding,
                                     "source_slice": {"source_read_ref": 7, "start_line": 1 if kind == "rejected" else 2,
                                                      "end_line": 3}}),
        ])
    verified = kind not in {"zero", "rejected"}
    events.append(("validation", {"cycle": 1, "cycle_ref": 5, "total_candidates": int(kind != "zero"),
                                  "verified_count": int(verified), "rejected_count": int(kind == "rejected"),
                                  "candidate_to_verified_ratio": 1.0 if verified else None}))
    status = kind if kind in {"failed", "interrupted"} else "completed"
    events.append(("run.finished", {"execution_status": status, "error": None if status == "completed" else {
        "stage": "graph_execution", "type": "Error", "message": "scripted failure"}}))
    rows = [{"contract_version": CONTRACT, "run_id": RUN_ID, "seq": i, "timestamp": 1000.0,
             "step_type": step, "payload": payload} for i, (step, payload) in enumerate(events, 1)]
    metadata = {"contract_version": CONTRACT, "run_id": RUN_ID, "target_directory": "/gone",
                "final_plan": None, "total_retries": 0, "compressed_findings_count": 1,
                "trajectory_file": "/gone/ignored.jsonl", "total_raw_char_count": len(raw),
                "total_compressed_char_count": compressed["compressed_char_count"],
                "compression_ratio": len(raw) / compressed["compressed_char_count"],
                "start_ref": 1, "finish_ref": len(rows), "execution_status": status,
                "ledger_sha256": "", "event_count": len(rows), "evidence_status": "complete",
                "report_ref": None, "final_compression_refs": [4],
                "final_finding_refs": [8] if kind == "verified" else []}
    return rows, metadata


def _write(folder, rows, metadata):
    ledger = "".join(json.dumps(row) + "\n" for row in rows)
    metadata["ledger_sha256"] = _hash(ledger)
    (folder / f"trajectory_{RUN_ID}.jsonl").write_text(ledger)
    (folder / f"metadata_{RUN_ID}.json").write_text(json.dumps(metadata))


def _insert(rows, metadata, index, added):
    """Insert structurally valid rows, shifting old refs so tests reach semantic checks."""
    count = len(added)

    def shift(value):
        if type(value) is list:
            for item in value:
                shift(item)
        elif type(value) is dict:
            for key, item in value.items():
                if key.endswith("_ref") and type(item) is int and item > index:
                    value[key] += count
                elif key.endswith("_refs") and type(item) is list:
                    value[key] = [ref + count if ref > index else ref for ref in item]
                else:
                    shift(item)

    shift(rows)
    shift(metadata)
    for offset, row in enumerate(added, index + 1):
        row.update(contract_version=CONTRACT, run_id=RUN_ID, timestamp=1000.0, seq=offset)
    rows[index:index] = added
    for seq, row in enumerate(rows, 1):
        row["seq"] = seq
    metadata["event_count"] = len(rows)


@pytest.mark.parametrize("kind", ["verified", "zero", "rejected", "failed", "interrupted"])
def test_standalone_production_outcomes(tmp_path, kind):
    rows, metadata = _fixture(kind)
    _write(tmp_path, rows, metadata)
    result = ingest_run(tmp_path, RUN_ID)
    assert result["status"] == ("ERROR" if kind in {"failed", "interrupted"} else "PASS")
    assert len(result["final_findings"]) == int(kind == "verified")
    assert result["execution_status"] == metadata["execution_status"]
    assert '"success":' not in json.dumps(result)
    assert "task_success" in result["unavailable"]
    assert len(list(tmp_path.iterdir())) == 2  # Ingestion never publishes a result file.


@pytest.mark.parametrize("mutation", [
    "version", "mixed_version", "seq", "bool_seq", "run_id", "unknown_event", "hash",
    "missing_commit", "torn", "duplicate_key", "nan", "overflow_number", "forward_ref",
    "wrong_ref_type", "bool_ref", "source_hash", "source_symbol", "slice", "candidate",
    "aggregate", "final_missing", "final_duplicate", "final_orphan", "metadata_count",
    "compression_count", "compression_selection", "lifecycle", "duplicate_call", "orphan_call",
    "report", "cycle_count", "bool_ratio", "metadata_duplicate", "missing_cycle_end",
])
def test_fail_closed_on_corrupt_or_inconsistent_evidence(tmp_path, mutation):
    rows, metadata = _fixture()
    if mutation == "version":
        metadata["contract_version"] = "cipherloop-production-v1"
    elif mutation == "mixed_version":
        rows[3]["contract_version"] = "cipherloop-production-v99"
    elif mutation in {"seq", "bool_seq"}:
        rows[0]["seq"] = True if mutation == "bool_seq" else 2
    elif mutation == "run_id":
        rows[3]["run_id"] = "different"
    elif mutation == "unknown_event":
        rows[5]["step_type"] = "candidate"
    elif mutation in {"forward_ref", "wrong_ref_type", "bool_ref"}:
        rows[7]["payload"]["source_read_ref"] = {"forward_ref": 9, "wrong_ref_type": 5, "bool_ref": True}[mutation]
    elif mutation == "source_hash":
        rows[6]["payload"]["text"] += "# tampered\n"
    elif mutation == "source_symbol":
        text = "import os\nx = constant() # input\nos.system(x)\n"
        rows[6]["payload"].update(text=text, text_sha256=_hash(text))
    elif mutation == "slice":
        rows[7]["payload"]["source_slice"]["end_line"] = 100
    elif mutation == "candidate":
        rows[5]["payload"]["summary"] = "[ERROR] other.py:3 - Command injection"
    elif mutation == "aggregate":
        rows[8]["payload"]["verified_count"] = 0
    elif mutation.startswith("final_"):
        metadata["final_finding_refs"] = {"final_missing": [], "final_duplicate": [8, 8], "final_orphan": [7]}[mutation]
    elif mutation == "metadata_count":
        metadata["compressed_findings_count"] = 0
    elif mutation == "compression_count":
        rows[3]["payload"]["finding"]["raw_char_count"] = 0
    elif mutation == "compression_selection":
        rows[3]["payload"]["finding"]["top_findings"] = []
        base = {k: v for k, v in rows[3]["payload"]["finding"].items() if not k.endswith("char_count")}
        rows[3]["payload"]["finding"]["compressed_char_count"] = len(json.dumps(base, ensure_ascii=False, sort_keys=True))
    elif mutation == "lifecycle":
        metadata["execution_status"] = "failed"
    elif mutation == "duplicate_call":
        rows[1]["payload"]["tool_calls"] *= 2
    elif mutation == "orphan_call":
        rows[1]["payload"]["tool_calls"][0]["id"] = "other"
    elif mutation == "report":
        metadata["report_ref"] = 8
    elif mutation == "cycle_count":
        rows[4]["payload"]["verified_findings_count"] = 1
    elif mutation == "bool_ratio":
        rows[8]["payload"]["candidate_to_verified_ratio"] = True
    elif mutation == "missing_cycle_end":
        rows[8]["step_type"] = "validation.started"
        rows[8]["payload"] = {"cycle": 2, "compressed_findings_count": 1, "verified_findings_count": 0}
    _write(tmp_path, rows, metadata)
    ledger = tmp_path / f"trajectory_{RUN_ID}.jsonl"
    meta = tmp_path / f"metadata_{RUN_ID}.json"
    if mutation == "hash":
        ledger.write_text(ledger.read_text().replace("Independent", "Tampered"))
    elif mutation == "missing_commit":
        meta.unlink()
    elif mutation == "torn":
        ledger.write_text(ledger.read_text()[:-3])
    elif mutation in {"duplicate_key", "nan", "overflow_number"}:
        text = ledger.read_text()
        if mutation == "duplicate_key":
            text = text.replace('"seq": 1,', '"seq": 1, "seq": 1,', 1)
        else:
            text = text.replace('"timestamp": 1000.0', '"timestamp": ' + ("NaN" if mutation == "nan" else "1e999"), 1)
        ledger.write_text(text)
        metadata["ledger_sha256"] = _hash(text)
        meta.write_text(json.dumps(metadata))
    elif mutation == "metadata_duplicate":
        meta.write_text(meta.read_text().replace('"event_count": 10', '"event_count": 10, "event_count": 10'))
    with pytest.raises(ProductionArtifactError) as error:
        ingest_run(tmp_path, RUN_ID)
    if mutation == "missing_commit":
        assert error.value.code == "incomplete"
    elif mutation in {"version", "mixed_version", "unknown_event"}:
        assert error.value.code == "unsupported"


@pytest.mark.parametrize("index", [2, 3, 5, 6, 7, 8])
def test_duplicate_relationships_rejected_with_valid_sequences_and_hashes(tmp_path, index):
    rows, metadata = _fixture()
    _insert(rows, metadata, index + 1, [copy.deepcopy(rows[index])])
    _write(tmp_path, rows, metadata)
    with pytest.raises(ProductionArtifactError):
        ingest_run(tmp_path, RUN_ID)


def test_repeated_cycles_keep_distinct_decision_refs_with_same_finding_id(tmp_path):
    rows, metadata = _fixture()
    added = copy.deepcopy(rows[4:9])
    for row in added:
        p = row["payload"]
        if "cycle" in p:
            p["cycle"] = 2
        for key in ("cycle_ref", "candidate_ref", "source_read_ref"):
            if key in p:
                p[key] += 5
        if row["step_type"] == "validation.started":
            p["verified_findings_count"] = 1
        if row["step_type"] == "validation.decision":
            p["source_slice"]["source_read_ref"] += 5
    _insert(rows, metadata, 9, added)
    metadata["final_finding_refs"] = [8, 13]
    _write(tmp_path, rows, metadata)
    result = ingest_run(tmp_path, RUN_ID)
    assert [f["decision_ref"] for f in result["final_findings"]] == [8, 13]
    assert result["final_findings"][0]["finding"] == result["final_findings"][1]["finding"]


def test_multiple_calls_and_different_result_order(tmp_path):
    rows, metadata = _fixture()
    rows[1]["payload"]["tool_calls"].insert(0, {"id": "search", "name": "search_code", "args": {}})
    finding = {"tool": "search_code", "snippet": "result", "truncated": False}
    size = len(json.dumps(finding, ensure_ascii=False, sort_keys=True))
    finding.update(raw_char_count=6, compressed_char_count=size)
    _insert(rows, metadata, 4, [
        {"step_type": "message", "payload": {"type": "ToolMessage", "role": "tool", "content": "result",
                                              "tool_call_id": "search", "tool_name": "search_code"}},
        {"step_type": "compression", "payload": {"raw_result_ref": 5, "state_index": 1, "finding": finding}},
    ])
    rows[6]["payload"]["compressed_findings_count"] = 2
    metadata["compressed_findings_count"] = 2
    metadata["final_compression_refs"] = [4, 6]
    metadata["total_raw_char_count"] += 6
    metadata["total_compressed_char_count"] += size
    metadata["compression_ratio"] = metadata["total_raw_char_count"] / metadata["total_compressed_char_count"]
    _write(tmp_path, rows, metadata)
    result = ingest_run(tmp_path, RUN_ID)
    assert result["status"] == "PASS"
    assert [s["tool_call_id"] for s in result["steps"]] == ["search", "scan", "scan", "search"]


def test_unavailable_source_does_not_become_successful_zero(tmp_path):
    rows, metadata = _fixture("rejected")
    rows[6]["payload"].update(status="error", text=None, text_sha256=None,
                              error={"stage": "validation_read", "type": "OSError", "message": "unavailable"})
    rows[7]["payload"].update(reason="read_exception", source_slice=None)
    _write(tmp_path, rows, metadata)
    result = ingest_run(tmp_path, RUN_ID)
    assert result["status"] == "ERROR"
    assert result["diagnostics"][0]["code"] == "validation_unavailable"


@pytest.mark.parametrize(("text", "reason", "expected"), [
    ("Tool Execution Error: unavailable", "read_error_marker", "ERROR"),
    ("System Error: unavailable", "read_error_marker", "ERROR"),
    ("def broken(:\n", "syntax_error", "ERROR"),
    ("", "no_taint_trace", "PASS"),
])
def test_rejection_and_failure_source_spans(tmp_path, text, reason, expected):
    rows, metadata = _fixture("rejected")
    rows[6]["payload"].update(text=text, text_sha256=_hash(text))
    span = {"source_read_ref": 7, "start_line": 1, "end_line": 1} if reason == "syntax_error" else None
    rows[7]["payload"].update(reason=reason, source_slice=span)
    _write(tmp_path, rows, metadata)
    assert ingest_run(tmp_path, RUN_ID)["status"] == expected


def test_false_no_trace_claim_cannot_hide_syntax_failure(tmp_path):
    rows, metadata = _fixture("rejected")
    text = "def broken(:\n"
    rows[6]["payload"].update(text=text, text_sha256=_hash(text))
    rows[7]["payload"]["source_slice"]["end_line"] = 1
    _write(tmp_path, rows, metadata)
    with pytest.raises(ProductionArtifactError, match="syntax failure disguised"):
        ingest_run(tmp_path, RUN_ID)


def test_copied_bundle_has_no_target_dependency(tmp_path):
    rows, metadata = _fixture()
    _write(tmp_path, rows, metadata)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    assert ingest_run(tmp_path, RUN_ID) == ingest_run(tmp_path, RUN_ID)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_ingestion_in_python_without_site_packages_or_cipherloop(tmp_path):
    rows, metadata = _fixture()
    _write(tmp_path, rows, metadata)
    source_root = Path(ingest_run.__code__.co_filename).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-S", "-c",
         "import sys; from traceforge.adapters.cipherloop_production import ingest_run; "
         "assert ingest_run(sys.argv[1], sys.argv[2])['status'] == 'PASS'; "
         "assert 'cipherloop' not in sys.modules", str(tmp_path), RUN_ID],
        env={"PYTHONPATH": str(source_root)}, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_compression_without_any_validation_is_not_a_completed_negative(tmp_path):
    rows, metadata = _fixture()
    rows = rows[:4] + [rows[-1]]
    rows[-1]["seq"] = 5
    metadata.update(event_count=5, finish_ref=5, final_finding_refs=[])
    _write(tmp_path, rows, metadata)
    with pytest.raises(ProductionArtifactError, match="unvalidated"):
        ingest_run(tmp_path, RUN_ID)


def test_symlinked_artifact_is_rejected(tmp_path):
    rows, metadata = _fixture()
    _write(tmp_path, rows, metadata)
    ledger = tmp_path / f"trajectory_{RUN_ID}.jsonl"
    saved = tmp_path / "saved"
    ledger.rename(saved)
    ledger.symlink_to(saved)
    with pytest.raises(ProductionArtifactError, match="symlink"):
        ingest_run(tmp_path, RUN_ID)


def test_failed_final_findings_require_their_retained_compressions(tmp_path):
    rows, metadata = _fixture("failed")
    metadata.update(final_finding_refs=[8], final_compression_refs=[],
                    compressed_findings_count=0, total_raw_char_count=0,
                    total_compressed_char_count=0, compression_ratio=None)
    _write(tmp_path, rows, metadata)
    with pytest.raises(ProductionArtifactError, match="state|compression"):
        ingest_run(tmp_path, RUN_ID)


def test_completed_run_requires_validation_even_without_tools(tmp_path):
    rows, metadata = _fixture("zero")
    rows = [rows[0], rows[-1]]
    rows[-1]["seq"] = 2
    metadata.update(event_count=2, finish_ref=2, final_compression_refs=[],
                    compressed_findings_count=0, total_raw_char_count=0,
                    total_compressed_char_count=0, compression_ratio=None)
    _write(tmp_path, rows, metadata)
    with pytest.raises(ProductionArtifactError, match="validation"):
        ingest_run(tmp_path, RUN_ID)


@pytest.mark.parametrize("raw", [
    '{"results":[],"errors":[{"message":"Fallback scanner failed: offline"}],'
    '"fallback_used":true,"original_error":"Semgrep crashed"}',
    '{"results":[],"results":[]}',
    '{"results":[],"unused":NaN}',
    '{"results":[],"unused":1e999}',
])
def test_unavailable_or_ambiguous_scanner_output_is_error_evidence(tmp_path, raw):
    # These are all accepted by the real producer's json.loads-based compressor.
    rows, metadata = _fixture("zero")
    rows[2]["payload"]["content"] = raw
    rows[3]["payload"]["finding"]["raw_char_count"] = len(raw)
    metadata["total_raw_char_count"] = len(raw)
    metadata["compression_ratio"] = len(raw) / metadata["total_compressed_char_count"]
    _write(tmp_path, rows, metadata)
    result = ingest_run(tmp_path, RUN_ID)
    assert result["status"] == "ERROR"
    assert result["diagnostics"][0]["code"] == "tool_output_unavailable"


def test_generic_tool_error_is_not_a_clean_zero_candidate_observation(tmp_path):
    rows, metadata = _fixture("zero")
    raw = "Tool Execution Error (Code 2): cannot read target"
    rows[1]["payload"]["tool_calls"][0]["name"] = "read_file"
    rows[2]["payload"].update(tool_name="read_file", content=raw)
    base = {"tool": "read_file", "snippet": raw, "truncated": False}
    size = len(json.dumps(base, ensure_ascii=False, sort_keys=True))
    rows[3]["payload"]["finding"] = {**base, "raw_char_count": len(raw),
                                       "compressed_char_count": size}
    metadata.update(total_raw_char_count=len(raw), total_compressed_char_count=size,
                    compression_ratio=len(raw) / size)
    _write(tmp_path, rows, metadata)
    assert ingest_run(tmp_path, RUN_ID)["status"] == "ERROR"


@pytest.mark.parametrize("separator", [b"\r", b"\r\n"])
def test_jsonl_requires_lf_delimited_events_but_accepts_crlf(tmp_path, separator):
    rows, metadata = _fixture()
    _write(tmp_path, rows, metadata)
    ledger = tmp_path / f"trajectory_{RUN_ID}.jsonl"
    data = separator.join(ledger.read_bytes().split(b"\n")[:-1]) + b"\n"
    ledger.write_bytes(data)
    metadata["ledger_sha256"] = hashlib.sha256(data).hexdigest()
    (tmp_path / f"metadata_{RUN_ID}.json").write_text(json.dumps(metadata))
    if separator == b"\r":
        with pytest.raises(ProductionArtifactError) as error:
            ingest_run(tmp_path, RUN_ID)
        assert error.value.code == "corrupt"
    else:
        assert ingest_run(tmp_path, RUN_ID)["status"] == "PASS"

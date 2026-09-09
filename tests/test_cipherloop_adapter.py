from copy import deepcopy

import pytest

from traceforge.adapters.cipherloop import (
    load_case,
    match_messages,
    validate_normalized,
)
from traceforge.evaluation.baseline_contract import (
    FIXTURES,
    ArtifactError,
    canonical_artifact,
    digest,
    parse,
    read,
    write,
)
from traceforge.evaluation.cipherloop_baseline import evaluate_case

CASES = read(FIXTURES / "manifest.json")["cases"]


def ledger(bundle):
    return [
        parse(line)
        for line in (bundle / "toy/trajectory_toy.jsonl").read_text().splitlines()
    ]


def rewrite(bundle, name, value, case_id="toy"):
    """Recompute checksums to exercise semantic checks independently of hashes."""
    import json

    folder = bundle / case_id
    if name == "ledger":
        (folder / f"trajectory_{case_id}.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in value)
        )
    else:
        write(
            folder
            / (f"metadata_{case_id}.json" if name == "metadata" else "capture.json"),
            value,
        )
    index = read(bundle / "index.json")
    index["cases"][case_id][f"{name}_sha256"] = digest(canonical_artifact(name, value))
    write(bundle / "index.json", index)


def test_multicall_matching_preserves_ids_and_rows(bundle):
    rows = ledger(bundle)
    second = deepcopy(rows[0]["payload"]["tool_calls"][0])
    second["id"] = "second"
    rows[0]["payload"]["tool_calls"].append(second)
    result = deepcopy(rows[1])
    result["payload"]["tool_call_id"] = "second"
    rows.insert(1, result)  # Results may arrive in different call order.
    steps, events = match_messages(rows, "toy")
    assert [s["tool_call_id"] for s in steps] == [
        "toy-scan",
        "second",
        "second",
        "toy-scan",
    ]
    assert [s["step_id"] for s in steps] == [1, 2, 3, 4]
    assert steps[1]["cipherloop_reference"]["row"] == 1
    assert events[0]["reference"]["row"] == 4


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("duplicate_call", "duplicate"),
        ("duplicate_result", "duplicate"),
        ("orphan", "orphan"),
        ("missing_result", "tool result"),
        ("wrong_name", "name mismatch"),
        ("wrong_run", "run_id"),
        ("unknown", "unknown event"),
        ("second_validation", "one validation"),
        ("invalid_timestamp", "invalid timestamp"),
    ],
)
def test_message_integrity(bundle, mutation, message):
    rows = ledger(bundle)
    if mutation == "duplicate_call":
        rows[0]["payload"]["tool_calls"] *= 2
    elif mutation == "duplicate_result":
        rows.insert(2, deepcopy(rows[1]))
    elif mutation == "orphan":
        rows[1]["payload"]["tool_call_id"] = "absent"
    elif mutation == "missing_result":
        rows.pop(1)
    elif mutation == "wrong_name":
        rows[1]["payload"]["tool_name"] = "read_file"
    elif mutation == "wrong_run":
        rows[1]["run_id"] = "safe"
    elif mutation == "unknown":
        rows[1]["step_type"] = "unknown"
    elif mutation == "second_validation":
        rows.append(deepcopy(rows[-1]))
    else:
        rows[0]["timestamp"] = True
    rewrite(bundle, "ledger", rows)
    with pytest.raises(ArtifactError, match=message):
        load_case(bundle / "toy", CASES[0])


@pytest.mark.parametrize(
    "filename",
    [
        "index.json",
        "toy/source.py",
        "toy/capture.json",
        "toy/metadata_toy.json",
        "toy/trajectory_toy.jsonl",
    ],
)
def test_missing_artifact_is_error(bundle, filename):
    (bundle / filename).unlink()
    result, normalized = evaluate_case(bundle / "toy", CASES[0])
    assert result["status"] == "error"
    assert normalized is None


@pytest.mark.parametrize(
    "content",
    [
        "{bad json\n",
        "{}\n",
        "null\n",
        "[]\n",
        '{"run_id":"toy","run_id":"safe"}\n',
        '{"timestamp":NaN}\n',
    ],
)
def test_malformed_ledger_is_error(bundle, content):
    (bundle / "toy/trajectory_toy.jsonl").write_text(content)
    assert evaluate_case(bundle / "toy", CASES[0])[0]["status"] == "error"


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("slice", "slice mismatch"),
        ("read", "validation read"),
        ("duplicate_finding", "duplicate"),
        ("missing_path", "taint_path"),
        ("path", "path not backed"),
        ("compression", "compressor"),
        ("status", "incomplete"),
        ("shearing", "shearing"),
    ],
)
def test_semantic_evidence_checks(bundle, mutation, message):
    capture = read(bundle / "toy/capture.json")
    if mutation == "slice":
        capture["source_slice"]["text"] = "fabricated"
    elif mutation == "read":
        capture["validation_reads"] = []
    elif mutation == "duplicate_finding":
        capture["verified_findings"] *= 2
    elif mutation == "missing_path":
        del capture["verified_findings"][0]["taint_path"]
    elif mutation == "path":
        capture["verified_findings"][0]["taint_path"][1] = "app.py:8:absent"
    elif mutation == "compression":
        capture["compressed_findings"][0]["raw_char_count"] += 1
    elif mutation == "status":
        capture["execution_status"] = "error"
    else:
        capture["remaining_messages"] = 1
    rewrite(bundle, "capture", capture)
    with pytest.raises(ArtifactError, match=message):
        load_case(bundle / "toy", CASES[0])


@pytest.mark.parametrize(
    "filename",
    ["source.py", "capture.json", "metadata_toy.json", "trajectory_toy.jsonl"],
)
def test_tampered_artifact_checksum(bundle, filename):
    path = bundle / "toy" / filename
    if filename == "metadata_toy.json":
        value = read(path)
        value["total_raw_char_count"] += 1
        write(path, value)
    else:
        path.write_text(
            path.read_text().replace("app.py", "bad.py")
            if filename != "source.py"
            else "# tampered\n"
        )
    assert evaluate_case(bundle / "toy", CASES[0])[0]["status"] == "error"


def test_validation_and_metadata_arithmetic(bundle):
    rows = ledger(bundle)
    rows[2]["payload"]["rejected_count"] = 1
    rewrite(bundle, "ledger", rows)
    with pytest.raises(ArtifactError, match="validation count"):
        load_case(bundle / "toy", CASES[0])
    rows[2]["payload"]["rejected_count"] = 0
    rewrite(bundle, "ledger", rows)
    metadata = read(bundle / "toy/metadata_toy.json")
    metadata["total_retries"] = 1
    rewrite(bundle, "metadata", metadata)
    with pytest.raises(ArtifactError, match="metadata/count"):
        load_case(bundle / "toy", CASES[0])


def test_incompatible_provenance(bundle):
    index = read(bundle / "index.json")
    index["provenance"]["cipherloop_commit"] = "wrong"
    write(bundle / "index.json", index)
    with pytest.raises(ArtifactError, match="provenance"):
        load_case(bundle / "toy", CASES[0])


def test_schema_and_step_ids(bundle):
    _, normalized = evaluate_case(bundle / "toy", CASES[0])
    normalized["outcome"]["success"] = "yes"
    with pytest.raises(ArtifactError, match="schema"):
        validate_normalized(normalized)
    normalized["outcome"]["success"] = True
    normalized["steps"][1]["step_id"] = 1
    with pytest.raises(ArtifactError, match="step IDs"):
        validate_normalized(normalized)

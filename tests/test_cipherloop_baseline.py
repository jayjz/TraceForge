import json
import os
import subprocess
import sys

import pytest
from test_cipherloop_adapter import rewrite

from traceforge.evaluation.baseline_contract import (
    FIXTURES,
    ROOT,
    ArtifactError,
    canonical_artifact,
    read,
)
from traceforge.evaluation.cipherloop_baseline import evaluate, evaluate_case

CASES = read(FIXTURES / "manifest.json")["cases"]


def test_real_pipeline_outcomes(captures):
    for case in CASES:
        result, normalized = evaluate_case(captures[0] / case["id"], case)
        assert result["status"] == "pass"
        assert all(check["passed"] for check in result["checks"])
        assert normalized["outcome"] == {"success": True}
        capture = normalized["metadata"]["cipherloop"]["capture"]
        assert capture["remaining_messages"] == 0
        assert len(capture["validation_reads"]) == 1
        assert (
            result["observed"]["verified_count"] == case["expected"]["verified_count"]
        )
        assert result["observed"]["candidate_to_verified_ratio"] == (
            1.0 if case["id"] == "toy" else None
        )
        assert "final_answer" not in normalized["outcome"]
        assert "rubric_scores" in result["unavailable"]


def test_full_canonical_reproduction(captures):
    assert evaluate(captures[0]) == evaluate(captures[1])
    assert evaluate(captures[0]) == read(FIXTURES / "artifacts/evaluation.json")

    def canonical(directory):
        result = {}
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            if path.name == "evaluation.json":
                continue
            name = path.relative_to(directory).as_posix()
            if path.suffix == ".jsonl":
                value = [json.loads(line) for line in path.read_text().splitlines()]
                result[name] = canonical_artifact("ledger", value)
            elif path.suffix == ".json":
                kind = (
                    "metadata"
                    if path.name.startswith("metadata_")
                    else "normalized"
                    if path.name == "normalized.json"
                    else "other"
                )
                result[name] = canonical_artifact(kind, read(path))
            else:
                result[name] = path.read_bytes()
        return result

    assert canonical(captures[0]) == canonical(captures[1])
    assert canonical(captures[0]) == canonical(FIXTURES / "artifacts")


def test_valid_but_wrong_path_is_oracle_failure(bundle):
    capture = read(bundle / "toy/capture.json")
    finding = capture["verified_findings"][0]
    finding["taint_path"].pop(1)
    finding["evidence_snippet"] = "AST-verified taint path: " + " -> ".join(
        finding["taint_path"]
    )
    rewrite(bundle, "capture", capture)
    result, normalized = evaluate_case(bundle / "toy", CASES[0])
    assert result["status"] == "fail"
    assert normalized["outcome"]["success"] is False
    assert [check["id"] for check in result["checks"] if not check["passed"]] == [
        "taint_path"
    ]


def test_safe_read_failure_is_execution_error(bundle):
    capture = read(bundle / "safe/capture.json")
    capture["validation_reads"][0]["status"] = "error"
    rewrite(bundle, "capture", capture, "safe")
    result, normalized = evaluate_case(bundle / "safe", CASES[1])
    assert result["status"] == "error"
    assert normalized is None


def test_harness_refuses_append(captures, harness):
    with pytest.raises(FileExistsError):
        harness.generate(ROOT.parent / "CipherLoop", captures[0])


def test_harness_detects_validator_skipping_read(tmp_path, harness, monkeypatch):
    from cipherloop.executor import validator

    monkeypatch.setattr(validator, "verify_finding_evidence", lambda *_: None)
    output = tmp_path / "broken"
    with pytest.raises(ArtifactError, match="validation read failed or missing"):
        harness.generate(ROOT.parent / "CipherLoop", output)
    assert not (output / "index.json").exists()


def test_capture_without_tactical_or_network_execution(tmp_path, harness, monkeypatch):
    from cipherloop.tools import filesystem

    def forbidden(*args, **kwargs):
        pytest.fail("host tactical/network execution attempted")

    monkeypatch.setattr(filesystem, "_get_docker_client", forbidden)
    monkeypatch.setattr("socket.socket.connect", forbidden)
    harness.generate(ROOT.parent / "CipherLoop", tmp_path / "guarded")
    assert "cipherloop.orchestrator.nodes" not in sys.modules


def test_cli_exit_codes_and_adapter_import_boundary(bundle):
    code = "import sys; from traceforge.evaluation.cipherloop_baseline import main; result = main(); assert not any(n == 'cipherloop' or n.startswith('cipherloop.') for n in sys.modules); sys.exit(result)"
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

    def run():
        return subprocess.run(
            [sys.executable, "-c", code, str(bundle)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    assert run().returncode == 0
    capture = read(bundle / "toy/capture.json")
    finding = capture["verified_findings"][0]
    finding["taint_path"].pop(1)
    finding["evidence_snippet"] = "AST-verified taint path: " + " -> ".join(
        finding["taint_path"]
    )
    rewrite(bundle, "capture", capture)
    assert run().returncode == 1
    (bundle / "safe/capture.json").unlink()
    result = run()
    assert result.returncode == 2
    assert json.loads(result.stdout)[1]["status"] == "error"
    assert not (bundle / "safe/normalized.json").exists()

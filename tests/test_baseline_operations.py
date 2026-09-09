"""Controlled operational failures; never change checkout permissions."""

import json
import sys
from pathlib import Path

import pytest

from traceforge.adapters import cipherloop as adapter
from traceforge.evaluation import baseline_contract as contract
from traceforge.evaluation import cipherloop_baseline as evaluator


def seed_results(bundle):
    assert all(r["status"] == "pass" for r in evaluator.evaluate(bundle))
    (bundle / "toy/owner-notes.txt").write_text("keep")


def assert_invalidated(bundle):
    assert not (bundle / "toy/normalized.json").exists()
    assert not (bundle / "safe/normalized.json").exists()
    assert (bundle / "toy/owner-notes.txt").read_text() == "keep"


@pytest.mark.parametrize("failure", ["missing", "malformed", "unreadable"])
def test_manifest_failure_invalidates_all_results(
    bundle, tmp_path, monkeypatch, capsys, failure
):
    seed_results(bundle)
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    if failure == "malformed":
        (fixtures / "manifest.json").write_text("{invalid")
    if failure == "unreadable":
        original = Path.read_bytes

        def denied(path):
            if path == fixtures / "manifest.json":
                raise PermissionError("controlled manifest read denial")
            return original(path)

        monkeypatch.setattr(Path, "read_bytes", denied)
    monkeypatch.setattr(contract, "FIXTURES", fixtures)
    monkeypatch.setattr(sys, "argv", ["evaluate", str(bundle)])
    assert evaluator.main() == 2
    results = json.loads(capsys.readouterr().out)
    assert all(
        r["status"] == "error" and "manifest.json" in r["error"] for r in results
    )
    assert_invalidated(bundle)


@pytest.mark.parametrize(
    "filename, method",
    [
        ("source.py", "read_bytes"),
        ("capture.json", "read_bytes"),
        ("trajectory_toy.jsonl", "read_text"),
    ],
)
def test_unreadable_artifacts(bundle, monkeypatch, filename, method):
    seed_results(bundle)
    original = getattr(Path, method)

    def denied(path, *args, **kwargs):
        if path == bundle / "toy" / filename:
            raise PermissionError(f"controlled unreadable {filename}")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, method, denied)
    results = evaluator.evaluate(bundle)
    assert results[0]["status"] == "error"
    assert filename in results[0]["error"]
    assert results[1]["status"] == "pass"
    assert not (bundle / "toy/normalized.json").exists()


@pytest.mark.parametrize("failure", ["missing", "malformed", "invalid"])
def test_schema_failures_are_structured(bundle, tmp_path, monkeypatch, failure):
    seed_results(bundle)
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    if failure != "missing":
        (schemas / "trajectory.schema.json").write_text(
            "{" if failure == "malformed" else '{"type":17}'
        )
    monkeypatch.setattr(adapter, "ROOT", tmp_path)
    results = evaluator.evaluate(bundle)
    assert all(r["status"] == "error" and "schema" in r["error"] for r in results)
    assert_invalidated(bundle)


def test_atomic_output_write_failure_leaves_no_stale_or_partial_result(
    bundle, monkeypatch, capsys
):
    seed_results(bundle)
    original = contract.os.replace

    def denied(source, target):
        if target == bundle / "toy/normalized.json":
            raise PermissionError("controlled output write denial")
        return original(source, target)

    monkeypatch.setattr(contract.os, "replace", denied)
    monkeypatch.setattr(sys, "argv", ["evaluate", str(bundle)])
    assert evaluator.main() == 2
    results = json.loads(capsys.readouterr().out)
    assert "write" in results[0]["error"]
    assert results[1]["status"] == "pass"
    assert not (bundle / "toy/normalized.json").exists()
    assert not list((bundle / "toy").glob(".normalized.json.*"))
    assert (bundle / "toy/owner-notes.txt").read_text() == "keep"


def test_output_cleanup_denial_is_explicit_and_does_not_evaluate_case(
    bundle, monkeypatch
):
    seed_results(bundle)
    original = Path.unlink

    def denied(path, *args, **kwargs):
        if path == bundle / "toy/normalized.json":
            raise PermissionError("controlled cleanup denial")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", denied)
    results = evaluator.evaluate(bundle)
    assert results[0]["status"] == "error"
    assert "existing result is stale" in results[0]["error"]
    assert "checks" not in results[0]
    assert results[1]["status"] == "pass"


def test_case_symlink_does_not_delete_outside_files(bundle, tmp_path):
    original = bundle / "toy"
    outside = tmp_path / "outside"
    original.rename(outside)
    (outside / "normalized.json").write_text("owner data")
    original.symlink_to(outside, target_is_directory=True)
    results = evaluator.evaluate(bundle)
    assert results[0]["status"] == "error"
    assert "symlink" in results[0]["error"]
    assert (outside / "normalized.json").read_text() == "owner data"


def test_result_symlink_is_unlinked_without_following_target(bundle, tmp_path):
    outside = tmp_path / "owner.json"
    outside.write_text("keep")
    (bundle / "toy/normalized.json").unlink(missing_ok=True)
    (bundle / "toy/normalized.json").symlink_to(outside)
    assert evaluator.evaluate(bundle)[0]["status"] == "pass"
    assert outside.read_text() == "keep"
    assert not (bundle / "toy/normalized.json").is_symlink()


def test_programming_defect_propagates_after_invalidation(bundle, monkeypatch):
    seed_results(bundle)

    def broken(*args):
        raise RuntimeError("programming defect")

    monkeypatch.setattr(evaluator, "evaluate_case", broken)
    with pytest.raises(RuntimeError, match="programming defect"):
        evaluator.evaluate(bundle)
    assert_invalidated(bundle)


@pytest.mark.parametrize("failure", ["manifest", "write"])
def test_capture_cli_operational_errors_are_structured(
    tmp_path, harness, monkeypatch, capsys, failure
):
    output = tmp_path / "capture"
    monkeypatch.setattr(sys, "argv", ["generate", "--output", str(output)])
    if failure == "manifest":
        monkeypatch.setattr(contract, "FIXTURES", tmp_path)
    else:

        def denied(*args):
            raise PermissionError("controlled capture output denial")

        monkeypatch.setattr(harness, "write", denied)
    assert harness.main() == 2
    error = json.loads(capsys.readouterr().err)
    assert error["stage"] == "capture" and error["status"] == "error"
    assert not (output / "index.json").exists()


def test_new_environment_preserves_its_own_identity(tmp_path, harness, monkeypatch):
    observed = {
        "python": "3.12.99",
        "platform": "independent test environment",
        "packages": {"test-package": "1.0"},
    }
    monkeypatch.setattr(contract, "environment", lambda: observed)
    output = tmp_path / "new-environment"
    harness.generate(contract.ROOT.parent / "CipherLoop", output)
    assert contract.read(output / "index.json")["provenance"]["environment"] == observed
    assert all(r["status"] == "pass" for r in evaluator.evaluate(output))


def test_reference_provenance_remains_strict(bundle):
    reference = contract.read(contract.FIXTURES / "artifacts/index.json")
    reference["provenance"]["environment"]["python"] = "changed"
    with pytest.raises(contract.ArtifactError, match="reference provenance"):
        contract.validate_provenance(reference)

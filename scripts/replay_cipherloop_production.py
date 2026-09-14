"""Replay one pinned CipherLoop production-v2 capture across the file boundary.

This deliberately installs and runs CipherLoop in a private checkout and virtual
environment. TraceForge only receives copied artifact bytes and evaluates them with
its own production reader.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from traceforge.adapters.cipherloop_production import (
    ProductionArtifactError,
    ingest_run,
)

CIPHERLOOP_REVISION = "c98c5d80e507ad3010d8004c86d7d6b8a4ac0c87"
CIPHERLOOP_REPOSITORY = "https://github.com/jayjz/CipherLoop.git"


def _run(command, *, cwd=None, env=None):
    subprocess.run(command, cwd=cwd, env=env, check=True)


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bundle(source, destination):
    metadata_path, = source.glob("metadata_*.json")
    metadata = json.loads(metadata_path.read_bytes())
    run_id = metadata["run_id"]
    trajectory_path = source / f"trajectory_{run_id}.jsonl"
    destination.mkdir()
    copied = {}
    for original in (trajectory_path, metadata_path):
        target = destination / original.name
        shutil.copy2(original, target)
        original_digest, copied_digest = _sha256(original), _sha256(target)
        if original_digest != copied_digest:
            raise RuntimeError(f"artifact copy changed {original.name}")
        copied[original.name] = copied_digest
    return run_id, metadata["contract_version"], copied


def _evaluate(folder, run_id, expected_status, expected_execution_status):
    result = ingest_run(folder, run_id)
    if result["status"] != expected_status:
        raise AssertionError(f"expected {expected_status}, got {result['status']}")
    if result["execution_status"] != expected_execution_status:
        raise AssertionError("unexpected execution status")
    return {"status": result["status"], "execution_status": result["execution_status"]}


def replay(root, repository, revision):
    producer = root / "CipherLoop"
    producer_venv = root / "cipherloop-venv"
    capture = root / "producer-output"
    handoff = root / "handoff"
    _run(["git", "clone", "--no-checkout", repository, str(producer)])
    _run(["git", "checkout", "--detach", revision], cwd=producer)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=producer, text=True).strip()
    if head != revision:
        raise RuntimeError(f"producer checkout is {head}, not requested revision {revision}")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=producer, text=True):
        raise RuntimeError("isolated producer checkout is dirty")

    _run([sys.executable, "-m", "venv", str(producer_venv)])
    producer_python = producer_venv / "bin" / "python"
    _run([str(producer_python), "-m", "pip", "install", "-e", ".[dev]"], cwd=producer)
    _run([str(producer_python), "-m", "pip", "check"])
    producer_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "LANGSMITH_TRACING": "false"}
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY", "LANGSMITH_API_KEY"):
        producer_env.pop(name, None)
    _run([str(producer_python), "scripts/capture_production_smoke.py", "--output", str(capture)],
         cwd=producer, env=producer_env)

    handoff.mkdir()
    verified_id, contract, verified_digests = _bundle(capture / "verified", handoff / "verified")
    failed_id, failed_contract, failed_digests = _bundle(capture / "failed", handoff / "failed")
    if contract != "cipherloop-production-v2" or failed_contract != contract:
        raise AssertionError("unexpected producer contract version")
    verified = _evaluate(handoff / "verified", verified_id, "PASS", "completed")
    failed = _evaluate(handoff / "failed", failed_id, "ERROR", "failed")

    corrupted = handoff / "corrupted"
    shutil.copytree(handoff / "verified", corrupted)
    ledger, = corrupted.glob("trajectory_*.jsonl")
    ledger.write_bytes(ledger.read_bytes().replace(b"Offline contract smoke", b"Xffline contract smoke", 1))
    try:
        ingest_run(corrupted, verified_id)
    except ProductionArtifactError as exc:
        if exc.code != "corrupt":
            raise AssertionError(f"expected corrupt rejection, got {exc.code}") from exc
    else:
        raise AssertionError("modified artifact was accepted")
    return {
        "producer_revision": head,
        "contract_version": contract,
        "positive": {"run_id": verified_id, "artifacts": verified_digests, **verified},
        "availability_control": {"run_id": failed_id, "artifacts": failed_digests, **failed},
        "integrity_control": {"status": "rejected", "reason": "ledger_sha256 mismatch"},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cipherloop-revision", default=CIPHERLOOP_REVISION)
    parser.add_argument("--cipherloop-repository", default=CIPHERLOOP_REPOSITORY)
    parser.add_argument("--workspace", type=Path, help="Fresh directory to retain replay artifacts.")
    args = parser.parse_args()
    if args.cipherloop_revision != CIPHERLOOP_REVISION:
        parser.error(f"only the pinned compatibility revision is supported: {CIPHERLOOP_REVISION}")
    if args.workspace:
        args.workspace.mkdir(parents=True, exist_ok=False)
        summary = replay(args.workspace, args.cipherloop_repository, args.cipherloop_revision)
    else:
        with tempfile.TemporaryDirectory(prefix="traceforge-cipherloop-production-") as temporary:
            summary = replay(Path(temporary), args.cipherloop_repository, args.cipherloop_revision)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

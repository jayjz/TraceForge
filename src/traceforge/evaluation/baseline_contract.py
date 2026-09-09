"""Small, versioned file contract shared by capture and artifact ingestion."""

import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests/fixtures/cipherloop"
VERSION = "cipherloop-offline-v1"
IMPLEMENTATION = (
    "scripts/generate_cipherloop_baseline.py",
    "src/traceforge/adapters/cipherloop.py",
    "src/traceforge/evaluation/baseline_contract.py",
    "src/traceforge/evaluation/cipherloop_baseline.py",
    "schemas/trajectory.schema.json",
    "rubrics/base_v0.yaml",
    "tests/fixtures/cipherloop/manifest.json",
    "tests/fixtures/cipherloop/environment.json",
)


class ArtifactError(ValueError):
    """Missing, incompatible, or internally inconsistent evidence."""


def require(condition, message):
    if not condition:
        raise ArtifactError(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse(text):
    def invalid(value):
        raise ArtifactError(f"non-finite JSON number: {value}")

    return json.loads(text, object_pairs_hook=_pairs, parse_constant=invalid)


def read(path):
    return parse(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    return sha(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    )


def canonical_artifact(name, value):
    """Only recorder timestamps and its absolute ledger path are volatile."""
    if name == "ledger":
        return [{k: v for k, v in row.items() if k != "timestamp"} for row in value]
    if name == "metadata":
        return {k: v for k, v in value.items() if k != "trajectory_file"}
    if name == "normalized":
        return {
            **value,
            "steps": [
                {k: v for k, v in step.items() if k != "timestamp"}
                for step in value["steps"]
            ],
        }
    return value


def environment():
    # Include the entire resolved environment, including pre-existing packages.
    packages = {}
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"].lower().replace("_", "-")
        packages.setdefault(name, dist.version)
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": dict(sorted(packages.items())),
    }


def provenance():
    manifest = read(FIXTURES / "manifest.json")
    return {
        "normalization_version": VERSION,
        "cipherloop_commit": manifest["cipherloop_commit"],
        "traceforge_base_commit": manifest["traceforge_base_commit"],
        "implementation_sha256": {
            name: sha((ROOT / name).read_bytes()) for name in IMPLEMENTATION
        },
        "environment": read(FIXTURES / "environment.json"),
        "scanner": "synthetic Semgrep-shaped response; no scanner executed",
    }

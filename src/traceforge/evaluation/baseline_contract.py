"""Small, versioned file contract shared by capture and artifact ingestion."""

import hashlib
import importlib.metadata
import json
import os
import platform
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests/fixtures/cipherloop"
VERSION = "cipherloop-offline-v2"
CASE_IDS = ("toy", "safe")
MANIFEST_SHA256 = "5d43b292921bff44399147f0f011bcd5eb762edc8aa5d95b10e1f0f28084597e"
REFERENCE_INDEX_SHA256 = (
    "15ca2a846573905931236aad1de94a9aa06dfbf5fda9c141848ac1f043533631"
)
IMPLEMENTATION = (
    "scripts/generate_cipherloop_baseline.py",
    "src/traceforge/adapters/cipherloop.py",
    "src/traceforge/evaluation/baseline_contract.py",
    "src/traceforge/evaluation/cipherloop_baseline.py",
    "schemas/trajectory.schema.json",
    "rubrics/base_v0.yaml",
    "tests/fixtures/cipherloop/manifest.json",
    "pyproject.toml",
    "requirements/baseline.txt",
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
    try:
        return parse(read_bytes(path).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, ArtifactError) as exc:
        raise ArtifactError(f"read {path}: {exc}") from exc


def read_bytes(path):
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ArtifactError(f"read {path}: {exc}") from exc


def load_manifest():
    path = FIXTURES / "manifest.json"
    data = read_bytes(path)
    # This release supports exactly the original two cases. Check before using
    # IDs as paths or interpreting oracle fields; a changed manifest is incompatible.
    require(sha(data) == MANIFEST_SHA256, f"{path}: incompatible manifest")
    return parse(data.decode("utf-8"))


def write(path, value):
    """Atomic replacement; failed serialization is a programming error."""
    text = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        os.replace(temporary, path)
    except OSError as exc:
        raise ArtifactError(f"write {path}: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                raise ArtifactError(
                    f"temporary output cleanup {temporary}: {exc}"
                ) from exc


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
    # Observation, not a compatibility gate. No environment packages are imported.
    packages = {}
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"].lower().replace("_", "-")
        packages.setdefault(name, dist.version)
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": dict(sorted(packages.items())),
    }


def provenance(captured_environment=None):
    manifest = load_manifest()
    return {
        "normalization_version": VERSION,
        "cipherloop_commit": manifest["cipherloop_commit"],
        "traceforge_base_commit": manifest["traceforge_base_commit"],
        "implementation_sha256": {
            name: sha(read_bytes(ROOT / name)) for name in IMPLEMENTATION
        },
        "environment": environment()
        if captured_environment is None
        else captured_environment,
        "scanner": "synthetic Semgrep-shaped response; no scanner executed",
    }


def validate_provenance(index):
    captured = index["provenance"]
    if captured["normalization_version"] == "cipherloop-offline-v1":
        # Preserve the original reference without regenerating its evidence or
        # accepting arbitrary legacy producers whose implementation is unavailable.
        data = read_bytes(FIXTURES / "artifacts/index.json")
        require(sha(data) == REFERENCE_INDEX_SHA256, "reference index hash mismatch")
        require(
            index == parse(data.decode("utf-8")), "incompatible reference provenance"
        )
        return
    observed = captured["environment"]
    require(
        isinstance(observed, dict)
        and set(observed) == {"python", "platform", "packages"},
        "invalid environment provenance",
    )
    require(
        all(
            isinstance(observed[key], str) and observed[key]
            for key in ("python", "platform")
        ),
        "missing environment identity",
    )
    require(
        isinstance(observed["packages"], dict)
        and observed["packages"]
        and all(
            isinstance(k, str) and isinstance(v, str) and v
            for k, v in observed["packages"].items()
        ),
        "invalid package provenance",
    )
    require(captured == provenance(observed), "incompatible provenance")

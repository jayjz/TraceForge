# CipherLoop production ingestion

`traceforge.adapters.cipherloop_production.ingest_run(folder, run_id)` consumes
CipherLoop's **`cipherloop-production-v2`** contract from two copied files:
`trajectory_<UUID>.jsonl` and `metadata_<UUID>.json`. It imports only Python's standard
library, never CipherLoop. Original target/ledger paths in evidence are descriptive.
It neither opens the original target nor executes tools nor writes evaluator output.

This path is separate from `adapters/cipherloop.py`, the pinned two-case baseline,
its fixtures/provenance, and `trajectory.schema.json`. None of those contracts changed.
Checkpoint production v1 is unsupported because it cannot identify retained final
finding occurrences. Missing/unknown versions never fall back to the synthetic adapter.

The canonical producer contract is CipherLoop `docs/production-evidence-contract.md`.
The reader independently checks strict JSON, versions, hashes, ordered identities,
call/result pairs, compression selection/counts, validation cycles and attempts,
source reads/slices, finding AST locations, final references, and metadata arithmetic.
Repeated upstream finding IDs are legal across distinct decisions; duplicate or
orphan event relationships are rejected. Failed captures may preserve observations
that never entered final state; final references must remain a complete state prefix.

Results use **`traceforge-cipherloop-production-v1`**, not the legacy normalized
trajectory schema. `status: PASS` concerns `capture_integrity_and_source_locations`.
`status: ERROR` identifies observed failed/interrupted execution or unavailable
validation (read failure, malformed candidate, syntax failure). Structured diagnostics
retain the relevant event reference/error. Missing commitments raise
`ProductionArtifactError(code="incomplete")`; incompatible formats use `unsupported`;
malformed bytes use `corrupt`; invalid relationships use `inconsistent`.
No rejected/corrupt capture produces a normal successful result.

Task success, detection accuracy, exploitability, report, and model provenance remain
explicitly unavailable. AST location checks verify that referenced symbols occur at
the stated locations in analyzed text. They do not prove dataflow or exploitability,
and accepting a recorded no-trace rejection does not establish target safety.
No production `FAIL` oracle is invented: the frozen benchmark still owns its fixture
PASS/FAIL/ERROR semantics. Output pins the adapter and both artifact hashes for local
reproduction; hashes do not authenticate a producer capable of rewriting everything.

## Offline production boundary reproduction

Use an environment with CipherLoop's declared dependencies installed for capture,
and a separate TraceForge environment for evaluation. From the CipherLoop checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python scripts/capture_production_smoke.py \
  --output /tmp/cipherloop-production-smoke
```

The output directory must be new. Six scenarios use the real CLI lifecycle,
LangGraph message/list reducers, compressor, validator, and recorder. Tool results
and source reads are explicitly scripted; no scanner, target app, Docker daemon,
cloud service, or local model runs. This is a production-contract integration smoke,
not a live agent capture or new detection benchmark.

Copy the resulting directory to another location. Each scenario contains just the
two contract artifacts. From TraceForge, the following runs without site packages
or a CipherLoop import path:

```sh
cp -R /tmp/cipherloop-production-smoke /tmp/cipherloop-copied-bundles
PYTHONPATH=src python -S - <<'PY'
import json
from pathlib import Path
from traceforge.adapters.cipherloop_production import ingest_run

for folder in sorted(Path('/tmp/cipherloop-copied-bundles').iterdir()):
    metadata = json.loads(next(folder.glob('metadata_*.json')).read_bytes())
    result = ingest_run(folder, metadata['run_id'])
    expected = 'ERROR' if folder.name in {'read_failure', 'failed', 'interrupted'} else 'PASS'
    assert result['status'] == expected
    assert len(result['final_findings']) == int(folder.name == 'verified')
    print(folder.name, result['status'], result['execution_status'])
PY
```

Expected integrity/source-location results: verified, zero, rejected → PASS;
read_failure, failed, interrupted → ERROR. Source-read failure can have observed
execution `completed`; the explicit validation error prevents confusing it with
a clean zero-candidate observation.

```sh
python -m pytest -q tests/test_cipherloop_production.py
python -m ruff check src/traceforge/adapters/cipherloop_production.py tests/test_cipherloop_production.py
```

The new tests are self-contained and do not call the baseline capture harness.
To run all baseline regressions too, preserve its required clean CipherLoop checkout
at `f03a1e186e491cf24aa0f0e0671cac766c1fa8ab` as described in
`docs/cipherloop-baseline.md`; use an isolated layout instead of changing an active
producer branch. No baseline repinning, regeneration of goldens, or loosened checks
is part of production ingestion.

P0.1 producer closure and this initial P0.2 ingestion path are verified offline.
The next bounded milestone is a real sandbox/model execution exported as this
two-file bundle and independently ingested. No live audit, hosted CI, detection
accuracy, or power-loss/attestation guarantee follows from the offline smoke.

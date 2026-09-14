# TraceForge

TraceForge is an **experimental Python evaluation package** for studying evidence
and trajectories from tool-using agents.

The original baseline is a **two-case offline CipherLoop evidence baseline**:
scripted scanner responses pass through CipherLoop's real compressor, AST
validator, and recorder. TraceForge ingests the resulting files, checks schema
and evidence integrity, and evaluates an independent fixture oracle.

- `toy`: one expected source → variable → command-execution finding.
- `safe`: zero verified findings after a successful source read and rejection of
  the supplied candidate.

These fixtures test evidence handling and integration. They do not establish
scanner coverage, general detection accuracy, or security effectiveness.

Separate [production-v2 artifact ingestion](docs/cipherloop-production.md) is also
implemented and verified offline. It independently checks capture integrity and
source locations without importing CipherLoop or assigning task-success verdicts.
A real preflight failure was captured and ingested as ERROR; a successful live
sandbox/model audit has not yet been demonstrated.

General trajectory scoring, calibrated LLM judges, and live detection evaluation
are **not implemented**. The research notes and weighted
rubric describe future work. Recovery, safety, cost, token, and rubric scores
remain unavailable in this baseline.

## Clean setup

Use Python 3.12 and Git. Run from the TraceForge checkout. The baseline currently
uses an editable installation because its manifest, schema, and source provenance
remain checkout resources; a standalone wheel is not a supported baseline runner.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements/bootstrap.txt
# TraceForge itself:
.venv/bin/python -m pip install --no-build-isolation -c requirements/baseline.txt -e .
# Optional synthetic-capture dependencies and focused test tools:
.venv/bin/python -m pip install --no-build-isolation -c requirements/baseline.txt -e '.[dev,baseline]'
.venv/bin/python -m pip check
```

The constraints pin the complete tested dependency resolution for CPython 3.12
on Linux x86_64. Setup may access the package index; execution is offline. Neither
a global Python installation nor CipherLoop's existing environment is modified.

The harness additionally reads the pinned CipherLoop **source checkout** at
`../CipherLoop`. It imports only the components needed for synthetic capture;
do not install CipherLoop's full live-agent dependency stack. If the sibling
already exists, verify its HEAD and clean working tree; do not reset it. If it
is absent, obtain a new read-only source checkout:

```sh
git clone --no-checkout https://github.com/jayjz/CipherLoop.git ../CipherLoop
git -C ../CipherLoop checkout --detach f03a1e186e491cf24aa0f0e0671cac766c1fa8ab
```

The harness verifies that exact commit, a clean working tree, and both fixture
hashes. It refuses incompatible source rather than substituting a newer revision.

## Offline reproduction

After setup, run this generate → evaluate block:

```sh
export PYTHONDONTWRITEBYTECODE=1 LANGSMITH_TRACING=false
unset OPENAI_API_KEY ANTHROPIC_API_KEY LANGSMITH_API_KEY
baseline_dir="$(mktemp -d /tmp/traceforge-repro.XXXXXX)/capture"
.venv/bin/python scripts/generate_cipherloop_baseline.py --output "$baseline_dir" &&
  .venv/bin/python -m traceforge.evaluation.cipherloop_baseline "$baseline_dir"
```

No cloud credentials, models, Docker daemon, Ollama, GPU, or live scanner are
needed. The evaluator prints JSON diagnostics and writes normalized results.
Exit codes are `0` for fixture success, `1` for a valid oracle mismatch, and `2`
for artifact or operational errors. Output directories must be fresh for capture.

See [the baseline documentation](docs/cipherloop-baseline.md) for exact verified
commands, provenance, filesystem behavior, test results, and limitations.
[The GitHub Actions workflow](.github/workflows/cipherloop-baseline.yml) runs the
bounded checks using the same setup; adding the workflow does not establish that
a hosted run has passed.

## Implemented files and research

- `scripts/generate_cipherloop_baseline.py`: synthetic capture harness.
- `src/traceforge/adapters/cipherloop.py`: artifact-only ingestion and integrity checks.
- `src/traceforge/adapters/cipherloop_production.py`: independent production evidence ingestion.
- `src/traceforge/evaluation/`: fixture evaluation and versioned file contract.
- `tests/fixtures/cipherloop/`: two-case manifest and preserved reference evidence.
- `schemas/trajectory.schema.json`: normalized trajectory schema.
- [Research foundation](docs/research-foundation.md) and
  [rubric design](docs/rubric-design.md): research and planned evaluation methods.

Licensed under [MIT](LICENSE).

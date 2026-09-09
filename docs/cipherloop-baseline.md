# CipherLoop offline evidence baseline

Verified 2026-09-09 on `feat/cipherloop-offline-baseline`, derived from the assessment
branch. This is a two-case evidence integration baseline. Synthetic scanner
responses pass through the real CipherLoop compressor, AST validator, message
reducer, and trajectory recorder. No fixture application or tactical tool runs.
CipherLoop is unchanged; detection logic is unchanged.

From the TraceForge checkout, this single generate → evaluate shell block
reproduces the baseline using the prepared local environment:

```sh
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:/tmp/traceforge-baseline-deps
unset OPENAI_API_KEY ANTHROPIC_API_KEY LANGSMITH_API_KEY
baseline_dir="$(mktemp -d /tmp/traceforge-repro.XXXXXX)/capture"
../CipherLoop/venv/bin/python scripts/generate_cipherloop_baseline.py --output "$baseline_dir" &&
  ../CipherLoop/venv/bin/python -m traceforge.evaluation.cipherloop_baseline "$baseline_dir"
```

Generation requires a fresh output directory because the recorder appends.
Evaluation writes each case's `normalized.json` and prints deterministic JSON
diagnostics. Exit codes: **0** all fixture checks pass, **1** complete evidence
disagrees with the oracle, **2** missing, malformed, incompatible, or insufficient
evidence. An error has no `outcome.success`; reevaluation removes a stale
`normalized.json` for an invalid case. Safe rejection is a successful outcome.

The command performs no network operations and needs no cloud credentials,
Docker, Ollama, model downloads, or running services. A focused test also blocks
socket connections and Docker client acquisition during capture.

Environment preparation is separate from offline execution. The existing
`../CipherLoop/venv` was reused. Only its missing, already-declared JSON Schema
dependency and five transitive packages were installed into
`/tmp/traceforge-baseline-deps`; CipherLoop's environment was not modified:

```sh
../CipherLoop/venv/bin/python -m pip install --target /tmp/traceforge-baseline-deps \
  --cache-dir /tmp/traceforge-pip-cache 'jsonschema==4.26.0'
```

That setup required approved package-index access after sandbox DNS failure.
For a fresh overlay, use the exact six pins in
[`schema-requirements.txt`](../tests/fixtures/cipherloop/schema-requirements.txt).
An air-gapped fresh machine needs those wheels supplied beforehand; no wheel
bundle is included. The complete observed package resolution is recorded in
[`environment.json`](../tests/fixtures/cipherloop/environment.json). Generation
rejects a different Python version, platform string, or package resolution;
portability to other environments has not been tested.

Source and environment provenance:

| Input | Exact value |
|---|---|
| CipherLoop source commit | `f03a1e186e491cf24aa0f0e0671cac766c1fa8ab` |
| TraceForge assessment/base commit | `3a79434bc63d0db932abfa0fe855eed3c7262b4c` |
| TraceForge unchanged main | `382d800653ba35bf20dc091e9900c7d5a8e5fd8e` |
| Normalization contract | `cipherloop-offline-v1` |
| Python | `3.12.3`, GCC `13.3.0` |
| Platform | `Linux-7.0.0-30-generic-x86_64-with-glibc2.39` |
| Relevant installed versions | langchain-core `1.6.0`, langgraph `1.2.11`, docker `7.2.0`, jsonschema `4.26.0`, pytest `9.1.1`, ruff `0.16.4` |

The implementation is identified by file SHA-256 hashes in the capture's
`index.json`, alongside both source commits, schema/rubric/manifest hashes, and
the environment. The TraceForge commit above is the starting commit, not a
claim that the implementation existed in that commit. Incompatible capture
provenance is rejected. CipherLoop must have the pinned HEAD and a clean tree.

Independent fixture oracle and exact observed results:

| Case | Fixture SHA-256 | Candidates / verified / rejected | Result |
|---|---|---|---|
| `toy` | `3478e0a33851efca082c84461b7afb017fe5c542d53e632705713ef8ee6b3474` | `1 / 1 / 0` | pass |
| `safe` | `10419797e9e51b69fa84f111a4131a7acbbe1bf11f18ba71307cf5c2ccdeacfd` | `1 / 0 / 1` | pass |

Toy's exact path is `app.py:8:request.args.get` → `app.py:8:ip` →
`app.py:10:subprocess.run`. Its source slice is lines 8–10. Safe receives a
candidate at line 11; its slice is lines 11–16, including the constant arguments.
Both receive a successful full-source read at the validator boundary. Their
candidate/verified ratios are `1.0` and `null`, respectively. Both normalized
outcomes have `success: true`.

Each case records three ledger rows (call, raw result, validation), two normalized
steps, one compressed tool-output dictionary, two removed messages, and zero
remaining messages. Raw/compressed character counts are **120 / 153** for both;
the ratio is **0.7843137254901961**. These tiny inputs expand under compression.
The recorder's `total_retries: 0` is a harness-supplied planner counter, not a
measurement of recovery. `final_plan` is null because no planner runs.

The reference capture is in
[`tests/fixtures/cipherloop/artifacts`](../tests/fixtures/cipherloop/artifacts):

- `index.json`: provenance and canonical artifact checksums.
- Each case's `trajectory_*.jsonl` and `metadata_*.json`: untouched recorder output.
- `capture.json`: exact compressor dictionaries and finding objects, successful
  validator read records, source slice, source/input hashes, shearing results,
  execution status, and artifact/row references.
- `source.py`: byte-identical fixture snapshot, never executed.
- `normalized.json`: existing Draft 2020-12 schema plus namespaced evidence.
- `evaluation.json`: exact fixture diagnostics from the generate → evaluate run.

The adapter imports no CipherLoop modules. It checks schema validity, ordered
unique step IDs, call/result IDs and names, run IDs, one validation cycle,
artifact hashes, source-backed slices/locations/path references, compression
counts, validation arithmetic, and successful reads. Duplicate calls, results,
findings, JSON keys, or validation cycles fail rather than being deduplicated.
Multi-call mapping is tested, but the baseline contract accepts one scanner
call per fixture. The manifest defines expected outcomes independently of
capture; complete, internally consistent oracle mismatches are `fail`.

Canonical comparison excludes **only** ledger row `timestamp`, recorder metadata
`trajectory_file`, and normalized step `timestamp` (the converted ledger time).
The original values remain in raw artifacts. Checksums for ledger/metadata use
those canonical forms; JSON whitespace/key order is insignificant. Source
snapshots are compared byte-for-byte. No finding, diagnostic, ID, count, source
slice, or provenance field is excluded. Two fresh captures and the saved
reference are compared by the focused reproduction test.

Verification commands run from TraceForge, unless stated otherwise:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=src:/tmp/traceforge-baseline-deps ../CipherLoop/venv/bin/python -m pytest \
  -q -p no:cacheprovider tests/test_cipherloop_adapter.py tests/test_cipherloop_baseline.py

../CipherLoop/venv/bin/ruff check scripts/generate_cipherloop_baseline.py \
  src/traceforge/adapters src/traceforge/evaluation \
  tests/conftest.py tests/test_cipherloop_adapter.py tests/test_cipherloop_baseline.py

# From ../CipherLoop:
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 venv/bin/python -m pytest \
  -q -p no:cacheprovider tests/test_trajectory.py tests/test_compressor.py tests/test_validator.py
```

Focused baseline tests: **44 passed in 1.36s**. Focused upstream checks: **7 passed in
0.67s**. Ruff: **All checks passed!** Schema and semantic validation run in the
baseline tests and reference evaluation; no broader test suite was run.
The documented reproduction block completed with exit **0**, with cloud keys
unset, writing `/tmp/traceforge-repro.ijqM3E/capture`. The saved reference was
generated and evaluated with the same environment and unset keys, also exit **0**.

Limits: scripted candidates do not measure scanner coverage, live agent
behavior, or general detection accuracy. The AST validator has its existing
intra-procedural limitations; its confidence is preserved as upstream evidence,
not calibrated. Hashes detect corruption against the local trusted manifest and
capture index; they are not signatures or proof against a forged producer that
rewrites the index and all evidence. The adapter checks evidence consistency
and the fixture oracle, not independent reexecution of AST analysis. Production
ledgers without sidecars are intentionally insufficient. Original agent tasks,
reports, model provenance, recovery, safety, tokens, cost, and rubric scores
remain unavailable. No detection improvement was implemented.

Highest-value next milestone: add a narrow production capture contract for
source-read success, finding objects/source slices, task identity, and explicit
completion/failure, so real ledgers can satisfy the same evidence boundary.

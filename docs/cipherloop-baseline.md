# CipherLoop offline evidence baseline

Release hardening verified 2026-09-09 on `feat/cipherloop-offline-baseline`, starting
at `e3663d394722b2d0774b60106402de6c6f5db325`. This remains an experimental two-case
evidence integration baseline. Synthetic scanner responses pass through the real
CipherLoop compressor, AST validator, message reducer, and recorder. No fixture
application or tactical tool runs. CipherLoop and detection logic are unchanged.

## Clean setup and offline reproduction

From a fresh TraceForge checkout, use Python 3.12 and a dedicated virtual environment:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements/bootstrap.txt
# TraceForge core installation:
.venv/bin/python -m pip install --no-build-isolation -c requirements/baseline.txt -e .
# Only the capture harness dependencies and focused test tools:
.venv/bin/python -m pip install --no-build-isolation -c requirements/baseline.txt -e '.[dev,baseline]'
.venv/bin/python -m pip check
```

[`requirements/baseline.txt`](../requirements/baseline.txt) pins the complete tested
third-party resolution (52 distributions, including build/test tools) for CPython
3.12 on Linux x86_64. The package adds the three direct capture requirements through
its `baseline` extra: langchain-core `1.6.0`, langgraph `1.2.11`, and docker `7.2.0`.
The full CipherLoop application and its model-provider stack are not installed.
TraceForge is an editable install because the baseline still uses checkout-local
manifest/schema/provenance resources; a standalone wheel is not a supported runner.

The harness needs a separate, clean CipherLoop source checkout at `../CipherLoop`,
at **`f03a1e186e491cf24aa0f0e0671cac766c1fa8ab`**. It verifies HEAD and fixture hashes
before capture. If the sibling is absent, use the source-only checkout commands in
[README.md](../README.md#clean-setup). Never reset an existing sibling to satisfy the
pin. Neither CipherLoop's tracked files nor its existing venv need modification.

Setup uses the package index. Offline execution needs no cloud credentials, Docker
daemon, Ollama, GPU, model download, or live scanner. For a fresh air-gapped machine,
supply the pinned wheels and source checkout beforehand; wheels are not vendored.
The old `/tmp` overlay and `../CipherLoop/venv` setup are historical, not prerequisites.

After setup, this single generate → evaluate block reproduces the baseline:

```sh
export PYTHONDONTWRITEBYTECODE=1 LANGSMITH_TRACING=false
unset OPENAI_API_KEY ANTHROPIC_API_KEY LANGSMITH_API_KEY
baseline_dir="$(mktemp -d /tmp/traceforge-repro.XXXXXX)/capture"
.venv/bin/python scripts/generate_cipherloop_baseline.py --output "$baseline_dir" &&
  .venv/bin/python -m traceforge.evaluation.cipherloop_baseline "$baseline_dir"
```

Generation requires a fresh directory because the upstream recorder appends. It
writes `index.json` last; missing index means incomplete capture. Evaluation prints
JSON diagnostics and atomically writes each case's `normalized.json`.

- **0:** every fixture evaluation passes, including a successful safe rejection.
- **1:** complete, valid evidence disagrees with the independent fixture oracle.
- **2:** missing, malformed, incompatible, or insufficient evidence, or an
  operational failure that prevents evaluation/output publication.

Capture errors are JSON on stderr with `stage: capture` and `status: error`.
Evaluation errors appear in its JSON result list, without `outcome.success`.
Expected read, JSON, schema, output-write, and cleanup failures are covered. The
outer boundary does not catch arbitrary exceptions; unexpected programming
failures remain diagnosable rather than becoming ordinary negative results.

Before reading the manifest, evaluation invalidates the two reserved output files
`toy/normalized.json` and `safe/normalized.json`. No recursive cleanup occurs and
other filenames are preserved. Symlinked capture/case directories are refused;
result-file symlinks are unlinked without following their targets. These directories
must not be concurrently modified while evaluation runs. If permissions prevent
invalidation, evaluation reports that any existing result is stale and skips the
case. It cannot physically remove a file when the filesystem denies removal;
consumers must honor the current diagnostics and exit code. Partial writes use a
temporary file and atomic replacement, so a failed write cannot publish success.

## Provenance and preserved reference

New captures use **`cipherloop-offline-v2`**. Each records actual Python version,
platform, resolved packages, CipherLoop commit, original TraceForge assessment/base
commit `3a79434bc63d0db932abfa0fe855eed3c7262b4c`, implementation hashes, and hashes of
the manifest, schema, rubric, packaging, and dependency constraints. The assessment
commit is historical context; implementation file hashes identify the current code.

Environment data is an observation, not a universal compatibility gate. A new
kernel, patch release, or extra installed package does not require editing a golden
environment file. New captures retain their own identity and must reproduce within
that environment. The adapter checks current contract/source hashes and the captured
environment's structure, without requiring the evaluator to have the capture's
installed packages. This is not certification of arbitrary environments.

The original `cipherloop-offline-v1` reference artifacts and fixture manifest remain
byte-for-byte unchanged. Its exact index is anchored by SHA-256
`15ca2a846573905931236aad1de94a9aa06dfbf5fda9c141848ac1f043533631`; only that legacy
index/provenance is accepted. Evidence checksums still apply. The original Python
3.12.3/Linux package inventory remains in
[`environment.json`](../tests/fixtures/cipherloop/environment.json), and the old
[`schema-requirements.txt`](../tests/fixtures/cipherloop/schema-requirements.txt)
records its overlay. These are historical evidence, not current installation locks.

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
`trajectory_file`, and normalized step `timestamp` (converted ledger time). Original
values remain in raw artifacts. Ledger/metadata checksums use those canonical forms;
JSON whitespace/key order is insignificant. Source snapshots compare byte-for-byte.
Two fresh captures compare fully, including provenance. Across the new environment
and the historical reference, tests compare evidence hashes and fixture diagnostics;
they do not pretend the different provenance is canonically identical. The old
reference also passes ingestion and matches its preserved normalized output.

## Exact release verification

Two new isolated environments were created with system Python 3.12.3, without using
CipherLoop's venv or the old overlay. `/tmp/traceforge-release-venv` resolved the pins;
**`/tmp/traceforge-clean-venv`** then installed directly from them. The second setup
used these exact commands from TraceForge (package access required sandbox approval):

```sh
python3 -m venv /tmp/traceforge-clean-venv
/tmp/traceforge-clean-venv/bin/python -m pip install --cache-dir /tmp/traceforge-release-pip-cache -r requirements/bootstrap.txt
/tmp/traceforge-clean-venv/bin/python -m pip install --no-build-isolation --cache-dir /tmp/traceforge-release-pip-cache -c requirements/baseline.txt -e .
/tmp/traceforge-clean-venv/bin/python -m pip install --no-build-isolation --cache-dir /tmp/traceforge-release-pip-cache -c requirements/baseline.txt -e '.[dev,baseline]'
/tmp/traceforge-clean-venv/bin/python -m pip check

PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 LANGSMITH_TRACING=false \
/tmp/traceforge-clean-venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_cipherloop_adapter.py tests/test_cipherloop_baseline.py tests/test_baseline_operations.py

/tmp/traceforge-clean-venv/bin/python -m ruff check scripts/generate_cipherloop_baseline.py \
  src/traceforge tests/conftest.py tests/test_cipherloop_adapter.py \
  tests/test_cipherloop_baseline.py tests/test_baseline_operations.py

export PYTHONDONTWRITEBYTECODE=1 LANGSMITH_TRACING=false
unset PYTHONPATH OPENAI_API_KEY ANTHROPIC_API_KEY LANGSMITH_API_KEY
/tmp/traceforge-clean-venv/bin/python scripts/generate_cipherloop_baseline.py --output /tmp/traceforge-clean-capture &&
  /tmp/traceforge-clean-venv/bin/python -m traceforge.evaluation.cipherloop_baseline /tmp/traceforge-clean-capture
```

Results: **62 tests passed in 1.66s**; Ruff reported **All checks passed!**; pip check
reported **No broken requirements found.** Generate → evaluate exited **0**, with
toy `1 verified / 0 rejected` and safe `0 verified / 1 rejected`. Schema and semantic
checks passed. Regression tests exercise exit codes 0/1/2, missing/unreadable
manifests, unreadable evidence, invalid schemas, output-write and stale-cleanup
failures, symlink handling, and propagation of an unexpected programming failure.
An initial regression test had a setup collision with an existing temporary output;
it was corrected before this passing run. No real checkout permissions were changed.

The clean environment contains TraceForge plus 52 third-party distributions, all
matching the pins. Its platform is `Linux-7.0.0-30-generic-x86_64-with-glibc2.39`.
Relevant versions: Python `3.12.3`, pydantic `2.13.5`, jsonschema `4.26.0`, pytest
`9.1.1`, ruff `0.16.4`, and the three capture imports pinned above. Full environment
provenance is in `/tmp/traceforge-clean-capture/index.json`; the resolution needed
to reinstall it is checked in. No broader/upstream suite was rerun for this release.
The earlier baseline's 44-test and 7-upstream-test results remain historical results.

## CI and limits

[The workflow](../.github/workflows/cipherloop-baseline.yml) has one Python 3.12 job
on Ubuntu 24.04, read-only repository permissions, no services or user-provided
secrets, and no push/deployment steps. Both checkout steps disable credential
persistence. Action commits were verified against the official
[checkout v4.2.2 release](https://github.com/actions/checkout/releases/tag/v4.2.2) and
[setup-python v5.6.0 release](https://github.com/actions/setup-python/releases/tag/v5.6.0).
CipherLoop is checked out at its exact SHA and verified before installation/capture.
An unauthenticated GitHub API read returned HTTP 200 and that exact source SHA.

**Hosted GitHub Actions was not run.** Its installation, focused tests, lint, and
baseline commands were verified locally in the fresh environment (using the existing
pinned sibling source). Workflow YAML parsed, and its events, permission setting,
and single-job structure were checked. The hosted checkout and runner behavior
remain unverified. The workflow's final tracked-diff guard is for the committed CI
checkout; locally the intended uncommitted release changes were inspected instead.

Limits: this is an editable-checkout baseline, not a portable wheel distribution
of fixture resources. Pins constrain versions, not wheel bytes; no offline wheel
bundle is supplied. Other OS/Python combinations have not been validated. Scripted
candidates do not measure scanner coverage, live agent behavior, or general detection
accuracy. The AST validator retains its intra-procedural limitations; upstream
confidence is preserved, not calibrated. Hashes detect corruption against trusted
local contracts and reference evidence; they do not authenticate a producer capable
of rewriting its index and evidence. Production ledgers without sidecars remain
insufficient. Original agent tasks, reports, model provenance, recovery, safety,
tokens, cost, and rubric scores remain unavailable. Detection logic is unchanged.

Recommended next milestone: run this bounded workflow on GitHub and verify the
hosted source checkout and dependency installation before beginning production
capture integration.

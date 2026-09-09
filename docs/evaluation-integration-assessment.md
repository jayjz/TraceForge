# CipherLoop → TraceForge evaluation assessment

Assessed 2026-09-09 using local files only. **Smallest sound milestone: a two-case, offline evidence-pipeline baseline in TraceForge**, using scripted scanner responses with CipherLoop's real compressor, AST validator, and recorder. This measures evidence handling and trace integration; it does not establish live agent detection accuracy, scanner coverage, or judge validity.

## Repository state and scope

| Repository | Inspected branch | Exact HEAD |
|---|---|---|
| CipherLoop | `main` | `f03a1e186e491cf24aa0f0e0671cac766c1fa8ab` |
| TraceForge | `main` | `382d800653ba35bf20dc091e9900c7d5a8e5fd8e` |

Both working trees were clean. The workspace parent is not a Git repository. No ancestor `AGENTS.md` was present; CipherLoop's root `AGENTS.md` was the only repository instruction file found. It requires sandboxed tactical execution, POSIX container paths, compressed memory, and source/sink/code-slice evidence. Its referenced `specs/` directory is absent. `docs/MEMORY_PROTOCOL.md` also prescribes an append-only agent log; this reconnaissance's explicit restriction to an assessment takes precedence over log writes and the general full-pytest workflow.

The assessment is written on the new TraceForge branch `docs/evaluation-integration-assessment`; neither `main` ref nor CipherLoop's files are changed. No integration is implemented.

## Verified execution and evidence flow

Source references below are relative to CipherLoop unless prefixed with `TraceForge/`.

1. `src/cipherloop/main.py::audit` checks Docker/Ollama, resolves the target mount, creates a UUID-based recorder, streams graph state, then finalizes metadata. Finalization is not protected by `finally`, so interrupted runs may lack metadata. Provisioning requests no network and a read-only mount; reuse checks target identity, not every isolation setting.
2. `orchestrator/graph.py::build_graph` under `src/cipherloop/` routes planner → local model ↔ sandbox tools → compressor → validator → planner or synthesizer. Exit depends on an empty/“complete” plan or `retries >= 25`; `retries` counts planner invocations, not failed tool retries. The local tool loop has no explicit local retry cap. `orchestrator/nodes.py` creates cloud clients at import time. The planner does not incorporate the incoming initial plan into its prompt.
3. `tools/filesystem.py` constrains container paths with `posixpath` and executes through Docker. Semgrep uses registry configs `p/secrets` and `p/rce`; `sandbox/Dockerfile` neither pins scanner versions nor vendors these rules. A fresh air-gapped scan is therefore not an established reproducible baseline.
4. `executor/local_node.py` falls back from Semgrep failure to sandboxed regex scanning. Contrary to the README's AST-to-Semgrep diagram, `executor/validator.py::find_taint_trace` returns `None` on syntax errors. Fallback results omit severity, while `executor/compressor.py::process_semgrep_output` retains only `WARNING`/`ERROR` candidates: fallback matches currently do not reach validation through this path.
5. The compressor keeps at most five ranked Semgrep summaries; generic output is truncated. It records tool-call AI messages and raw tool results, then returns `RemoveMessage` entries for messages with IDs. Raw `ToolMessage` content exists in active graph state until this boundary; recording occurs here, not immediately at execution. Non-tool-call messages are not archived.
6. The validator parses summary file/line locations, reads source through the sandbox tool, and performs limited Python intra-procedural AST taint tracking. Findings include source, sink, path, status, and confidence. However, `evidence_snippet` is a textual AST path, **not a source-code slice**; labels are not general exploitability proof. Rejections have no per-candidate reasons. Each validation revisits accumulated compressed findings, and both finding lists use append reducers, so later cycles can repeat candidates/findings.

## Trace formats and integration gap

TraceForge implements only `src/traceforge/__init__.py` (version), a JSON Schema, and a YAML rubric. There are no models, adapter, scorer, diagnostics module, CLI, tests, or sample trajectories. Those items in its README tree and roadmap are planned. The five-dimension rubric and Lucky Pass rule are descriptive, not executable or calibrated.

| CipherLoop artifact | TraceForge contract / required decision |
|---|---|
| JSONL rows: numeric epoch `timestamp`, `run_id`, `step_type`, `payload` | Schema requires one object with `trajectory_id`, `task`, `steps`, `outcome`. Assign ordered step IDs; convert timestamps to UTC date-time strings when retained. |
| `message` payload: class, role, content; AI `tool_calls`; tool `tool_name` and `tool_call_id` | Expand multi-call AI messages into individual `tool_call` steps; map results to `tool_result`; preserve call IDs and original row references. Validate pairing rather than inventing calls. |
| `validation` payload: candidate/verified/rejected counts, candidates ÷ verified or null | No validation step type exists. Preserve these events as namespaced metadata with row references; do not disguise them as model thoughts or tool results. Counts are per validation invocation, not unique findings. |
| Metadata: run ID, target, final plan, planner count, compressed-batch count, raw/compressed character totals and ratio | Preserve metric names and definitions. Character compression is not token/cost reduction; batch count is not vulnerability count; planner count must not become tool-retry count. |
| No original task, finding objects, source slices, final report, explicit outcome, or model/version provenance in these artifacts | Supply a fixture/task manifest and a harness evidence sidecar. Existing production ledgers alone cannot support evidence-level outcome scoring. |

`TrajectoryRecorder.finalize` computes compression from retained finding dictionaries; the ledger does not contain those compressed dictionaries or per-tool compression counts. Raw messages and aggregate metadata are insufficient to verify every compression decision without replay or additional evidence. Timestamps describe recording time. Validator file reads bypass the message ledger, and fallback actions appear inside a tool response rather than as separate calls. Thus this is an incomplete execution history, with no basis for comprehensive safety, recovery, or efficiency scores.

The TraceForge schema permits additional properties, so a namespaced evidence/provenance extension does not require changing its enum. It requires boolean `outcome.success`; use an independently specified fixture oracle, not “audit completed” or “verified count > 0.” Incomplete evidence must produce an explicit evaluation error, not a fabricated success/failure label. Schema validity alone does not enforce call pairing, unique IDs, or evidence sufficiency.

## Existing deterministic material

| Material | Baseline use and limit |
|---|---|
| `fixtures/toy/app.py` | Positive case: `request.args.get` at line 8 → `subprocess.run(..., shell=True)` at line 10. Read as source; do not run Flask or the command. |
| `fixtures/safe/app.py` | Negative case: constant `subprocess.run` arguments at line 11. A supplied candidate should be rejected; zero verified findings is the expected successful evaluation. |
| `tests/test_e2e_vulnerable.py`, `tests/test_e2e_safe.py` | Offline graph patterns with mocked planner/local model/compressor and mocked validator reads; vulnerable synthesis is also mocked. Neither attaches a recorder or tests real compression/tool execution. |
| `tests/test_compressor.py`, `test_validator.py`, `test_trajectory.py` | Reusable Semgrep-shaped data, AST evidence expectations, message-shearing checks, and compression totals. These are component examples, not a stored run corpus. |
| `tests/test_local_node.py` | Mocked scanner failure/recovery cases for a later extension, not proof of real scanner recovery. |

No tracked JSONL trajectories, run metadata corpus, or dependency lockfiles were found. Python dependency ranges alone do not fix a reproducible environment.

## Recommended next milestone

Keep the integration boundary in **TraceForge: artifact ingestion plus a small offline fixture harness**. The adapter should consume files without importing CipherLoop. Only the harness imports its compressor, validator, recorder, and required message/state utilities from the pinned local checkout; avoid the CLI and cloud-initializing graph modules.

For each fixture, construct ordered, fixed-ID AI/tool messages containing one scripted Semgrep candidate at the actual sink line. Run the real compressor, apply its message removals, run the real validator with fixture text supplied at the read boundary, and finalize the real recorder. Preserve returned findings and compression dictionaries in a harness sidecar, together with actual fixture source slices and hashes. This follows existing test mocking conventions without executing tactical tools on the host. Label scanner responses as synthetic and final report as unavailable.

Normalize ledger + metadata + sidecar + manifest into the existing TraceForge schema. Emit deterministic pass/fail checks with artifact/row references, separate from observed metrics; defer weighted rubric scoring, LLM judges, fault injection, live scans, and general production-run support. Require one validation cycle initially to avoid treating cumulative event counts as unique detections.

Likely new TraceForge files:

- `src/traceforge/adapters/cipherloop.py`: artifact parsing, mapping, integrity checks.
- `src/traceforge/evaluation/cipherloop_baseline.py`: fixture oracle and structured diagnostics, with a small module entry point.
- `scripts/generate_cipherloop_baseline.py`: explicitly synthetic capture using pinned CipherLoop components.
- `tests/fixtures/cipherloop/`: two manifest cases, source snapshots, generated artifacts, expected diagnostics, and generation provenance.
- `tests/test_cipherloop_adapter.py`, `tests/test_cipherloop_baseline.py`: focused contracts and regressions.
- `docs/cipherloop-baseline.md`, and narrowly scoped `pyproject.toml`/lock configuration: exact reproduction command and tested dependency versions. JSON Schema validation is already a declared dependency.

No CipherLoop change is necessary for this milestone. A later production capture change would likely touch `core/trajectory.py`, `executor/validator.py`, and `main.py` under `src/cipherloop/` to persist task, completion, and evidence records; that is separate work from detection logic.

### Acceptance criteria and minimal verification plan

1. Two offline cases pass: toy produces exactly one expected source/sink/path finding; safe receives one candidate and produces zero verified findings. Source slices and fixture hashes substantiate locations; claims remain limited to these cases.
2. Outputs validate against Draft 2020-12 plus explicit semantic checks: ordered unique step IDs, matched tool-call IDs, consistent run IDs, complete manifest/sidecar, and one validation cycle. Unknown events remain inspectable or cause a clear error.
3. Compression totals reconcile with captured compressor results. Validation arithmetic reconciles with findings, zero denominators remain null, and planner iterations stay distinct from retries. Unsupported metrics/dimensions are unavailable rather than assigned favorable defaults.
4. Malformed JSONL, missing/mismatched artifacts, orphan results, and tampered evidence fail explicitly; the negative fixture is not confused with a broken run. Use a few focused parametrized adapter/evaluator tests.
5. Generate both cases twice in fresh temporary directories and compare canonical artifacts/diagnostics after removing only declared volatile timestamps/output paths. Pin both source commits, fixture/input hashes, schema/rubric hashes, Python version, dependency resolution, and normalization version. Reject incompatible provenance.
6. Run only those new tests and the focused upstream checks below. Use installed or later explicitly resolved dependencies; no Docker, Ollama, model calls, downloads, or network are needed during baseline execution. Document one repeatable generate → evaluate command.

## Exact checks performed during reconnaissance

- Inspected `pwd`, repository directory entries, `git status --porcelain=v1 --branch`, `git branch --show-current`, `git branch --list`, and `git rev-parse HEAD` for both repositories. Checked ancestor instructions and used targeted `rg --files` (including hidden/unignored instruction searches excluding Git/venvs), `rg -n`, `git ls-files`, and file reads for the sources/tests/docs named above. Checked for `specs`, trace artifacts, lockfiles, an existing assessment, and ignore rules.
- Used existing CipherLoop `venv/bin/python` (Python 3.12.3), with pytest 9.1.1, langgraph 1.2.11, langchain-core 1.6.0, langchain-anthropic 1.6.1, docker 7.2.0, and PyYAML 6.0.3. These are observed local versions, not a complete dependency lock.
- Ran exactly this focused command from CipherLoop; **7 passed in 1.48s**:

  ```sh
  PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 venv/bin/python -m pytest -q -p no:cacheprovider \
    tests/test_trajectory.py::test_finalize_aggregates_tool_compression_metrics \
    tests/test_compressor.py::test_process_semgrep_output_parses_and_ranks \
    tests/test_compressor.py::test_compressor_node_memory_sweeping \
    tests/test_validator.py::test_validator_emits_only_a_complete_ast_verified_finding \
    tests/test_e2e_safe.py::test_safe_fixture_produces_no_verified_findings_and_a_safe_report \
    tests/test_e2e_vulnerable.py::test_vulnerable_fixture_produces_an_ast_verified_report \
    tests/test_local_node.py::test_both_tools_fail_gracefully
  ```

- Parsed TraceForge schema with `json.loads` and rubric with `yaml.safe_load`; confirmed required top-level schema fields, five dimensions, and weights totaling 1.0. `jsonschema` is unavailable in the checked system/CipherLoop interpreters, so no JSON Schema validator was run and nothing was installed.
- Created only the documentation branch and this assessment; checked final diffs/statuses, unchanged HEAD/main refs, and document whitespace. No broad suite, scanner, fixture application, Docker/Ollama command, paid inference, clone/pull/fetch, push, merge, or deployment was executed.

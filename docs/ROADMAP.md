# TraceForge Roadmap

## Current release boundary — 2026-09-12

The frozen two-case CipherLoop baseline remains unchanged. Initial P0.2 production
artifact ingestion is implemented and verified offline; see
[the production contract scope](cipherloop-production.md). A real missing-Docker
preflight failure was ingested as ERROR. Successful live sandbox/model execution
is not yet demonstrated and is the next bounded verification step on Windows.
Repository CI now includes the production regression tests alongside the baseline;
this does not claim a hosted run has passed. Cross-repository feature compatibility
CI needs published compatible revisions before it can pin these local fixes.

The phases below are longer-term research directions, not release acceptance
criteria or authority to add judges, scanner capability, or product UI now.

## Phase 0 — Scaffold (established)
- Research foundation documented
- Trajectory schema (v0)
- Base multi-dimensional rubric (v0)
- Package skeleton + license

## Phase 1 — Core Loop
- Pydantic models matching the trajectory schema
- Deterministic checkers (schema validity, tool presence, retry counts, forbidden actions)
- Basic LLM-as-Judge scorer driven by `rubrics/base_v0.yaml`
- Lucky Pass heuristic flag
- CLI or simple Python API: load trajectory → score → diagnostics JSON

## Phase 2 — Calibration & Real Agents
- Score 30–50 real trajectories from AetherForge / HVAC ops / Unhinged-style agents
- Human calibration + inter-rater notes
- Improve criteria language and few-shot judge prompts
- Export structured diagnostics usable for prompt/tool/control-plane improvements

## Phase 3 — Adaptive + Fault Injection
- Optional AdaRubric-style task-adaptive dimension generation
- Controlled fault injection for recovery measurement
- Regression suite format for continuous evaluation
- Optional ATIF-compatible export/import

## Non-goals (for now)
- Full multi-agent coordination scoring
- Replacing public leaderboards
- Heavyweight hosted evaluation platform

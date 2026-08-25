# TraceForge Roadmap

## Phase 0 — Scaffold (current)
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

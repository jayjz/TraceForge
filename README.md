# TraceForge

**Process-aware evaluation and adaptive rubrics for tool-using LLM agents.**

TraceForge scores the *trajectory*, not just the final answer.  
It targets the gaps that current production evals still miss: recovery quality, tool-selection/argument correctness, process efficiency, coherence, side-effects, and the "Lucky Pass" problem (correct outcome via brittle or chaotic path).

Grounded in recent scholarly work including AgentLens, AdaRubric, TRACE, TRAJECT-Bench, Plan-RewardBench, ACES/ATIF, and Recovery-Bench style protocols.

---

## Why this exists

Most agent evals still reduce a run to pass/fail or final-answer accuracy.  
Research consistently shows this is insufficient:

- **Lucky Pass problem** (AgentLens): ~10%+ of successful trajectories on coding agents reach the right outcome through weak process (brute-force, incomplete verification, excessive exploration).
- **Static rubrics fail** (AdaRubric): Fixed dimensions (Helpfulness, Fluency…) systematically mis-score goal-directed tool agents. Task-adaptive rubrics raise human correlation significantly.
- **Trajectory > outcome** (TRACE, TRAJECT-Bench, Plan-RewardBench): Tool selection order, argument validity, dependency satisfaction, recovery from injected faults, and efficiency must be scored explicitly.
- **Long-horizon degradation**: Preference judges and LLM-as-Judge accuracy drop sharply as trajectory length grows.

TraceForge is a practical, local-first scaffold for building production-grade process evaluation on *your* agents (control planes, ops agents, edge systems).

---

## Core Design Principles (from the literature)

1. **Trajectory is the unit of evaluation** — ordered sequence of thoughts, tool calls + args + returns, errors, retries, state changes, final outcome.
2. **Multi-dimensional, preferably task-adaptive rubrics** — orthogonal axes with explicit verbalized criteria (1–5 or pass/fail + rationale).
3. **Separate process from outcome** — detect Lucky Passes; score recovery independently of final success.
4. **Deterministic gates + LLM judges** — schema validity, forbidden actions, retry limits are code-checked; interpretive dimensions use calibrated LLM-as-Judge.
5. **Human calibration loop** — inter-rater agreement and human–judge agreement are first-class metrics.
6. **Actionable diagnostics** — scores must point to concrete improvements (tool schema, prompt, control-plane guards, recovery policy).

---

## Planned Dimensions (v0 base rubric)

| Dimension | What it measures | Primary sources |
|-----------|------------------|-----------------|
| Goal Achievement | Did the trajectory accomplish the stated + inferred intent? | AgentLens, TRACE, production practice |
| Tool Selection & Arguments | Correct tool(s), valid schema, semantic arg correctness | TRAJECT-Bench, BFCL lineage, Plan-RewardBench |
| Recovery Quality | Detection → diagnosis → correct response to tool/env failures | Plan-RewardBench (Robust Recovery), Recovery-Bench |
| Process Efficiency & Coherence | Minimal waste, no loops, sensible depth, logical ordering | TRACE (Efficiency), AgentLens (waste signals) |
| Side-Effects / Safety / Constraints | No unintended writes, policy violations, unsafe actions | Plan-RewardBench (Safety Refusal), production |
| (Optional) Uncertainty & Escalation | Calibrated communication when stuck or uncertain | Recovery protocols |

These are starting points. AdaRubric-style task-adaptive generation will be layered on top.

---

## Repository Structure (scaffold)

```
TraceForge/
├── README.md
├── docs/
│   ├── research-foundation.md      # Key papers & design decisions
│   ├── rubric-design.md            # How to build & calibrate rubrics
│   └── trajectory-schema.md        # Normalized trajectory format
├── schemas/
│   └── trajectory.schema.json      # Minimal ATIF-inspired schema
├── rubrics/
│   ├── base_v0.yaml                # Initial multi-dimensional rubric
│   └── examples/
├── src/
│   └── traceforge/
│       ├── __init__.py
│       ├── schema.py
│       ├── scorer.py               # Deterministic + LLM-judge scaffolding
│       └── diagnostics.py
├── examples/
│   └── sample_trajectory.json
├── tests/
└── pyproject.toml
```

---

## Research Foundation (selected)

- **AgentLens** — Process-aware SWE trajectory scoring; Lucky Pass detection; PTA references.
- **AdaRubric** — Task-adaptive rubric generation; step-level confidence-weighted scoring; high human correlation.
- **TRACE** — Reference-free multi-dimensional trajectory evaluation (Efficiency, Hallucination, Adaptivity) with evidence bank.
- **TRAJECT-Bench** — Trajectory-aware tool-use metrics (selection, arguments, order/dependency).
- **Plan-RewardBench** — Trajectory-level preference benchmark covering Safety Refusal, Tool-Irrelevance, Complex Planning, Robust Error Recovery.
- **ACES / ATIF** — Agent Trajectory Interchange Format; skill-level continuous evaluation.
- Supporting: Recovery-Bench style protocols, long-horizon dense grading work, AgentAtlas taxonomies.

Full notes live in `docs/research-foundation.md`.

---

## Status

**Scaffold / Phase 0** (August 2026).  
Research mapped. Core schema + base rubric + evaluation loop design in progress.  
Intended first use-cases: local control-plane agents (AetherForge-style), field/ops agents, thin-client edge agents under real constraints.

---

## License

MIT (planned).

---

*Built for people who ship agents under real constraints — not demo-only evaluation.*

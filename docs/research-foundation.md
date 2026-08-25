# Research Foundation

This document captures the scholarly grounding for TraceForge. It is living documentation — update as new work lands and as we validate design choices against real trajectories.

## Core Problems Identified in the Literature

### 1. Outcome-only evaluation is misleading
Binary pass/fail or final-answer accuracy hides process quality. Agents can reach correct states through brittle, wasteful, or unsafe paths ("Lucky Pass").

**Key evidence**: AgentLens (SWE agents) found ~10.7% of passing trajectories were Lucky Passes on their PTA-eligible set, dominated by Brute-Force Convergence and Incomplete Implementation.

### 2. Static rubrics systematically mis-score agents
Applying the same dimensions (Helpfulness, Fluency, Safety…) to every task type produces low human correlation on goal-directed, tool-using work.

**Key evidence**: AdaRubric shows task-adaptive rubrics raise Pearson r to ~0.79 vs ~0.62 for strong static baselines, with high inter-run reliability (Krippendorff α ≈ 0.83).

### 3. Trajectory-level metrics are required for tool agents
Tool selection, argument correctness, order/dependency satisfaction, recovery behavior, and efficiency must be measured explicitly.

**Key evidence**: TRAJECT-Bench, TRACE, Plan-RewardBench all demonstrate that final accuracy alone is insufficient and that long-horizon trajectories degrade judge performance sharply.

### 4. Recovery is a first-class capability
Most evals ignore or under-weight how agents detect, diagnose, and respond to tool failures, empty results, timeouts, or corrupted observations.

**Key evidence**: Plan-RewardBench (Robust Error Recovery family), Recovery-Bench style protocols, production failure analyses.

## Selected Primary Sources (2025–2026)

| Work | Core Contribution | Relevance to TraceForge |
|------|-------------------|-------------------------|
| **AgentLens** | Process-aware scoring for SWE trajectories; Lucky Pass detection; PTA references | Lucky Pass concept, process vs outcome separation, waste signals |
| **AdaRubric** | Task-adaptive rubric generation + step-level confidence-weighted scoring | Adaptive rubric layer, human-correlation target |
| **TRACE** | Reference-free multi-dimensional trajectory eval (Efficiency, Hallucination, Adaptivity) + evidence bank | Reference-free path, multi-dim design |
| **TRAJECT-Bench** | Trajectory-aware tool-use diagnostics (selection, args, order) | Tool-level metrics |
| **Plan-RewardBench** | Trajectory preference bench covering Safety Refusal, Tool-Irrelevance, Complex Planning, Robust Recovery | Rubric families, recovery & safety axes |
| **ACES / ATIF** | Agent Trajectory Interchange Format; skill-level continuous evaluation | Trajectory schema inspiration |
| Supporting | Recovery-Bench, AgentAtlas taxonomies, long-horizon dense grading, CRATE | Failure taxonomies, step-level reasoning |

## Design Decisions Derived from Research

1. **Normalize trajectories first** — Adopt a simple, explicit schema (inspired by ATIF ideas) so deterministic checks and judges operate on the same object.
2. **Start with a strong base multi-dimensional rubric**, then add adaptive generation (AdaRubric-style) once the base is calibrated.
3. **Always score recovery and process efficiency separately from goal achievement** — this is the main differentiator from chatbot-style eval.
4. **Hybrid scoring** — Code for schema, counts, forbidden actions, retry limits; LLM-as-Judge for interpretive axes; human calibration as the source of truth.
5. **Diagnostics over scalar scores** — Every evaluation should produce actionable failure localization where possible.
6. **Local-first / private by default** — Aligns with constrained hardware and private agent deployments (control planes, field ops, edge).

## Open Research Questions We Track

- How well do LLM judges hold up on long-horizon (32k+ token) trajectories without step-level decomposition?
- Optimal trade-off between fixed high-quality base dimensions vs fully adaptive per-task rubrics for production regression suites.
- Best practices for injecting realistic faults (timeouts, stale data, schema errors) to measure recovery without destroying reproducibility.
- Mapping process scores to concrete agent improvements (prompt, tool description, control-plane circuit breakers).

## Citation Stance

TraceForge is an engineering scaffold informed by the above research. It does not claim to re-implement any single paper. When we adopt a specific technique (e.g., Lucky Pass heuristics, adaptive rubric generation), we will cite the source in code and docs.

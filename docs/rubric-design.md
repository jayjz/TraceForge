# Rubric Design & Calibration

Practical guidance derived from AdaRubric, AgentLens, Plan-RewardBench, TRACE, and annotation best practices.

## Principles

1. **Orthogonality** — Dimensions should measure distinct aspects. If two dimensions almost always move together, collapse or redefine them.
2. **Verbalized criteria** — Every score level (1–5) needs concrete, observable language. Avoid vague terms like "good" or "reasonable" without anchors.
3. **Process vs outcome separation** — Never let final success fully determine process scores. Explicitly allow high outcome + low process (Lucky Pass candidates).
4. **Task relevance** — Base dimensions are a starting point. For specialized domains (HVAC ops, control-plane safety, coding), extend or adapt dimensions rather than forcing generic ones.
5. **Deterministic first** — Anything that can be checked by code (schema validity, required tools present, retry count, forbidden actions) should be. LLM judges handle the rest.

## Calibration Loop (minimum viable)

1. Collect 30–50 real trajectories from your target agent(s), including successes, failures, and recovery cases.
2. Score them yourself (or with a second annotator) using the base rubric. Record disagreements.
3. Refine criteria language until inter-rater agreement is acceptable on the hard dimensions (especially recovery and efficiency).
4. Run an LLM judge with the same rubric. Measure agreement with your human scores.
5. Iterate prompt + few-shot examples until human–judge agreement is usable for regression work.
6. Lock the calibrated rubric for a period; treat changes as versioned and re-calibrate after significant edits.

## Adaptive Extension (later)

Once the base rubric is stable, introduce AdaRubric-style generation:
- Given a task description, propose 3–6 task-specific dimensions with criteria.
- Keep a small set of mandatory process dimensions (recovery, tool correctness, efficiency) even when adapting.
- Validate generated rubrics against human judgment before trusting them for preference data or automated scoring.

## Lucky Pass Heuristic (v0)

Flag a trajectory as potential Lucky Pass when:
- `goal_achievement >= 4` **and**
- (`process_efficiency_coherence <= 2` **or** `recovery_quality <= 2`)

This is a diagnostic signal, not a hard label. Investigate the trace.

## Anti-Patterns

- Scoring only the final answer and calling it "agent evaluation."
- Using a single composite number without per-dimension breakdown.
- Letting the LLM judge invent its own dimensions instead of following the rubric.
- Never measuring recovery because "the run succeeded."
- Changing the rubric every week without re-calibration.

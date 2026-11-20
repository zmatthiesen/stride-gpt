---
name: stride-threats
description: Perform evidence-aware STRIDE analysis of an approved codebase or description using specialized subsystem agents and shared reference cards.
argument-hint: "[approved run directory]"
disable-model-invocation: true
---

Read `../stride-model/contract.md` relative to this skill directory. Input:
$ARGUMENTS. Require explicitly approved scope and input mode. If no approved
scope exists, use `/stride-model`'s planning and approval steps, then STOP for
approval rather than starting analysis.

Coordinate `stride-analyst` for each approved subsystem with explicit ownership,
the trusted library root, input mode, exclusions, and nonoverlapping ID ranges.
Use `stride-synthesizer` for cross-system interactions. Do not invoke agents
from inside another agent.

Check every STRIDE category without inventing a required number of findings.
Use actual code evidence or explicit description/missing-control hypotheses.
Load applicable shared reference cards through Read, record which were loaded,
and preserve their supported framework mappings.

Persist `scope`, `findings`, `cross_cutting_threats`, `observations`, assumptions,
exclusions, coverage gaps, and synthesis status in `draft.json`. Keep an entry
for every subsystem, including failures. A standalone STRIDE-only run can use
an empty `requested_outputs` list; do not imply diagrams or follow-ups exist.
Render a draft report or use the optional offline finalizer with approval.

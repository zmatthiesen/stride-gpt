---
name: stride-dread
description: Assess STRIDE threats with explainable 1-to-10 DREAD dimensions, an arithmetic mean, and explicit uncertainty.
argument-hint: "[approved run directory]"
disable-model-invocation: true
---

Read `../stride-model/contract.md` relative to this skill directory. Input:
$ARGUMENTS. Require an approved run with known threat IDs; request it if absent.
Do not introduce a different risk methodology or imply scores are objective.

For each threat assess damage, reproducibility, exploitability, affected users,
and discoverability on an integer scale from 1 to 10. Lower scores mean lower
risk/ease/reach; higher scores mean greater risk/ease/reach. Use 1 for minimal
impact, very difficult reproduction/exploitation, very few users, or very hard
discovery; use 10 for severe impact, trivial reliable reproduction/exploitation,
system-wide affected users, or obvious discovery. Explain intermediate choices.

Write one `dread` object per threat as coordinator. Each of its five dimensions
contains `score` and `rationale`; state environmental assumptions and confidence
in the rationale. Calculate the unweighted arithmetic mean, not a sum, in the
human-readable report; the offline finalizer recomputes it. Do not use a zero
or a made-up measurement to represent unknown deployment facts. Make uncertain
estimates explicit and request human review. In a standalone run request only
`dread`.

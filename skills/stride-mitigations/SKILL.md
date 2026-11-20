---
name: stride-mitigations
description: Produce actionable, threat-linked controls and residual-risk guidance for an approved STRIDE-GPT run without modifying the target.
argument-hint: "[approved run directory]"
disable-model-invocation: true
---

Read `../stride-model/contract.md` relative to this skill directory. Input:
$ARGUMENTS. Require an approved run and its threat list. If absent, request it;
do not invent findings or begin a new analysis.

For every threat, propose preventive and detective controls appropriate to the
observed architecture. State where to implement them, the responsible
component, how to verify them, assumptions, and remaining risk. Prefer existing
mechanisms and least privilege; distinguish a proposed control from one
actually observed. Do not promise that a control removes all risk.

As coordinator, write one `mitigations` entry per known threat ID, combining
its controls in `text`, and include the result in `report.md`. Never modify
target source or cloud resources. Unknown ownership should remain a question.
In a standalone run request only `mitigations`.

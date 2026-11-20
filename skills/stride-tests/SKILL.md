---
name: stride-tests
description: Write threat-linked Gherkin security acceptance scenarios for an approved STRIDE-GPT run; do not execute tests or exploits.
argument-hint: "[approved run directory]"
disable-model-invocation: true
---

Read `../stride-model/contract.md` relative to this skill directory. Input:
$ARGUMENTS. Require an approved run, known threats, and proposed controls.
If controls are missing, request them or apply `/stride-mitigations` within the
existing approval rather than inventing unrelated behavior.

For each threat write a `Scenario:` with `Given`, `When`, and `Then`, using
concrete observable acceptance criteria tied to its mitigation. Include
negative cases, authorization/tenant boundaries, and relevant input limits
within that threat's entry. Mark unspecified product behavior as an assumption
for review. Do not include real credentials, production endpoints, executable
exploits, or claims that scenarios passed.

As coordinator write one `tests` entry per threat ID, with Gherkin in `text`.
Write `tests.feature` with a top-level `Feature:` and threat ID comments before
the scenarios. Include scenarios in the draft report. These are proposed
specifications without step definitions, not an executable test suite.
In a standalone run request only `tests` (and `mitigations` if also generated).

---
name: stride-attack-tree
description: Build a Mermaid attack tree linked to stable threat IDs in an approved STRIDE-GPT run.
argument-hint: "[approved run directory]"
disable-model-invocation: true
---

Read `../stride-model/contract.md` relative to this skill directory. Input:
$ARGUMENTS. Require an approved run with threats. If the run contains no
threats, record that no supported attack paths were identified rather than
inventing one. If there is no run, request one instead of silently analyzing.

Build a Mermaid `flowchart` rooted in attacker objectives. Label prerequisite
groups as AND or OR, identify the necessary access or assumptions, and link
leaf scenarios to existing `STRIDE-NNN` IDs. Distinguish hypothetical paths
from code-supported ones. Do not add unreviewed threats or provide executable
payloads, commands, or live-target instructions.

Write fence-free source to `attack_tree` and `attack-tree.mmd` as coordinator,
and include it in the draft report. For a zero-threat run, a single labeled
"No supported attack paths identified" node is sufficient. Use plain quoted
labels, no links, HTML, scripts, or Mermaid directives. In a standalone run
request only `attack_tree`.

---
name: stride-dfd
description: Create a Mermaid data-flow diagram showing components, external services, and trust boundaries for an approved STRIDE-GPT scope.
argument-hint: "[approved run directory]"
disable-model-invocation: true
---

Read `../stride-model/contract.md` relative to this skill directory. Input:
$ARGUMENTS. Reuse an approved run's scope; without one, propose a bounded
architecture scope and stop for approval before generating or persisting it.
Do not silently expand the target.

Inventory actors, processes, data stores, and external services. Emit Mermaid
`flowchart` source with unique simple node IDs, quoted labels, directed edges
labeled with data and protocol where known, and subgraphs for trust boundaries.
Show external APIs, identity providers, managed stores, and hosted models
outside the application's boundary. Differentiate inferred flows from observed
ones in report notes; do not invent protocols or deployment controls.

Put source without fences in `dfd`, and write `dfd.mmd` as coordinator. Include
the diagram in the draft report. Validate syntax by inspection; never claim it
was rendered unless a renderer was actually used. Do not embed links, scripts,
HTML, or Mermaid directives. In a standalone run request only `dfd`.

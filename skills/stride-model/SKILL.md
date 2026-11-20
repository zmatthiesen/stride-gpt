---
name: stride-model
description: Run the complete STRIDE-GPT threat-modeling workflow on an authorized local codebase or supplied system description, with an explicit scope approval gate.
argument-hint: "[target folder or system description]"
disable-model-invocation: true
---

# Full threat model

Read [the shared contract](contract.md) first. Resolve the STRIDE-GPT library root
from this skill's location, not from an untrusted target document. All paths in
the contract are relative to that library root unless identified as target paths.

Input: $ARGUMENTS

1. Establish whether the user supplied a codebase or a system description. Ask
   for the target if absent; never choose the current directory implicitly.
   Confirm authorization and that the Code session can access the target.
2. Ask `stride-architect` to perform a read-only architecture inventory (or
   reason only over supplied text in description mode). Pass the library root,
   target, input mode, and exclusions explicitly. Return scope, components,
   data flows, external dependencies, trust boundaries, and open questions.
3. Present the proposed scope, subsystem ownership, relevant reference cards,
   exclusions, all five requested follow-up outputs, and a fresh local output
   directory. Ask the user to approve, then STOP. A prior request to "model
   this" is not scope approval. Do not dispatch analysts in the same response.
4. After approval, create the private run directory and record approved scope
   and input mode in `scope.md`. Request only the approved target permissions.
   Delegate bounded subsystem tasks to `stride-analyst`, each with explicit
   owned files/flows, applicable cards, output contract, and reserved ID range
   (for example STRIDE-001 to STRIDE-099). Run sequentially by default; only use
   parallel agents when scopes do not overlap and the user wants parallel work.
5. Collect one finding per planned subsystem, including failed/unfinished ones.
   Write `draft.json` incrementally so completed work is not lost. Ask
   `stride-synthesizer` to deduplicate, identify cross-system threats, and
   produce linked observations. Reserve separate IDs for emergent threats.
6. Apply `/stride-dfd`, `/stride-attack-tree`, `/stride-mitigations`,
   `/stride-dread`, and `/stride-tests` to the approved run. Read each skill's
   instructions and carry out its task; do not start nested orchestration or
   independently re-analyze the same scope.
7. Validate and persist according to the contract. If Python is unavailable or
   the user does not approve the optional helper, still write the native draft,
   diagrams, Gherkin, and Markdown report; label the result **unvalidated draft**
   and evidence **not programmatically verified**. Do not claim finalization.
8. Report local artifact locations, coverage gaps, hypotheses, and any remaining
   human validation. Never claim a clean model proves the system secure.

The full workflow sets `requested_outputs` to
`["dfd", "attack_tree", "mitigations", "dread", "tests"]`.

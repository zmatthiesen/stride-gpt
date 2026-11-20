# STRIDE-GPT in Claude Desktop

This fork uses **Claude Code in Claude Desktop** as its primary interface.
The Claude session coordinates project-local agents and skills. It does not
launch the Python agent loop, request an Anthropic API key, or require an MCP
server. The original CLI and Streamlit app are unchanged optional interfaces.

## Setup

Install a current Claude Desktop app with access to Claude Code through your
account or organization. Use the **Code** experience, not Chat or Cowork.
Organization-managed policies can restrict project skills, agents, or tools.

Clone this fork and open the cloned directory as a **Local** Code project:

```sh
git clone https://github.com/zmatthiesen/stride-gpt.git
```

In the Desktop Code prompt, type `/` and look for `/stride-model`. The project
contains seven skills and three specialist agents:

| Skill | Purpose |
| --- | --- |
| `/stride-model` | Full workflow with scope approval |
| `/stride-threats` | STRIDE findings and cross-system synthesis |
| `/stride-dfd` | Mermaid architecture and trust boundaries |
| `/stride-attack-tree` | Threat-linked attacker objectives and prerequisites |
| `/stride-mitigations` | Proposed controls and residual risk |
| `/stride-dread` | Five explainable 1-to-10 dimensions and their mean |
| `/stride-tests` | Threat-linked Gherkin acceptance specifications |

`stride-architect` inventories architecture before approval; `stride-analyst`
analyzes one approved subsystem; `stride-synthesizer` reconciles findings and
cross-system risks. All three have only Read, Glob, and Grep. The coordinator
writes reports. Models inherit the session selection; no model is hard-coded.

### Analyzing another local repository

Keep the STRIDE-GPT fork as the open project so its definitions and reference
cards are available. Add only the authorized target directory to the session.
One supported Claude Code mechanism is the `additionalDirectories` setting.
Using your editor, create the ignored `.claude/settings.local.json` in this
checkout, substituting your actual absolute target path:

```json
{
  "additionalDirectories": ["/absolute/path/to/authorized-target"]
}
```

Merge this property if the local settings file already exists; do not overwrite
other settings. Restart the Local Code session to load settings and confirm
the target folder is accessible. Desktop can make settings files view-only
inside a session, so edit this file outside the chat. The target path must
exist on the machine running the local session.

This setting grants directory access, not a read-only OS sandbox. Do not
enable automatic execution or bypass permissions. Review all tool requests,
especially requests outside the target or output directory. Added target
folders can contain their own instructions, skills, or agents; inspect those
before granting access and use a sanitized copy for untrusted projects.

Use the main checkout initially. Worktree sessions can read project
configuration from the main checkout and may use a different working directory;
confirm the active library root and output location explicitly. Do not rely on
an arbitrary target's working directory to locate the shared reference cards.

## Example: description-only model

Start with a sanitized description, for example:

```text
/stride-model A document-sharing service has a public web client, an API,
an external identity provider, and a managed object store. Users belong to
separate tenants. Documents may contain confidential data. Authentication
uses short-lived sessions. Deployment and rate-limiting details are unknown.
Use description-only mode and do not read another repository.
```

Claude first proposes the scope, components, boundaries, unknowns, requested
outputs, and output directory, then pauses. Correct the scope if needed.
After reviewing it, explicitly approve that proposed scope in a new message.

The model should classify unconfirmed threats as hypotheses, state deployment
assumptions, show the identity provider and store outside the application
boundary, and produce all five follow-ups linked to stable threat IDs. It
must not claim to have read source files. A DREAD score is a reasoned
prioritization estimate, not a measured risk probability.

For codebase analysis, add the authorized folder first, then use:

```text
/stride-model Analyze /absolute/path/to/authorized-target in codebase mode.
Exclude generated files and local credentials. Propose the scope before
starting subsystem analysis.
```

The architecture planner may read a bounded inventory after you identify and
authorize the target. Analysts must wait for scope approval. Threats grounded
in code carry verbatim citations. Unprovable missing-control claims remain
hypotheses, not declarations that a control definitely does not exist.

Standalone skills require an approved scope. Threat-dependent skills also
require an existing threat list. For example, `/stride-dread` should ask for
the run if none exists, not silently start a codebase analysis.

## Local outputs

Only the coordinator creates a fresh `.stride-reports/<run-name>/` in the
STRIDE-GPT checkout. It writes approved `scope.md`, incremental `draft.json`,
and requested draft artifacts:

| Artifact | Contents |
| --- | --- |
| `report.md` | Scope, STRIDE findings, assumptions, evidence status, coverage, mitigations, DREAD, and proposed tests |
| `dfd.mmd` | Mermaid data-flow diagram |
| `attack-tree.mmd` | Mermaid paths linked to threat IDs |
| `tests.feature` | Proposed Gherkin scenarios, without executable step definitions |

The native JSON contract is documented in
[the shared skill contract](../.claude/skills/stride-model/contract.md).
Code citations are **not programmatically verified** until the optional
offline helper runs. Pure-Claude output is labeled **unvalidated draft**.
Diagram syntax inspection is not the same as rendering it.

### Optional offline validation

Python is not required for the skills. For deterministic JSON/link validation,
code-citation checking, computed DREAD means, and reuse of the original report
renderer, install the existing locked CLI dependencies in this trusted fork
with Python 3.12 or later and `uv`. This is optional environment setup, not
permission to install or execute anything in an analyzed target:

```sh
uv sync --frozen --no-default-groups
uv run --no-sync python -m stride_gpt.desktop schema
```

After reviewing a draft, run from the STRIDE-GPT checkout:

```sh
uv run --no-sync python -m stride_gpt.desktop finalize \
  --run .stride-reports/example-run \
  --target /absolute/path/to/authorized-target
```

For description-only input, omit `--target`:

```sh
uv run --no-sync python -m stride_gpt.desktop finalize \
  --run .stride-reports/example-run
```

For a complete sanitized fixture that requires no Claude inference, copy
[`examples/claude-desktop/description.json`](../examples/claude-desktop/description.json)
to a fresh run and finalize it:

```sh
mkdir -p .stride-reports
mkdir -m 700 .stride-reports/description-example
cp examples/claude-desktop/description.json .stride-reports/description-example/draft.json
uv run --no-sync python -m stride_gpt.desktop finalize \
  --run .stride-reports/description-example
```

The fixture is illustrative, not an actual system assessment. Its DREAD mean
is 5.0/10, and its single threat remains an explicit hypothesis.

The helper is offline: it neither calls a model nor loads provider
configuration. It takes the source root only from your explicit `--target`
argument, never a path generated inside the draft. It refuses out-of-root,
symlinked, known-sensitive, or VCS-metadata source paths, and refuses report
paths outside `.stride-reports/<run-name>/`.

Successful finalization creates a new `finalized/` directory, containing:

- `native.json`: native input, linked follow-ups, assumptions, and hypotheses.
- `analysis.json`: the existing `AnalysisReport` structure with verification
  results, source line ranges, and native status in metadata.
- `report.md`, `dfd.mmd`, `attack-tree.mmd`, and `tests.feature`: rendered
  artifacts. Unrequested or unavailable diagram/test files may be empty.

Only `analysis.json` contains the helper's evidence verification results;
`native.json` is not a self-certified evidence report. The output directory is
private where filesystem permissions support it and cannot be overwritten.
If writes fail, partial files may remain: keep them for diagnosis and finalize
a new run rather than treating an incomplete directory as success.

A matching snippet proves only that the cited text exists, not that the
scenario is exploitable or the architecture coverage is complete. Native
validation checks structured fields and Gherkin keywords; it is not a Mermaid
renderer, Gherkin parser, exploit tester, or proof that Claude followed every
instruction. Sensitive-path checks are defensive heuristics, not a complete
secret detector. Never give the workflow unsanitized credentials.

Inspect `metadata.status` in `analysis.json`. Missing requested outputs,
unfinished or failed subsystems/synthesis, declared limitations, and unverified
evidence yield `partial`, while preserving useful findings. Malformed JSON,
invalid links/scores, forbidden paths, and overwrite attempts fail with a
nonzero exit and an explicit error. A successful command does not mean the
model is complete, and a completed model does not mean the system is secure.

If quota, context, or tool failures interrupt analysis, preserve findings and
mark remaining subsystems unfinished. Confirm scope and target changes before
continuing an old draft. Native artifacts are not legacy CLI checkpoints.
Claude session call counts, tokens, cost, and quota remain in the session UI;
the helper does not fabricate them.

## Data handling and boundaries

Reports persist locally, unlike the original web interface's no-storage
description. Git ignores `.stride-reports/`, but ignoring files is not
encryption or access control. Reports can include sensitive source snippets.
Review them before sharing and apply your organization's retention policy.
Remove individual run directories when no longer needed.

Your configured Claude service still processes session inputs and tool
results. Follow your account's and organization's data handling policies;
"offline helper" does not mean "offline Claude inference." Do not upload
credentials, personal data, production secrets, or unauthorized source.

No live scanning, exploit execution, target builds/tests, network retrieval,
remediation edits, global hooks, permission bypasses, or new API services are
part of this workflow. References are reused from the fork, not fetched at
analysis time. Reports and diagrams are untrusted generated content: review
them before using a renderer, editor, CI integration, or external service.

## Optional original interfaces

The README's existing [installation](../README.md#installation) and
[usage](../README.md#usage) instructions still apply to the CLI and web app.
Those interfaces retain their own provider settings, API keys, and persistence
rules. Merely choosing an Anthropic model in the web UI is not this native
workflow.

Installing the PyPI package does not install these repository-local Claude
definitions. Open a clone of this fork for the Desktop experience. This
adaptation is based on upstream revision
`7980fe4f19b797bc7c0e11822da88e25d357cf26`; the original MIT attribution is
preserved.

## Acceptance checklist and troubleshooting

Automated checks can validate definitions, references, schemas, evidence
checking, and report rendering. Actual Desktop behavior requires a signed-in
Desktop session and is **not established by those checks**.

1. Open a Local Code session on the fork; confirm all seven slash skills are
   discoverable and the three named agents can be delegated to.
2. Run the sanitized description example. Confirm an explicit scope-approval
   pause, no target-file reads, hypotheses without code citations, external
   trust boundaries, linked follow-ups, and local draft artifacts.
3. Add a sanitized fixture repository. Confirm read-only planning, approval
   before analysts, correct subsystem ownership, and verbatim relative-path
   citations. Reject any unexpected shell, network, or sensitive-file request.
4. Generate the complete workflow and inspect every threat ID across attack
   trees, mitigations, all five DREAD rationales, and Gherkin scenarios.
5. If using the optional helper, confirm finalization, source line ranges,
   arithmetic means, the recorded status, and rejection of an overwrite.
6. Interrupt a run or deny a tool request. Confirm completed findings survive,
   remaining scope is explicitly unfinished, and no completion claim is made.
7. Invoke an individual skill without prerequisites; confirm it asks for the
   approved run rather than manufacturing findings or expanding the scope.

If skills do not appear, verify that you opened the fork's root in **Code**,
not Chat, a package installation, or the analyzed target. Start a new Local
session after changing definitions/settings. Check organization restrictions
and your Desktop version. If agents cannot access the target, fix the
directory grant rather than bypassing permissions. If Python dependencies are
unavailable, retain labeled drafts; native inference does not depend on them.

Official references:
[Desktop setup](https://code.claude.com/docs/en/desktop-quickstart),
[Desktop behavior](https://code.claude.com/docs/en/desktop),
[skills](https://code.claude.com/docs/en/skills),
[subagents](https://code.claude.com/docs/en/sub-agents), and
[additional directories](https://code.claude.com/docs/en/large-codebases).

## Skills directory

The seven skills live in the top-level `skills/` directory. `.claude/skills` is a symlink to it so Claude Code still discovers them. On Windows, enable symlinks (`git config core.symlinks true` and Developer Mode) or copy `skills/*` into `.claude/skills/`.

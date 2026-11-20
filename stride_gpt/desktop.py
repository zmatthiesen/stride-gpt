"""Offline validation and rendering for Claude Code skills. No model calls."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from stride_gpt.agent.evidence import verify_evidence
from stride_gpt.agent.report import render_markdown
from stride_gpt.core.schemas import AnalysisPlan, AnalysisReport, Subsystem, SubsystemFinding

Text = Annotated[str, Field(min_length=1)]
ThreatId = Annotated[str, Field(pattern=r"^STRIDE-[0-9]{3,}$")]
Score = Annotated[int, Field(strict=True, ge=1, le=10)]
Category = Literal[
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]
Reference = Literal["genai", "agentic", "insider_threat", "mitre_enterprise", "mitre_atlas"]
Output = Literal["dfd", "attack_tree", "mitigations", "dread", "tests"]


class NativeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Citation(NativeModel):
    path: Text
    snippet: Text


class Threat(NativeModel):
    id: ThreatId
    category: Category
    scenario: Text
    impact: Text
    basis: Literal["code", "hypothesis"]
    evidence: Annotated[list[Citation], Field(max_length=3)]
    assumptions: list[Text]
    autonomy_level: Literal["L1", "L2", "L3", "L4"] | None = None
    mappings: dict[
        Literal["OWASP_LLM", "OWASP_ASI", "INSIDER_CATEGORY", "MITRE_ATTACK"], list[Text]
    ] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_basis(self) -> Self:
        if self.basis == "code" and not self.evidence:
            raise ValueError(f"{self.id}: code-based threats require evidence")
        if self.basis == "hypothesis" and (not self.assumptions or self.evidence):
            raise ValueError(f"{self.id}: hypotheses require assumptions and no code evidence")
        return self


class Scope(NativeModel):
    name: Text
    description: Text
    key_files: list[Text]
    focus_areas: list[Text]


class Finding(NativeModel):
    subsystem: Text
    outcome: Literal["completed", "unfinished", "error"]
    notes: list[Text]
    files_analyzed: list[Text]
    threats: list[Threat]

    @model_validator(mode="after")
    def explain_incomplete(self) -> Self:
        if self.outcome != "completed" and not self.notes:
            raise ValueError("unfinished or failed findings require explanatory notes")
        return self


class Observation(NativeModel):
    summary: Text
    related_threats: Annotated[list[ThreatId], Field(min_length=1)]


class LinkedText(NativeModel):
    threat_id: ThreatId
    text: Text


class Rating(NativeModel):
    score: Score
    rationale: Text


class Dread(NativeModel):
    threat_id: ThreatId
    damage: Rating
    reproducibility: Rating
    exploitability: Rating
    affected_users: Rating
    discoverability: Rating

    def mean(self) -> float:
        return (
            sum(
                getattr(self, name).score
                for name in (
                    "damage",
                    "reproducibility",
                    "exploitability",
                    "affected_users",
                    "discoverability",
                )
            )
            / 5
        )


class NativeRun(NativeModel):
    input_mode: Literal["codebase", "description"]
    target_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")]
    description: Text
    requested_outputs: list[Output]
    scope: Annotated[list[Scope], Field(min_length=1)]
    findings: list[Finding]
    cross_cutting_threats: list[Threat]
    observations: list[Observation]
    assumptions: list[Text]
    exclusions: list[Text]
    limitations: list[Text]
    references_loaded: list[Reference]
    synthesis_status: Literal["completed", "unfinished", "error"]
    dfd: str = ""
    attack_tree: str = ""
    mitigations: list[LinkedText] = Field(default_factory=list)
    dread: list[Dread] = Field(default_factory=list)
    tests: list[LinkedText] = Field(default_factory=list)

    def all_threats(self) -> list[Threat]:
        return [
            t for finding in self.findings for t in finding.threats
        ] + self.cross_cutting_threats

    @model_validator(mode="after")
    def check_links(self) -> Self:
        scopes = [s.name for s in self.scope]
        findings = [f.subsystem for f in self.findings]
        if len(set(scopes)) != len(scopes) or sorted(scopes) != sorted(findings):
            raise ValueError("scope names must be unique with exactly one finding per subsystem")
        ids = [t.id for t in self.all_threats()]
        if len(ids) != len(set(ids)):
            raise ValueError("threat IDs must be unique across the whole run")
        known = set(ids)
        for observation in self.observations:
            if not set(observation.related_threats) <= known:
                raise ValueError("observation refers to an unknown threat")
        for name in ("mitigations", "dread", "tests"):
            links = [item.threat_id for item in getattr(self, name)]
            if not set(links) <= known or len(links) != len(set(links)):
                raise ValueError(f"{name} must have unique, known threat IDs")
        for finding in self.findings:
            cited = {c.path for t in finding.threats for c in t.evidence}
            if not cited <= set(finding.files_analyzed):
                raise ValueError("subsystem evidence must cite files listed as analyzed")
        read_files = {p for f in self.findings for p in f.files_analyzed}
        if not {c.path for t in self.cross_cutting_threats for c in t.evidence} <= read_files:
            raise ValueError("cross-cutting evidence must cite files listed as analyzed")
        tree_ids = set(re.findall(r"\bSTRIDE-[0-9]{3,}\b", self.attack_tree))
        if not tree_ids <= known:
            raise ValueError("attack tree refers to an unknown threat")
        if self.input_mode == "description":
            if any(s.key_files for s in self.scope) or any(f.files_analyzed for f in self.findings):
                raise ValueError("description-only runs cannot claim inspected files")
            if any(t.basis != "hypothesis" for t in self.all_threats()):
                raise ValueError("description-only threats must be hypotheses")
        for test in self.tests:
            if not all(
                re.search(rf"(?m)^\s*{word}\s+\S", test.text)
                for word in ("Scenario:", "Given", "When", "Then")
            ):
                raise ValueError(f"{test.threat_id}: tests require Scenario, Given, When, Then")
        return self


def _safe_source(root: Path, value: str) -> Path:
    path = PurePosixPath(value)
    if "\\" in value or path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"source path must be relative to the approved target: {value}")
    denied = {".git", ".hg", ".svn", ".ssh", ".aws", ".azure", ".gnupg", ".kube"}
    for part in path.parts:
        name = part.casefold()
        if (
            name in denied
            or name.startswith((".env", "credentials", "secrets"))
            or name in {".npmrc", ".pypirc", "api_key.txt"}
            or Path(name).suffix in {".pem", ".key", ".p12", ".pfx", ".keystore"}
        ):
            raise ValueError(f"sensitive source path refused: {value}")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"source symlinks are refused: {value}")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError(f"source must be a file inside the approved target: {value}")
    return resolved


def build_report(run: NativeRun, target: Path | None) -> tuple[AnalysisReport, list[str]]:
    """Recheck citations against an explicitly supplied root, never a model path."""
    if run.input_mode == "codebase" and (target is None or not target.is_dir()):
        raise ValueError("codebase runs require --target pointing to the approved directory")
    if run.input_mode == "description" and target is not None:
        raise ValueError("description-only runs must not specify --target")
    root = target.resolve() if target is not None else None
    warnings = list(run.limitations)
    for finding in run.findings:
        if finding.outcome != "completed":
            warnings.append(f"{finding.subsystem}: {finding.outcome}")
        if root is not None:
            for path in finding.files_analyzed:
                _safe_source(root, path)
    if root is not None:
        for subsystem in run.scope:
            for path in subsystem.key_files:
                _safe_source(root, path)
    if run.synthesis_status != "completed":
        warnings.append(f"synthesis: {run.synthesis_status}")
    ids = {t.id for t in run.all_threats()}
    for output in set(run.requested_outputs):
        if output in {"dfd", "attack_tree"}:
            if not getattr(run, output):
                warnings.append(f"requested output missing: {output}")
        elif {item.threat_id for item in getattr(run, output)} != ids:
            warnings.append(f"requested output does not cover every threat: {output}")
    if "attack_tree" in run.requested_outputs and not ids <= set(
        re.findall(r"\bSTRIDE-[0-9]{3,}\b", run.attack_tree)
    ):
        warnings.append("attack tree does not cover every threat")

    def convert(threat: Threat) -> dict:
        checks = []
        if root is not None:
            for citation in threat.evidence:
                _safe_source(root, citation.path)
            checks = verify_evidence(
                root, [c.model_dump() for c in threat.evidence], max_items=len(threat.evidence)
            )
            if any(not c.verified for c in checks):
                warnings.append(f"{threat.id}: unverified evidence")
            if any(c.occurrences > 1 for c in checks):
                warnings.append(f"{threat.id}: ambiguous evidence location")
        return {
            "id": threat.id,
            "Threat Type": threat.category,
            "Scenario": f"[{threat.id}; {threat.basis}] {threat.scenario}",
            "Potential Impact": threat.impact,
            "evidence": [c.to_dict() for c in checks],
            **({"autonomy_level": threat.autonomy_level} if threat.autonomy_level else {}),
            **{
                name: values if name == "MITRE_ATTACK" else ", ".join(values)
                for name, values in threat.mappings.items()
            },
        }

    report = AnalysisReport(
        plan=AnalysisPlan(
            target_path=run.target_name,
            overall_description=run.description,
            subsystems=[Subsystem(**s.model_dump()) for s in run.scope],
        ),
        findings=[
            SubsystemFinding(
                subsystem=f.subsystem,
                outcome=f.outcome,
                files_analyzed=f.files_analyzed,
                threats=[convert(t) for t in f.threats],
                improvement_suggestions=f.notes,
            )
            for f in run.findings
        ],
        cross_cutting_threats=[convert(t) for t in run.cross_cutting_threats],
        systemic_observations=[
            {
                "Threat Type": "Systemic observation",
                "Scenario": o.summary,
                "Related Threats": o.related_threats,
            }
            for o in run.observations
        ],
        data_flow_diagram=run.dfd or None,
    )
    report.metadata = {
        "interface": "claude-code",
        "status": "partial" if warnings else "completed",
        "input_mode": run.input_mode,
        "limitations": warnings,
        "references_loaded": run.references_loaded,
        "token_usage": None,
    }
    return report, warnings


def _native_markdown(run: NativeRun, report: AnalysisReport, warnings: list[str]) -> str:
    lines = [
        f"> **Native run status: {report.metadata['status']}**",
        "> Citation verification checks quoted text, not exploitability or analysis completeness.",
        "> Description-only threats are hypotheses. Gherkin scenarios have not been executed.",
        "",
        render_markdown(report),
        "## Assumptions and boundaries",
        "",
        *[f"- {text}" for text in run.assumptions],
        *[f"- Excluded: {text}" for text in run.exclusions],
        *[f"- Limitation: {text}" for text in warnings],
        "",
        "## Threat assumptions",
        "",
    ]
    for threat in run.all_threats():
        lines.extend([f"### {threat.id} ({threat.basis})", *threat.assumptions, ""])
        if threat.autonomy_level:
            lines.append(f"Agent autonomy: {threat.autonomy_level}")
    lines.extend(["## Mitigations", ""])
    lines.extend(f"- **{m.threat_id}**: {m.text}" for m in run.mitigations)
    lines.extend(["", "## DREAD", "", "Scores are judgment-based, from 1 to 10.", ""])
    for rating in run.dread:
        lines.append(f"### {rating.threat_id}: mean {rating.mean():.1f}/10")
        for name in (
            "damage",
            "reproducibility",
            "exploitability",
            "affected_users",
            "discoverability",
        ):
            value = getattr(rating, name)
            lines.append(f"- {name}: {value.score}/10. {value.rationale}")
    if run.attack_tree:
        lines.extend(["", "## Attack tree", "", "```mermaid", run.attack_tree, "```"])
    lines.extend(["", "## Proposed tests (not executed)", ""])
    for test in run.tests:
        lines.extend([f"### {test.threat_id}", "```gherkin", test.text, "```", ""])
    return "\n".join(lines) + "\n"


def finalize(run_dir: Path, target: Path | None) -> Path:
    """Write a fresh finalized directory; never replace an existing report."""
    project = Path.cwd().resolve()
    directory = run_dir.absolute()
    relative = directory.relative_to(project)
    if len(relative.parts) != 2 or relative.parts[0] != ".stride-reports":
        raise ValueError("run directory must be .stride-reports/<run-name> in this project")
    for path in (project / ".stride-reports", directory, directory / "draft.json"):
        if path.is_symlink():
            raise ValueError(f"report symlinks are refused: {path.name}")
    draft = directory / "draft.json"
    if not draft.is_file() or draft.stat().st_size > 2_000_000:
        raise ValueError("draft.json must be a regular file no larger than 2 MB")
    run = NativeRun.model_validate_json(draft.read_text(encoding="utf-8"))
    report, warnings = build_report(run, target)
    # Render before reserving the output directory so validation failures leave no artifacts.
    outputs = {
        "native.json": run.model_dump_json(indent=2),
        "analysis.json": report.model_dump_json(indent=2),
        "report.md": _native_markdown(run, report, warnings),
        "dfd.mmd": run.dfd,
        "attack-tree.mmd": run.attack_tree,
        "tests.feature": "\n\n".join(f"# {t.threat_id}\n{t.text}" for t in run.tests),
    }
    if run.tests:
        outputs["tests.feature"] = (
            "Feature: Proposed threat mitigations\n\n" + outputs["tests.feature"]
        )
    output = directory / "finalized"
    output.mkdir(mode=0o700)
    for name, content in outputs.items():
        with (output / name).open("x", encoding="utf-8") as handle:
            handle.write(content + "\n")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="Print the native draft JSON schema")
    render = commands.add_parser("finalize", help="Validate a local draft and render reports")
    render.add_argument("--run", type=Path, required=True)
    render.add_argument("--target", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            print(json.dumps(NativeRun.model_json_schema(), indent=2))
        else:
            output = finalize(args.run, args.target)
            report = AnalysisReport.model_validate_json(
                (output / "analysis.json").read_text(encoding="utf-8")
            )
            print(f"{output}\nStatus: {report.metadata['status']}")
    except (OSError, ValueError, ValidationError) as error:
        print(f"Native report failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

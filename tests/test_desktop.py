"""Native definitions and offline finalization, without Claude or provider calls."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from stride_gpt.core.prompts.variants import _parse_frontmatter, _split_frontmatter
from stride_gpt.core.schemas import AnalysisReport
from stride_gpt.desktop import NativeRun, build_report, finalize, main

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def draft():
    return json.loads((ROOT / "examples/claude-desktop/description.json").read_text())


@pytest.fixture
def code_draft(draft, tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    (root / "api.py").write_text("def access(session):\n    return session.user\n")
    draft["input_mode"] = "codebase"
    draft["scope"][0]["key_files"] = ["api.py"]
    finding = draft["findings"][0]
    finding["files_analyzed"] = ["api.py"]
    finding["threats"][0].update(
        basis="code",
        evidence=[{"path": "api.py", "snippet": "return session.user"}],
        assumptions=[],
    )
    return draft, root


def test_native_definitions_discover_and_resolve_references():
    skills = ROOT / ".claude" / "skills"
    entries = sorted(skills.glob("*/SKILL.md"))
    assert len(entries) == 7
    for path in entries:
        front, body = _split_frontmatter(path.read_text())
        metadata = _parse_frontmatter(front)
        assert metadata["name"] == path.parent.name
        assert metadata["description"]
        assert metadata["disable-model-invocation"] == "true"
        assert "$ARGUMENTS" in body
        contract = path.parent / (
            "contract.md" if path.parent.name == "stride-model" else "../stride-model/contract.md"
        )
        assert contract.is_file()
    agents = sorted((ROOT / ".claude" / "agents").glob("*.md"))
    assert len(agents) == 3
    for path in agents:
        front, body = _split_frontmatter(path.read_text())
        metadata = _parse_frontmatter(front)
        assert metadata["name"] == path.stem
        assert metadata["description"]
        assert set(str(metadata["tools"]).split(", ")) == {"Read", "Glob", "Grep"}
        assert ".claude/skills/stride-model/contract.md" in body
    contract = (skills / "stride-model" / "contract.md").read_text()
    cards = re.findall(r"\| `([a-z_]+\.md)` \|", contract)
    assert len(cards) == 5
    for card in cards:
        assert (ROOT / "stride_gpt/core/prompts/threat_model" / card).is_file()
    assert (ROOT / "CLAUDE.md").is_file()


def test_description_finalization_and_existing_report_compatibility(draft, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / ".stride-reports" / "example"
    run_dir.mkdir(parents=True)
    (run_dir / "draft.json").write_text(json.dumps(draft))
    result = finalize(run_dir, None)
    report = AnalysisReport.model_validate_json((result / "analysis.json").read_text())
    assert report.metadata["status"] == "completed"
    assert report.metadata["token_usage"] is None
    assert report.findings[0].threats[0]["evidence"] == []
    assert report.systemic_observations[0]["Related Threats"] == ["STRIDE-001"]
    markdown = (result / "report.md").read_text()
    assert "mean 5.0/10" in markdown
    assert "STRIDE-001; hypothesis" in markdown
    assert "have not been executed" in markdown
    assert "Unknown" not in markdown
    assert (result / "tests.feature").read_text().startswith("Feature:")
    assert (result / "dfd.mmd").read_text().strip() == draft["dfd"]
    assert (result / "attack-tree.mmd").read_text().strip() == draft["attack_tree"]
    assert (
        NativeRun.model_validate_json((result / "native.json").read_text()).target_name
        == "example-app"
    )
    before = (result / "report.md").read_bytes()
    with pytest.raises(FileExistsError):
        finalize(run_dir, None)
    assert (result / "report.md").read_bytes() == before


def test_code_evidence_is_rechecked_not_self_certified(code_draft):
    draft, root = code_draft
    report, warnings = build_report(NativeRun.model_validate(draft), root)
    evidence = report.findings[0].threats[0]["evidence"][0]
    assert evidence["verified"] is True
    assert (evidence["start_line"], evidence["end_line"]) == (2, 2)
    assert warnings == []
    draft["findings"][0]["threats"][0]["evidence"][0]["snippet"] = "return verified_user"
    report, warnings = build_report(NativeRun.model_validate(draft), root)
    assert report.findings[0].threats[0]["evidence"][0]["verified"] is False
    assert report.metadata["status"] == "partial"
    assert warnings == ["STRIDE-001: unverified evidence"]


def test_native_framework_fields_survive_rendering(draft):
    threat = draft["findings"][0]["threats"][0]
    threat["mappings"] = {
        "OWASP_LLM": ["LLM01: Prompt Injection"],
        "OWASP_ASI": ["ASI01: Agent Goal Hijack"],
        "INSIDER_CATEGORY": ["Credential Compromise"],
        "MITRE_ATTACK": ["T1078: Valid Accounts"],
    }
    threat["autonomy_level"] = "L3"
    report, _ = build_report(NativeRun.model_validate(draft), None)
    converted = report.findings[0].threats[0]
    assert converted["OWASP_LLM"] == "LLM01: Prompt Injection"
    assert converted["MITRE_ATTACK"] == ["T1078: Valid Accounts"]
    assert converted["autonomy_level"] == "L3"


def test_attack_tree_requires_known_links_and_complete_coverage(draft):
    draft["attack_tree"] = 'flowchart TD\n  missing["STRIDE-999"]'
    with pytest.raises(ValidationError, match="unknown threat"):
        NativeRun.model_validate(draft)
    draft["attack_tree"] = 'flowchart TD\n  goal["No linked threats"]'
    report, warnings = build_report(NativeRun.model_validate(draft), None)
    assert report.metadata["status"] == "partial"
    assert "attack tree does not cover every threat" in warnings


@pytest.mark.parametrize(
    "change",
    [
        "unknown-link",
        "duplicate-id",
        "missing-evidence",
        "forged-verification",
        "files-in-description",
        "out-of-range-score",
        "bool-score",
        "invalid-gherkin",
    ],
)
def test_rejects_malformed_or_misleading_artifacts(draft, change):
    threat = draft["findings"][0]["threats"][0]
    if change == "unknown-link":
        draft["mitigations"][0]["threat_id"] = "STRIDE-999"
    elif change == "duplicate-id":
        draft["cross_cutting_threats"] = [dict(threat)]
    elif change == "missing-evidence":
        draft["input_mode"] = "codebase"
        threat["basis"] = "code"
    elif change == "forged-verification":
        threat["evidence"] = [{"path": "api.py", "snippet": "return user", "verified": True}]
    elif change == "files-in-description":
        draft["findings"][0]["files_analyzed"] = ["api.py"]
    elif change == "out-of-range-score":
        draft["dread"][0]["damage"]["score"] = 11
    elif change == "bool-score":
        draft["dread"][0]["damage"]["score"] = True
    elif change == "invalid-gherkin":
        draft["tests"][0]["text"] = "Test passed"
    with pytest.raises(ValidationError):
        NativeRun.model_validate(draft)


@pytest.mark.parametrize("field", ["mitigations", "dread", "tests", "dfd", "attack_tree"])
def test_missing_requested_followups_are_partial_not_silent_success(draft, field):
    draft[field] = "" if field in {"dfd", "attack_tree"} else []
    report, warnings = build_report(NativeRun.model_validate(draft), None)
    assert report.metadata["status"] == "partial"
    assert any(field in warning.replace(" ", "_") for warning in warnings)


def test_unfinished_subsystem_and_failed_synthesis_preserve_findings(draft):
    draft["findings"][0].update(outcome="unfinished", notes=["Permission denied during analysis."])
    draft["synthesis_status"] = "error"
    draft["limitations"] = ["Synthesis interrupted."]
    report, warnings = build_report(NativeRun.model_validate(draft), None)
    assert report.metadata["status"] == "partial"
    assert len(report.findings[0].threats) == 1
    assert "API: unfinished" in warnings
    assert "synthesis: error" in warnings


def test_missing_subsystems_and_false_completed_findings_are_rejected(draft):
    draft["scope"].append(
        {
            "name": "Worker",
            "description": "Unexamined worker",
            "key_files": [],
            "focus_areas": [],
        }
    )
    with pytest.raises(ValidationError, match="exactly one finding"):
        NativeRun.model_validate(draft)
    draft["scope"].pop()
    draft["findings"][0]["outcome"] = "unfinished"
    draft["findings"][0]["notes"] = []
    with pytest.raises(ValidationError, match="explanatory notes"):
        NativeRun.model_validate(draft)


@pytest.mark.parametrize(
    "path",
    [
        "../outside.py",
        "/etc/passwd",
        ".git/config",
        ".env",
        "credentials.json",
        "nested/secrets.yml",
        "private.key",
        "src\\api.py",
    ],
)
def test_forbidden_source_paths_fail_before_reading(code_draft, path):
    draft, root = code_draft
    draft["scope"][0]["key_files"] = []
    draft["findings"][0]["files_analyzed"] = [path]
    draft["findings"][0]["threats"][0]["evidence"][0]["path"] = path
    with pytest.raises(ValueError):
        build_report(NativeRun.model_validate(draft), root)


def test_source_symlink_is_rejected(code_draft, tmp_path):
    draft, root = code_draft
    external = tmp_path / "external.py"
    external.write_text("return session.user")
    (root / "api.py").unlink()
    (root / "api.py").symlink_to(external)
    with pytest.raises(ValueError, match="symlinks"):
        build_report(NativeRun.model_validate(draft), root)


def test_helper_requires_explicit_target(code_draft):
    payload, root = code_draft
    with pytest.raises(ValueError, match="require --target"):
        build_report(NativeRun.model_validate(payload), None)
    payload["input_mode"] = "description"
    payload["scope"][0]["key_files"] = []
    payload["findings"][0]["files_analyzed"] = []
    payload["findings"][0]["threats"] = []
    payload["observations"] = []
    payload["attack_tree"] = ""
    payload["mitigations"] = []
    payload["dread"] = []
    payload["tests"] = []
    with pytest.raises(ValueError, match="must not specify"):
        build_report(NativeRun.model_validate(payload), root)


def test_report_path_boundaries_and_errors(draft, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "draft.json").write_text(json.dumps(draft))
    assert main(["finalize", "--run", str(outside)]) == 1
    assert "Native report failed" in capsys.readouterr().err
    (tmp_path / ".stride-reports").mkdir()
    link = tmp_path / ".stride-reports" / "linked"
    link.symlink_to(outside, target_is_directory=True)
    assert main(["finalize", "--run", str(link)]) == 1
    assert "symlinks" in capsys.readouterr().err
    assert not (outside / "finalized").exists()


def test_cli_schema_and_malformed_draft_errors(tmp_path, monkeypatch, capsys):
    assert main(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["additionalProperties"] is False
    assert "findings" in schema["required"]
    monkeypatch.chdir(tmp_path)
    run = tmp_path / ".stride-reports" / "bad"
    run.mkdir(parents=True)
    (run / "draft.json").write_text('{"not valid"')
    assert main(["finalize", "--run", str(run)]) == 1
    assert "Native report failed" in capsys.readouterr().err
    assert not (run / "finalized").exists()

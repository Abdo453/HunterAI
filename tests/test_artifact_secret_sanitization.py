"""LEDGER-019 — Secret sanitization on every artifact output (M2).

Acceptance: a secret injected through any artifact channel (raw tool output,
parsed data, stage file, log line, timeline event, lineage record, manifest)
never appears verbatim in ANY file written to the engagement directory.
"""
from __future__ import annotations

from hunter_ai.pipeline.engagement_manager import EngagementManager

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
STRIPE_KEY = "sk_live_ABCD1234567890abcdefWXYZ"
PASSWORD = "SuperSecret123"

SECRETS = [AWS_KEY, GH_TOKEN, STRIPE_KEY, PASSWORD]

# The mask bullet is escaped as \u2022 inside JSON artifacts, so accept either
# the literal glyph (raw text files) or its JSON escape.
MASK_MARKERS = ("\u2022\u2022\u2022\u2022", "\\u2022\\u2022\\u2022\\u2022")


def _write_everything(mgr: EngagementManager) -> None:
    mgr.save_tool_artifact(
        stage="09_javascript",
        tool_name="gitleaks",
        command=f"gitleaks detect --token {GH_TOKEN}",
        raw_output=f"leak: aws={AWS_KEY}\npassword={PASSWORD}\n",
        parsed_data={"leaks": [{"api_key": STRIPE_KEY, "aws": AWS_KEY}]},
    )
    mgr.save_stage_file(
        "12_vulnerabilities",
        "findings.json",
        {"evidence": {"aws": AWS_KEY, "password": f"password={PASSWORD}"}},
    )
    mgr.record_lineage(
        asset_id="a1", asset_value=f"db://root:{PASSWORD}@host",
        asset_type="database", tool="gitleaks", stage="09_javascript",
        metadata={"token": GH_TOKEN},
    )
    mgr.record_timeline_event(
        stage="09_javascript", event="secret_found",
        message=f"Found credential {STRIPE_KEY} and password={PASSWORD}",
        detail=f"ghp token {GH_TOKEN}",
    )
    mgr.log(f"raw token {AWS_KEY} leaked")
    mgr._save_manifest()
    mgr._save_timeline()
    mgr._save_lineage()


def test_no_secret_leaks_into_any_artifact(tmp_path):
    mgr = EngagementManager(target="example.com", base_dir=str(tmp_path))
    _write_everything(mgr)

    blob = ""
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert files, "expected artifact files to be written"
    for p in files:
        blob += p.read_text(encoding="utf-8", errors="replace")

    for secret in SECRETS:
        assert secret not in blob, f"secret {secret!r} leaked verbatim"

    # The masking actually happened (not merely that files are empty).
    assert any(marker in blob for marker in MASK_MARKERS)


def test_stage_file_is_scrubbed_even_when_called_directly(tmp_path):
    mgr = EngagementManager(target="example.com", base_dir=str(tmp_path))
    path = mgr.save_stage_file("13_evidence", "raw.json", {"aws": AWS_KEY})
    content = open(path, encoding="utf-8").read()
    assert AWS_KEY not in content
    assert any(marker in content for marker in MASK_MARKERS)

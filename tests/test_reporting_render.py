"""Keep persisted report Markdown byte-compatible across renderer refactors."""

import hashlib

import pytest

from aidast.reporting import legacy_models, legacy_render, models, render


# Captured from both original renderers before extracting their common code.
EXPECTED_DIGESTS = {
    "case/hackerone/False": "0be3090b699c68dc4b1581b873d22f58b95735ba0f78b5c5f8c4b1ae2fe53a38",
    "case/hackerone/True": "089d0d24c66b0cd5e2f75b04f82f027805ed5ad5a2523777a3b1ee676abde560",
    "case/bugcrowd/False": "9621afb466c223494f5f1e077a531b5426b9fa943f902e6595892604e3e30ee7",
    "case/bugcrowd/True": "058aa23181518fb216acba7c77f8527f89e72816a6d69781118569a82d47a6ed",
    "case/intigriti/False": "bef57a208f89a4744dfa9ef151eec272e5660a2491256b06d41d1a215f28566c",
    "case/intigriti/True": "99c17dcebeb484f6bc5972bc874382036f644f4c2888b5ecc338fb976100ce2a",
    "legacy/hackerone/False": "3e982d53df851bb0c7b317f97d7a7d6c79e5e367bb023a95a1b4a06b4a05729f",
    "legacy/hackerone/True": "562a89cb5aa537156232029073eb54eb6befd8947337b798f53031dcd93cab43",
    "legacy/bugcrowd/False": "a63c57a2d1fbd109e2201572af7922d013e1bc50b0c3bce16aff7e859531986f",
    "legacy/bugcrowd/True": "4211a31e2b578f80aa526ad3c05fb14de30d52b4a4f214afd5bb7a1d3b482ec0",
    "legacy/intigriti/False": "e2e88ad5cf49954ed0b068f80c3ca431504bb58e9e6d1ebc824ab768ec74fdf7",
    "legacy/intigriti/True": "25c6bee13d9f825b9e68c24185fa43860720f628cd18c6034e9f7ebfc347eb59",
}


def render_fixture(schema, platform, optional):
    model_module, renderer, id_field = (
        (models, render, "case_id")
        if schema == "case"
        else (legacy_models, legacy_render, "validation_id")
    )

    def cited(text):
        return {"text": text, "evidence_ids": ["evidence_1", "evidence_2"]}

    document = {
        "platform": platform,
        id_field: "record_1",
        "source_context_sha256": "a" * 64,
        "title": cited("Local <result> & [title]"),
        "asset": cited("https://example.invalid/path"),
        "weakness": cited("Recorded classification"),
        "summary": cited("한글 요약\n<script>text</script> ![image](https://example.invalid)"),
        "steps_to_reproduce": [cited("First step\ncontinued"), cited("Second *step*")],
        "expected_behavior": cited("Expected"),
        "actual_behavior": cited("Observed"),
        "impact": cited("Recorded impact"),
    }
    if optional:
        document.update(
            prerequisites=[cited("Prerequisite one"), cited("Prerequisite two")],
            severity=cited("Low"),
            cvss_vector=cited("Recorded vector"),
            remediation="Escape <text> & `markup`.",
            attachment_evidence_ids=["evidence_1", "evidence_2"],
        )
        if platform == "bugcrowd":
            document["vrt_category"] = cited("Recorded VRT category")
    return renderer.render_report(model_module.ReportDraft.model_validate(document))


@pytest.mark.parametrize("schema", ["case", "legacy"])
@pytest.mark.parametrize("platform", ["hackerone", "bugcrowd", "intigriti"])
@pytest.mark.parametrize("optional", [False, True], ids=["required", "all-fields"])
def test_report_markdown_keeps_persisted_bytes(schema, platform, optional):
    markdown = render_fixture(schema, platform, optional)
    key = f"{schema}/{platform}/{optional}"
    assert hashlib.sha256(markdown.encode("utf-8")).hexdigest() == EXPECTED_DIGESTS[key]

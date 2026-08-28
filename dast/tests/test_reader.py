from __future__ import annotations

import unittest

from aidast.scope.models import CaptureReason, CaptureStatus
from aidast.scope.reader import PlaywrightProgramPageReader


def classify(text: str, *, final_url: str, has_scope_view: bool = False):
    return PlaywrightProgramPageReader._classify_capture(
        text, final_url=final_url, has_scope_view=has_scope_view
    )


class ClassifyCaptureTests(unittest.TestCase):
    def test_denial_signals_are_blocked(self) -> None:
        cases = {
            "Access Denied": CaptureReason.ACCESS_DENIED,
            "Please verify you are human": CaptureReason.BOT_CHALLENGE,
            "Enable JavaScript and cookies to continue": (
                CaptureReason.JAVASCRIPT_RENDER_INCOMPLETE
            ),
        }
        for text, reason in cases.items():
            with self.subTest(text=text):
                status, actual_reason = classify(
                    text, final_url="https://bugcrowd.com/engagements/example"
                )
                self.assertEqual(status, CaptureStatus.BLOCKED)
                self.assertEqual(actual_reason, reason)

    def test_near_empty_capture_is_blocked(self) -> None:
        status, reason = classify(
            "Register\nLogin",
            final_url="https://yeswehack.com/programs/example",
        )
        self.assertEqual(status, CaptureStatus.BLOCKED)
        self.assertEqual(reason, CaptureReason.CONTENT_INCOMPLETE)

    def test_hackerone_requires_structured_scope_table(self) -> None:
        sparse = "Notion Labs, Inc. " * 40
        status, reason = classify(
            sparse, final_url="https://hackerone.com/notion", has_scope_view=False
        )
        self.assertEqual(status, CaptureStatus.PARTIAL)
        self.assertEqual(reason, CaptureReason.CONTENT_INCOMPLETE)

        rich = (
            "Notion Labs, Inc. Assets In Scope Asset Name Bounty details here. "
        ) * 10
        status, reason = classify(
            rich, final_url="https://hackerone.com/notion", has_scope_view=True
        )
        self.assertEqual(status, CaptureStatus.COMPLETE)
        self.assertEqual(reason, CaptureReason.NONE)

    def test_bugcrowd_requires_targets_and_in_scope(self) -> None:
        sparse = "Bug Bounty engagement page with rules. " * 20
        status, _ = classify(
            sparse, final_url="https://bugcrowd.com/engagements/example"
        )
        self.assertEqual(status, CaptureStatus.PARTIAL)

        rich = "Targets In Scope Payment reward chart P1 P2 P3 P4 rules here. " * 10
        status, reason = classify(
            rich, final_url="https://bugcrowd.com/engagements/example"
        )
        self.assertEqual(status, CaptureStatus.COMPLETE)
        self.assertEqual(reason, CaptureReason.NONE)

    def test_yeswehack_requires_scopes_and_program_rules(self) -> None:
        sparse = "TeamViewer bug bounty program description text. " * 20
        status, _ = classify(
            sparse, final_url="https://yeswehack.com/programs/teamviewer"
        )
        self.assertEqual(status, CaptureStatus.PARTIAL)

        rich = "Scopes 9 assets listed here. Program Rules apply to testing. " * 10
        status, reason = classify(
            rich, final_url="https://yeswehack.com/programs/teamviewer"
        )
        self.assertEqual(status, CaptureStatus.COMPLETE)
        self.assertEqual(reason, CaptureReason.NONE)

    def test_generic_host_requires_in_scope_phrase(self) -> None:
        sparse = "Some program description without the marker phrase. " * 20
        status, _ = classify(sparse, final_url="https://intigriti.com/programs/x/y")
        self.assertEqual(status, CaptureStatus.PARTIAL)

        rich = "The following assets are in scope for this program. " * 10
        status, reason = classify(
            rich, final_url="https://intigriti.com/programs/x/y"
        )
        self.assertEqual(status, CaptureStatus.COMPLETE)
        self.assertEqual(reason, CaptureReason.NONE)


if __name__ == "__main__":
    unittest.main()

"""Tests for the detectors, masking, report, and git history scan."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import detectors  # noqa: E402
import scanner  # noqa: E402
from report import group_findings, render_markdown  # noqa: E402

AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"
AWS_SECRET = "AbCdEfGhIjKlMnOp" + "QrStUvWxYz0123456789+/AB"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GOOGLE_KEY = "AIza" + "SyDq1W2e3R4t5Y6u7I8o9P0a1S2d3F4g5HX"
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SENDGRID_KEY = (
    "SG." + "A1b2C3d4E5f6G7h8I9j0K1" + "."
    + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0fE1"
)
TWILIO_KEY = "SK" + "0123456789abcdef" * 2
JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)
DISCORD_URL = (
    "https://discord.com/api/webhooks/123456789012345678/"
    "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
)


def rule_ids(line: str) -> set[str]:
    return {finding.rule_id for finding in detectors.scan_line(line, "x.py", 1)}


class DetectorTests(unittest.TestCase):
    def test_known_key_shapes(self):
        cases = {
            "aws_access_key": f'aws_key = "{AWS_KEY}"',
            "aws_secret_key": f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}",
            "github_token": f'token = "{GITHUB_TOKEN}"',
            "google_api_key": f'key = "{GOOGLE_KEY}"',
            "stripe_live_key": f'stripe = "{STRIPE_KEY}"',
            "sendgrid_key": f'sendgrid = "{SENDGRID_KEY}"',
            "twilio_key": f'twilio = "{TWILIO_KEY}"',
            "jwt": f'authorization = "Bearer {JWT}"',
            "discord_webhook": f"webhook = {DISCORD_URL}",
        }
        for expected, line in cases.items():
            with self.subTest(expected):
                self.assertIn(expected, rule_ids(line))

    def test_private_key_header(self):
        self.assertIn(
            "private_key_block",
            rule_ids("-----BEGIN RSA PRIVATE KEY-----"),
        )

    def test_url_password(self):
        line = "db = postgres://app:S3cretPassw0rd@db.internal:5432/app"
        self.assertIn("url_credentials", rule_ids(line))

    def test_dotenv_assignment(self):
        line = "STRIPE_SECRET_KEY=notARealValue12345"
        self.assertIn("dotenv_assignment", rule_ids(line))

    def test_generic_assignment(self):
        line = 'api_key = "q9Xv2Lm8Np4Rs7Tu"'
        self.assertIn("generic_assignment", rule_ids(line))

    def test_placeholders_are_ignored(self):
        for line in [
            'api_key = "your_api_key_here"',
            'token = "changeme_please"',
            'password = "example_password"',
            'secret = "xxxxxxxxxxxx"',
        ]:
            with self.subTest(line):
                self.assertEqual(rule_ids(line), set())

    def test_normal_gameplay_text_is_ignored(self):
        line = "I killed him and then missed the jump, chat is laughing"
        self.assertEqual(rule_ids(line), set())

    def test_one_secret_one_rule(self):
        # The .env rule and the generic rule can both see an assignment.
        line = f'AWS_SECRET_ACCESS_KEY="{AWS_SECRET}"'
        findings = detectors.scan_line(line, "x.env", 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "aws_secret_key")


class MaskingTests(unittest.TestCase):
    def test_mask_keeps_only_edges(self):
        masked = detectors.mask_secret(AWS_KEY)
        self.assertTrue(masked.startswith("AKIA"))
        self.assertTrue(masked.endswith(AWS_KEY[-4:]))
        self.assertNotIn(AWS_KEY[4:-4], masked)

    def test_fingerprint_is_stable_and_short(self):
        first = detectors.fingerprint(GITHUB_TOKEN)
        second = detectors.fingerprint(GITHUB_TOKEN)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 12)

    def test_private_key_mask_hides_body(self):
        masked = detectors.mask_secret("RSA PRIVATE KEY", "header")
        self.assertIn("REDACTED", masked)


class ReportTests(unittest.TestCase):
    def test_report_groups_same_secret(self):
        findings = detectors.scan_line(f'key = "{GITHUB_TOKEN}"', "a.py", 4)
        findings += detectors.scan_line(f'key = "{GITHUB_TOKEN}"', "b.py", 9)
        groups = group_findings(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].findings), 2)

    def test_report_never_contains_raw_secret(self):
        findings = detectors.scan_line(f'key = "{GITHUB_TOKEN}"', "a.py", 4)
        groups = group_findings(findings)
        meta = {
            "generated_at": "2026-11-19T00:00:00+08:00",
            "paths": ["."],
            "files_scanned": 1,
            "files_skipped": 0,
            "git_used": False,
            "rules_count": len(detectors.RULES),
        }
        report = render_markdown(groups, meta)
        self.assertNotIn(GITHUB_TOKEN, report)
        self.assertIn("Rotation plans", report)
        self.assertIn("Verify the old one is dead", report)
        self.assertIn("github.com/settings/tokens", report)


class IgnoreTests(unittest.TestCase):
    def test_directory_and_glob_patterns(self):
        ignore = scanner.IgnoreRules(["tests/", "*.log", "secrets.env"])
        self.assertTrue(ignore.matches_rel("tests/test_scanner.py"))
        self.assertTrue(ignore.matches_rel("deep/tests/test_x.py"))
        self.assertTrue(ignore.matches_rel("logs/app.log"))
        self.assertTrue(ignore.matches_rel("config/secrets.env"))
        self.assertFalse(ignore.matches_rel("app/config.py"))

    def test_ignore_file_is_auto_loaded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".secretsignore").write_text("ignored.txt\n", encoding="utf-8")
            (root / "ignored.txt").write_text(GITHUB_TOKEN, encoding="utf-8")
            (root / "kept.txt").write_text("nothing here", encoding="utf-8")
            ignore = scanner.IgnoreRules.load([root])
            names = {path.name for path in scanner.iter_files(root, ignore)}
            self.assertEqual(names, {"kept.txt"})

    def test_inline_ignore_marker(self):
        line = f'key = "{GITHUB_TOKEN}"  # secrets:ignore'
        self.assertEqual(detectors.scan_line(line, "x.py", 1), [])


class ZipTests(unittest.TestCase):
    def test_secret_inside_zip(self):
        import zipfile

        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "takeout.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(
                    "Takeout/Drive/notes.txt",
                    f'TOKEN = "{GITHUB_TOKEN}"\n',
                )
                zf.writestr("Takeout/Drive/photo.jpg", b"\x00\x01binary")
            findings, read, skipped = scanner.scan_zip(archive)
            self.assertEqual(read, 1)
            self.assertEqual(skipped, 1)
            self.assertTrue(any(f.rule_id == "github_token" for f in findings))
            self.assertIn("!", findings[0].path)


class FileScanTests(unittest.TestCase):
    def test_binary_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "blob.bin"
            path.write_bytes(b"\x00\x01" + GITHUB_TOKEN.encode())
            self.assertEqual(scanner.scan_file(path), [])

    def test_git_history_finds_removed_secret(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            file = repo / "config.py"
            file.write_text(f'TOKEN = "{GITHUB_TOKEN}"\n', encoding="utf-8")
            run = lambda *args: subprocess.run(
                ["git", "-C", str(repo), *args],
                capture_output=True,
                text=True,
                check=True,
            )
            run("init", "-q")
            run("add", "config.py")
            run(
                "-c", "user.email=test@example.com",
                "-c", "user.name=Test",
                "commit", "-q", "-m", "add config",
            )
            file.write_text("TOKEN = 'removed'\n", encoding="utf-8")
            run("add", "config.py")
            run(
                "-c", "user.email=test@example.com",
                "-c", "user.name=Test",
                "commit", "-q", "-m", "remove token",
            )
            findings = scanner.scan_git_history(repo)
            self.assertTrue(
                any(f.rule_id == "github_token" for f in findings), findings
            )
            self.assertTrue(findings[0].commit)


if __name__ == "__main__":
    unittest.main()

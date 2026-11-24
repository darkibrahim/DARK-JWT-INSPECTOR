import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import main
from modules import reporter
from tests.helpers import TEST_SECRET, make_token


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.token = make_token({"sub": "u1", "email": "a@b.com", "password": "hunter2",
                                 "contact": "x@y.org", "exp": 9999999999, "iss": "i", "aud": "a"})
        self.res = main.analyze_token(self.token, TEST_SECRET)
        self.report = main.make_report(self.res)

    def test_redaction(self):
        text = reporter.to_json(self.report)
        for secret in ("hunter2", "a@b.com", "x@y.org", self.token, self.token.split(".")[2]):
            self.assertNotIn(secret, text)
        self.assertEqual(self.report["payload"]["password"], "[REDACTED]")
        self.assertEqual(self.report["payload"]["sub"], "u1")

    def test_report_is_valid_json_with_branding(self):
        data = json.loads(reporter.to_json(self.report))
        self.assertEqual(data["tool"]["developer"], "DARK IBRAHIM")
        self.assertEqual(data["verification"]["status"], "verified")

    def test_save_requires_consent(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            with self.assertRaises(PermissionError):
                reporter.save_report(self.report, target)
            self.assertFalse(target.exists())
            reporter.save_report(self.report, target, consent=True)
            self.assertTrue(json.loads(target.read_text(encoding="utf-8")))

    def test_cli_json_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "sub" / "rep.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main.main(["--json", "--no-color", "--output", str(out), self.token])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(buf.getvalue())["token"]["value"], "[REDACTED]")
            self.assertTrue(out.exists())

    def test_cli_does_not_save_without_output(self):
        before = set(Path(main.config.REPORTS_DIR).glob("*.json"))
        with redirect_stdout(io.StringIO()):
            main.main(["--no-color", self.token])
        self.assertEqual(before, set(Path(main.config.REPORTS_DIR).glob("*.json")))

    def test_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main.main(["--no-color", "garbage"]), 1)
            import os
            os.environ["DJI_TEST_SECRET"] = "wrong"
            self.assertEqual(main.main(["--no-color", "--secret-env", "DJI_TEST_SECRET", self.token]), 2)
            del os.environ["DJI_TEST_SECRET"]
            self.assertEqual(main.main(["--no-color", "--secret-env", "DJI_NOT_SET", self.token]), 1)

    def test_negative_leeway_rejected_by_parser(self):
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                main.build_parser().parse_args(["--leeway", "-5", "x"])

    def test_interactive_bad_token_is_not_kept(self):
        import builtins
        answers = iter(["1", "garbage", "2", "0"])
        original = builtins.input
        builtins.input = lambda *_a, **_k: next(answers)
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                code = main.interactive()
        finally:
            builtins.input = original
        self.assertEqual(code, 0)
        self.assertIn("Enter a token first", buf.getvalue())

    def test_interactive_survives_eof(self):
        import builtins
        answers = iter(["1"])
        def fake_input(*_a, **_k):
            try:
                return next(answers)
            except StopIteration:
                raise EOFError
        original = builtins.input
        builtins.input = fake_input
        try:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main.interactive(), 0)
        finally:
            builtins.input = original

    def test_banner_and_help_contain_branding(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main.main(["--about", "--no-color"])
        out = buf.getvalue()
        for text in ("DARK IBRAHIM", "Bug Bounty Hunter & Cyber Security Expert",
                     "profile.php?id=61580661413217", "github.com/darkibrahim", "@Hunter_1B4H14"):
            self.assertIn(text, out)
        self.assertIn("@Hunter_1B4H14", main.build_parser().format_help())


if __name__ == "__main__":
    unittest.main()

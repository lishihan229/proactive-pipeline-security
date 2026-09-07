import unittest

from pipeline_security.rules import scan_text


class RuleTests(unittest.TestCase):
    def test_detects_hardcoded_secret(self):
        findings = scan_text("app.py", 'api_key = "not-a-real-secret"')  # pps: ignore
        self.assertTrue(any(item.rule == "A02-hardcoded-secret" for item in findings))

    def test_detects_safe_code_as_clean(self):
        findings = scan_text("app.py", "import os\\napi_key = os.environ['API_KEY']")
        self.assertEqual(findings, [])

    def test_detects_shell_true(self):
        findings = scan_text("worker.py", "subprocess.run(command, shell=True)")  # pps: ignore
        self.assertTrue(any(item.rule == "A03-shell-injection" for item in findings))

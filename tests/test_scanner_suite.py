import unittest
import tempfile
import shutil
import os
from src.scanner_suite import ScannerSuite


class TestScannerSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scanner_suite_init(self):
        suite = ScannerSuite(target_dir=self.test_dir)
        self.assertEqual(suite.target_dir, os.path.abspath(self.test_dir))
        self.assertIn("semgrep", suite.tools_status)
        self.assertIn("gitleaks", suite.tools_status)
        self.assertIn("bandit", suite.tools_status)
        self.assertIn("pip-audit", suite.tools_status)

    def test_clean_directory_scan(self):
        suite = ScannerSuite(target_dir=self.test_dir)
        # Create a benign python file
        clean_file = os.path.join(self.test_dir, "app.py")
        with open(clean_file, "w", encoding="utf-8") as f:
            f.write("def hello():\n    return 'Hello, World!'\n")

        results = suite.run_full_audit()
        self.assertIn(results["gate_decision"], ["✅ PASSED", "⚠️ WARNING"])
        self.assertEqual(results["severity_counts"]["critical"], 0)


if __name__ == "__main__":
    unittest.main()

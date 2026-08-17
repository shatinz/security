import unittest
import tempfile
import shutil
import os
from src.research_engine import ResearchEngine


class TestResearchEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_research_engine_init(self):
        engine = ResearchEngine(output_dir=self.test_dir)
        self.assertEqual(engine.output_dir, self.test_dir)

    def test_generate_intelligence_brief(self):
        engine = ResearchEngine(output_dir=self.test_dir)
        mock_results = {
            "timestamp": "2026-08-17T09:00:00",
            "packages_scanned": 2,
            "findings_by_package": {
                "npm:next": 3,
                "PyPI:django": 1
            },
            "critical_cves": [
                {
                    "id": "GHSA-1234",
                    "cve": "CVE-2025-55182",
                    "package": "react",
                    "ecosystem": "npm",
                    "summary": "React2Shell RCE in RSC flight deserializer",
                    "details_url": "https://osv.dev/vulnerability/GHSA-1234"
                }
            ]
        }

        custom_threats = [
            {
                "title": "React2Shell",
                "severity": "CRITICAL",
                "vector": "Flight protocol deserializer",
                "mitigation": "Upgrade React >= 19.2.1"
            }
        ]

        brief = engine.generate_intelligence_brief(mock_results, custom_threats=custom_threats)
        self.assertIn("# 🛡️ Security Intelligence Brief", brief)
        self.assertIn("CVE-2025-55182", brief)
        self.assertIn("React2Shell", brief)


if __name__ == "__main__":
    unittest.main()


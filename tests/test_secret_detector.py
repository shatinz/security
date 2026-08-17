import unittest
from src.secret_detector import SecretDetector, calculate_entropy


class TestSecretDetector(unittest.TestCase):
    def test_entropy_calculation(self):
        low_entropy = calculate_entropy("aaaaaaa")
        high_entropy = calculate_entropy("aB8$kL2@zP9#qR5!")
        self.assertLess(low_entropy, 1.0)
        self.assertGreater(high_entropy, 3.0)

    def test_detect_openai_key(self):
        detector = SecretDetector()
        mock_token = "".join(["s", "k", "-", "proj", "-", "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"])
        sample = f'OPENAI_API_KEY = "{mock_token}"'
        findings = detector.scan_text(sample, "test.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "SEC-AI-OPENAI-001")
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertIn("sk-p...34yz", findings[0]["match_masked"])

    def test_detect_anthropic_key(self):
        detector = SecretDetector()
        # 93 chars + AA = 95 chars
        prefix = "".join(["s", "k", "-", "ant", "-", "api03", "-"])
        key = prefix + ("a" * 93) + "AA"
        sample = f'ANTHROPIC_KEY = "{key}"'
        findings = detector.scan_text(sample, "test.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "SEC-AI-ANTHROPIC-001")

    def test_detect_supabase_key(self):
        detector = SecretDetector()
        mock_sb = "".join(["s", "b", "_", "secret", "_", "1234567890123456789012345678901"])
        sample = f'SUPABASE_KEY = "{mock_sb}"'
        findings = detector.scan_text(sample, "test.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "SEC-AI-SUPABASE-001")

    def test_detect_github_fine_grained_token(self):
        detector = SecretDetector()
        prefix = "".join(["git", "hub", "_", "pat", "_"])
        token = prefix + ("a" * 82)
        sample = f'GH_PAT = "{token}"'
        findings = detector.scan_text(sample, "test.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "SEC-GH-002")


    def test_ignore_clean_code(self):
        detector = SecretDetector()
        sample = '''
        def calculate_total(price, tax):
            return price * (1 + tax)
        '''
        findings = detector.scan_text(sample, "clean.py")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()


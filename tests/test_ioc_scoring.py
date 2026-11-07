"""Threat-intel matches and the risk score. Imports scanner.py, so config.py
must be importable; nothing here touches the network or the database."""
import unittest
from unittest import mock

import scanner


def finding(tool="threat_intel", severity="high", issue="MalwareBazaar: listed", p_real=None):
    f = {"tool": tool, "severity": severity, "issue_text": issue, "filename": "/a",
         "line_number": 0, "code_snippet": ""}
    if p_real is not None:
        f["p_real"] = p_real
    return f


HASH = finding()
URL = finding(issue="URLhaus: listed")


class ThresholdGuard(unittest.TestCase):
    def test_thresholds_are_unchanged(self):
        self.assertEqual(scanner.CATEGORY_THRESHOLDS["malicious_pattern"], (15, 35, 100))
        self.assertEqual(scanner.CATEGORY_THRESHOLDS["vulnerability"], (20, 80, 300))
        self.assertEqual(scanner.SEVERITY_WEIGHT, {"high": 10, "medium": 3, "low": 1})


class WeightTests(unittest.TestCase):
    @staticmethod
    def malware(findings):
        return scanner.calculate_category_risk(findings)["malicious_pattern"]

    def test_no_match_changes_nothing(self):
        plain = [finding("yara", "high", "x", 0.5), finding("bandit", "low", "y", 1.0)]
        self.assertEqual(scanner.calculate_risk(plain)[3], 6)

    def test_one_known_malware_hash_is_critical_on_the_malware_axis(self):
        risk = self.malware([HASH])
        self.assertEqual((risk["score"], risk["level"]), (101, "Critical"))
        self.assertEqual(scanner.calculate_risk([HASH])[3:], (101, "High"))

    def test_one_known_bad_url_is_high_on_the_malware_axis(self):
        risk = self.malware([URL])
        self.assertEqual((risk["score"], risk["level"]), (36, "High"))
        self.assertEqual(scanner.calculate_risk([URL])[3:], (36, "Medium"))

    def test_url_points_are_capped_and_stay_high(self):
        risk = self.malware([URL] * 10)
        self.assertEqual((risk["score"], risk["level"]), (72, "High"))

    def test_matches_add_to_existing_findings(self):
        self.assertEqual(self.malware([HASH, URL, finding("yara", "high", "x", 1.0)])["score"], 147)

    def test_match_counts_as_a_high_finding(self):
        self.assertEqual(scanner.calculate_risk([HASH])[0], 1)

    def test_match_is_on_the_malware_axis_only(self):
        self.assertEqual(scanner.finding_category(HASH), "malicious_pattern")
        self.assertEqual(scanner.calculate_category_risk([HASH])["vulnerability"]["score"], 0)


class ClassifierTests(unittest.TestCase):
    def test_match_keeps_full_confidence_and_skips_the_model(self):
        with mock.patch.object(scanner, "_load_model_artifact") as loader:
            out = scanner.score_findings([finding()])
        loader.assert_not_called()
        self.assertEqual(out[0]["p_real"], 1.0)

    def test_match_is_not_lost_when_other_findings_are_scored(self):
        findings = [finding(), finding("yara", "low", "ordinary")]
        with mock.patch.object(scanner, "_load_model_artifact", return_value=None):
            out = scanner.score_findings(findings)
        self.assertEqual(len(out), 2)
        self.assertEqual([f["p_real"] for f in out], [1.0, 1.0])

    def test_real_model_tolerates_a_match_alongside_other_tools(self):
        findings = [finding(), finding("bandit", "medium", "Use of exec detected.")]
        out = scanner.score_findings(findings)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["p_real"], 1.0)
        self.assertTrue(0.0 <= out[1]["p_real"] <= 1.0)


class FailureTests(unittest.TestCase):
    def test_extraction_crash_is_reported_and_never_raised(self):
        with mock.patch.object(scanner.ioc_extractor, "extract_iocs", side_effect=RuntimeError("x")):
            result = scanner.run_ioc_extraction("/nonexistent", [])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["iocs"], [])

    def test_threat_intel_crash_keeps_the_extraction(self):
        rows = {"iocs": [{"ioc_type": "url", "value": "http://a.xyz/"}], "status": "done",
                "note": None, "files_scanned": 1, "files_hashed": 0, "ti_status": "off"}
        with mock.patch.object(scanner.ioc_extractor, "extract_iocs", return_value=rows), \
             mock.patch.object(scanner.ioc_extractor, "enrich_with_threat_intel",
                               side_effect=RuntimeError("x")):
            result = scanner.run_ioc_extraction("/nonexistent", [])
        self.assertEqual(len(result["iocs"]), 1)
        self.assertEqual(result["ti_status"], "failed")


if __name__ == "__main__":
    unittest.main()

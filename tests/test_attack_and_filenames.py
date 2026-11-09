"""MITRE ATT&CK labels on findings, and disguised file names (2026-11-09).
File names are only created in temp folders; nothing is run.

    python3 -m unittest discover -s tests -t . -v
"""
import os
import shutil
import tempfile
import unittest

import app as app_module
import filename_tricks as ft
import scanner


class AttackLabelTests(unittest.TestCase):
    def test_every_behaviour_rule_is_labelled_with_named_techniques(self):
        with open(scanner.RULES_PATH, encoding="utf-8") as fh:
            rules = [line.split()[1] for line in fh if line.startswith("rule ")]
        labelled = scanner._load_rule_attack()
        self.assertEqual(sorted(labelled), sorted(rules))
        for rule, ids in labelled.items():
            self.assertTrue(ids, rule)
            for t in ids:
                self.assertRegex(t, r"^T\d{4}(\.\d{3})?$", rule)
                self.assertIn(t, scanner.ATTACK_NAMES, f"{rule}: {t} has no name")

    def test_plain_and_hidden_matches_get_the_rules_techniques(self):
        for text in ("YARA rule matched: detect_reverse_shell — x",
                     "Hidden payload: YARA rule matched: detect_reverse_shell — x"):
            [t] = scanner.attack_techniques(text)
            self.assertEqual(t["id"], "T1059.004")
            self.assertEqual(t["url"], "https://attack.mitre.org/techniques/T1059/004/")

    def test_references_forge_and_other_engines_get_none(self):
        for text in ("Reference in a rule file, not code that runs: YARA rule matched: detect_crypto_miner — x",
                     "YARA Forge rule matched: SIGNATURE_BASE_HKTL_X [hacking tool] — x",
                     "ClamAV detected: Eicar-Test-Signature", "", None):
            self.assertEqual(scanner.attack_techniques(text), [], text)

    def test_report_filter_is_registered(self):
        f = app_module.app.jinja_env.filters["attack_techniques"]
        self.assertEqual(f("YARA rule matched: detect_crypto_miner — x")[0]["id"], "T1496")


class DisguisedNameTests(unittest.TestCase):
    def kinds(self, name):
        return [kind for kind, _, _ in ft.tricks_in(name)]

    def test_each_trick_is_caught(self):
        self.assertEqual(self.kinds("annexe‮cod.exe"), ["bidi"])
        self.assertEqual(self.kinds("invoice.pdf.exe"), ["double"])
        self.assertEqual(self.kinds("photo.jpg        .scr"), ["double"])
        self.assertEqual(self.kinds("Statement.DOCX.Exe"), ["double"])
        self.assertIn("mixed", self.kinds("pаypal-login.html"))     # Cyrillic а
        self.assertEqual(self.kinds("lnstaller.exe"), ["homoglyph"])
        self.assertEqual(self.kinds("5etup.bat"), ["homoglyph"])
        self.assertEqual(self.kinds("Micros0ft_update.zip"), ["homoglyph"])

    def test_ordinary_names_are_left_alone(self):
        for name in ("setup.py", "Installer.exe", "README.md", "logo.png.js", "data.tar.gz",
                     "report.pdf", "test_installer.py", "update.sh", "windows_build.ps1",
                     "Привет.txt", "αβγ.md", "app.min.js", "image.png", "notes.txt"):
            self.assertEqual(self.kinds(name), [], name)

    def test_direction_characters_never_reach_the_page_raw(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.makedirs(os.path.join(root, "docs2"))
        open(os.path.join(root, "docs2", "annexe‮cod.exe"), "w").close()
        open(os.path.join(root, "invoice.pdf.exe"), "w").close()
        open(os.path.join(root, "setup.py"), "w").close()
        findings = ft.find_disguised_names(root)
        self.assertEqual(sorted(f["filename"] for f in findings),
                         ["/docs2/annexe<U+202E>cod.exe", "/invoice.pdf.exe"])
        for f in findings:
            self.assertNotIn("‮", f["filename"] + f["code_snippet"] + f["issue_text"])
            self.assertEqual((f["tool"], f["severity"]), ("filename", "high"))

    def test_ignored_paths_are_skipped(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.makedirs(os.path.join(root, "tests"))
        open(os.path.join(root, "tests", "invoice.pdf.exe"), "w").close()
        self.assertEqual(ft.find_disguised_names(root, is_ignored=scanner.is_ignored_path), [])

    def test_counts_on_the_malware_axis_and_skips_the_classifier(self):
        f = {"tool": "filename", "severity": "high", "issue_text": "Disguised file name: x",
             "filename": "/a.pdf.exe", "line_number": 0, "code_snippet": ""}
        scanner.score_findings([f])
        self.assertEqual(f["p_real"], 1.0)
        self.assertEqual(scanner.finding_category(f), "malicious_pattern")
        self.assertEqual(scanner.calculate_category_risk([f])["malicious_pattern"]["score"], 10)


if __name__ == "__main__":
    unittest.main()

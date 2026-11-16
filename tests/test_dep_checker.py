"""Which dependency entries are reported as unpinned or loose, in both
directions: the real ones stay, the false ones go.

    python3 -m unittest discover -s tests -t .

No database or network; every case is a manifest written to a temp folder.
"""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import dep_checker


class Repo(unittest.TestCase):
    def setUp(self):
        self.path = tempfile.mkdtemp(prefix="maldet_deptest_")
        self.addCleanup(shutil.rmtree, self.path, ignore_errors=True)

    def write(self, name, text):
        with open(os.path.join(self.path, name), "w") as fh:
            fh.write(text)

    def findings(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return dep_checker.check_suspicious_patterns(self.path)

    def texts(self, prefix):
        return [f["issue_text"] for f in self.findings() if f["issue_text"].startswith(prefix)]


class PinKind(unittest.TestCase):
    def test_python(self):
        cases = {"2.28.1": "exact", "1.0.0rc1": "exact", "unpinned": "none", "*": "none",
                 ">=2.0": "range", "~=6.7": "range", "<1": "range", "<3,>=1.4": "range",
                 "^2.28": "range", "1.*": "range", "local": "local",
                 "@ git+https://github.com/a/b@9a8b626adb99b14e8af72dee1c1ab5ab4a17b859": "fixed",
                 "@ https://github.com/a/b.git@da5be0e": "fixed",
                 "@ git+https://github.com/a/b@v1.4.2": "fixed",
                 "@ git+https://github.com/a/b@fix-building": "mutable",
                 "@ git+https://github.com/a/b": "mutable",
                 "@ https://github.com/a/b/archive/master.zip": "mutable"}
        for version, kind in cases.items():
            self.assertEqual(dep_checker._pin_kind(version), kind, version)

    def test_npm(self):
        cases = {"1.3.3": "exact", "1.0.0-rc.5": "exact", "^1.3.3": "range", "~1.3": "range",
                 "1.x": "range", ">=1 <2": "range", "1.0.0 - 2.0.0": "range",
                 "*": "none", "latest": "none", "next": "none", "": "none",
                 "workspace:*": "local", "file:../lib": "local", "link:./x": "local",
                 "npm:typescript@^6.0.3": "range", "npm:typescript@6.0.3": "exact",
                 "github:user/repo": "mutable", "user/repo": "mutable",
                 "user/repo#0123abc": "fixed", "user/repo#semver:^1.2.0": "mutable",
                 "git+https://github.com/a/b.git#v2.0.1": "fixed",
                 "https://cdn.example.com/x-0.20.2.tgz": "mutable"}
        for version, kind in cases.items():
            self.assertEqual(dep_checker._pin_kind(version, "npm"), kind, version)


class Requirements(Repo):
    def test_constraints_are_not_called_unpinned(self):
        """Each of these was reported as having no version lock."""
        self.write("requirements.txt",
                   "whitenoise~=6.7\nuvicorn<1\nclick<9,>=7.0\nflask==3.0.0\n"
                   "proxyUtil @ git+https://github.com/x/proxyUtil@9a8b626adb99b14e8af72dee1c1ab5ab4a17b859\n")
        self.assertEqual(self.texts("Unpinned dependency"), [])

    def test_bare_names_and_branches_stay_reported(self):
        self.write("requirements.txt",
                   "pylzma\nbs4  # scraping\n"
                   "pyuv @ git+https://github.com/x/pyuv@fix-building-against-python311\n"
                   "tinyec @ https://github.com/x/tinyec/archive/master.zip\n")
        found = self.texts("Unpinned dependency")
        self.assertEqual(len(found), 4, found)
        self.assertIn("Unpinned dependency: 'pylzma' has no version lock — supply chain risk", found)
        self.assertIn("Unpinned dependency: 'bs4' has no version lock — supply chain risk", found)
        self.assertTrue(any("'pyuv' is installed from a branch or URL" in t for t in found))
        self.assertTrue(any("'tinyec' is installed from a branch or URL" in t for t in found))

    def test_options_and_hashes_are_not_packages(self):
        self.write("requirements.txt",
                   "-r base.txt\n--index-url https://example.com/simple\n-e .\n"
                   "requests==2.32.0 --hash=sha256:abc\n")
        self.assertEqual(self.findings(), [])

    def test_direct_and_editable_url_installs_stay_high(self):
        self.write("requirements.txt",
                   "git+https://github.com/x/y.git\n-e git+https://github.com/x/z.git\n")
        found = self.texts("Direct URL install detected")
        self.assertEqual(len(found), 2, found)

    def test_ranges_are_one_finding_because_there_is_no_lockfile(self):
        self.write("requirements.txt", "a>=1\nb~=2.0\nc<3\nd==4.0\n")
        found = [f for f in self.findings() if f["issue_text"].startswith("Loose version constraint")]
        self.assertEqual(len(found), 1, found)
        self.assertIn("3 dependencies in requirements.txt allow a range", found[0]["issue_text"])
        self.assertEqual(found[0]["severity"], "low")
        self.assertEqual(found[0]["code_snippet"].splitlines(), ["a>=1", "b~=2.0", "c<3"])

    def test_one_range_reads_as_singular(self):
        self.write("requirements.txt", "a>=1\n")
        self.assertIn("1 dependency in requirements.txt allows a range",
                      self.texts("Loose version constraint")[0])


class PackageJson(Repo):
    DEPS = {"dependencies": {"@radix-ui/react-checkbox": "^1.3.3", "left-pad": "1.3.0",
                             "ui": "workspace:*"},
            "devDependencies": {"eslint": "^10.13.0", "vite": "~7.1.0"}}

    def test_ranges_with_a_lockfile_are_not_reported(self):
        for lock in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            with self.subTest(lock=lock):
                self.write("package.json", json.dumps(self.DEPS))
                self.write(lock, "")
                self.assertEqual(self.findings(), [])
                os.remove(os.path.join(self.path, lock))

    def test_ranges_without_a_lockfile_are_one_finding(self):
        self.write("package.json", json.dumps(self.DEPS))
        found = self.findings()
        self.assertEqual(len(found), 1, found)
        self.assertIn("3 dependencies in package.json allow a range", found[0]["issue_text"])
        self.assertIn("no lockfile is committed", found[0]["issue_text"])

    def test_no_version_is_reported_even_with_a_lockfile(self):
        self.write("package.json", json.dumps({"dependencies": {"a": "*", "b": "latest",
                                                                "c": "github:user/repo",
                                                                "d": "user/repo#0123abc"}}))
        self.write("package-lock.json", "{}")
        found = self.texts("Unpinned dependency")
        self.assertEqual(len(found), 3, found)

    def test_long_lists_are_cut_in_the_snippet_not_the_count(self):
        self.write("package.json", json.dumps({"dependencies": {f"p{i}": "^1.0.0" for i in range(40)}}))
        f = self.findings()[0]
        self.assertIn("40 dependencies", f["issue_text"])
        self.assertEqual(f["code_snippet"].splitlines()[-1], "... and 25 more")


class Pyproject(Repo):
    TOML = ('[project]\ndependencies = ["whitenoise~=6.7", "uvicorn<1", "pyperclip", "authlib==1.6.12"]\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.28"\n'
            'impacket = {git = "https://github.com/x/impacket.git", branch = "gkdi"}\n'
            'pysecretsocks = {git = "https://github.com/x/PySecretSOCKS.git", rev = "da5be0e"}\n'
            'mylib = {path = "../mylib"}\n')

    def test_unpinned_is_only_the_bare_name_and_the_branch(self):
        self.write("pyproject.toml", self.TOML)
        found = self.texts("Unpinned dependency")
        self.assertEqual(len(found), 2, found)
        self.assertTrue(any("'pyperclip' has no version lock" in t for t in found))
        self.assertTrue(any("'impacket' is installed from a branch or URL" in t for t in found))

    def test_lockfile_decides_whether_ranges_are_reported(self):
        self.write("pyproject.toml", self.TOML)
        self.assertIn("3 dependencies in pyproject.toml", self.texts("Loose version constraint")[0])
        self.write("uv.lock", "")
        self.assertEqual(self.texts("Loose version constraint"), [])

    def test_exact_pins_for_the_cve_lookup_are_unchanged(self):
        """The parser now keeps '~=6.7' as written; it must not become a pin."""
        self.write("pyproject.toml", self.TOML)
        with contextlib.redirect_stdout(io.StringIO()):
            pins = dep_checker._exact_pins_from_manifests(self.path)
        self.assertEqual(pins, {("authlib", "1.6.12"): "pyproject.toml"})


class ClassifierKey(unittest.TestCase):
    def test_new_wording_keeps_its_category(self):
        import scanner
        for text, key in (
                ("Unpinned dependency: 'x' is installed from a branch or URL whose content can "
                 "change — supply chain risk", "Unpinned dependency"),
                ("Loose version constraint: 3 dependencies in package.json allow a range of "
                 "versions and no lockfile is committed — a newly published release is installed "
                 "automatically", "Loose version constraint")):
            self.assertEqual(scanner.frequency_key("dep_checker", text), key)


if __name__ == "__main__":
    unittest.main()

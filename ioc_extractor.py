"""Pulls indicators of compromise (IOCs) out of the files a scan has reason to
distrust: anything ClamAV or YARA flagged, plus install scripts, which run on
`pip install` / `npm install` whether or not any engine objected to them.

Deliberately not every file. A clean framework is full of URLs, and an IOC list
that names Flask's documentation site teaches its reader to ignore the list.

Everything read here comes from an untrusted repository. So nothing is ever
executed or imported (setup.py is parsed, not run), symlinks and anything
outside the clone are refused -- a link named setup.py pointing at the server's
config.py would otherwise publish its contents on a public page -- and only
regular files are opened, since reading a FIFO left by an archive would block.

No database code and no import of scanner.py, so it can be tested on its own.
scanner.run_ioc_extraction() wraps this and owns the "never fail a scan" rule.
"""

import ast
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import stat
import time
import tomllib
from urllib.parse import urlsplit

import requests

MAX_TEXT_BYTES = 2 * 1024 * 1024   # larger files are hashed but not read
MAX_VALUE_CHARS = 2048             # iocs.value; truncating an IOC would falsify it
MAX_IOCS = 5000                    # per scan, so one generated file cannot flood it
MAX_BASE64_PER_FILE = 2000
MIN_BASE64_CHARS = 41              # "longer than 40"
HASH_CHUNK = 1024 * 1024
DEFAULT_TIME_LIMIT = 60

IOC_TYPES = ("sha256", "discord_webhook", "telegram_bot_token", "btc_wallet",
             "eth_wallet", "url", "ipv4", "domain")

INSTALL_SCRIPTS = frozenset({"setup.py", "setup.cfg", "pyproject.toml", "package.json"})
# npm runs these by itself during install. "test" or "build" do not, and they
# are where ordinary projects keep their ordinary URLs.
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv",
                       ".tox", ".mypy_cache", ".pytest_cache"})

# Matched on a label boundary, never as a substring, so subdomains are covered
# and github.com.evil.example is not.
SAFE_DOMAINS = frozenset({
    "github.com", "githubusercontent.com", "pypi.org", "npmjs.com", "npmjs.org",
    "python.org", "readthedocs.io", "w3.org", "apache.org", "mozilla.org",
    "googleapis.com", "example.com", "example.org", "example.net", "localhost",
    # XML and JSON namespace identifiers: URLs that nothing ever connects to.
    "schemas.microsoft.com", "schemas.openxmlformats.org", "purl.org",
    "json-schema.org", "xml.org", "ns.adobe.com",
})
# RFC 2606/6761 names and local-network suffixes do not exist on the internet.
RESERVED_TLDS = frozenset({"test", "invalid", "example", "localhost", "local",
                           "internal", "lan", "home", "corp"})
# A bare word.word is usually code (logger.info, rect.top, foo.cc, requests.py),
# so without a scheme only TLDs that are rarely a method name or file extension
# count. A real URL is exempt: having a scheme is the evidence that it is one.
BARE_DOMAIN_TLDS = frozenset({
    "com", "net", "org", "biz", "ru", "su", "cn", "tk", "ga", "gq", "xyz",
    "club", "icu", "pw", "onion", "vip", "buzz", "cyou", "sbs", "cfd", "lol",
})

DISCORD_WEBHOOK_RE = re.compile(
    r"https?://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/"
    r"\d{17,20}/[\w-]{60,80}",
    re.IGNORECASE,
)
# No \b at the start: inside a Bot API URL the token follows the letters "bot".
TELEGRAM_TOKEN_RE = re.compile(r"(?<![0-9])\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'`<>\\^|{}]+", re.IGNORECASE)
IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])"
)
# Lowercase only, or System.Net and ASP.NET read as domains. The lookbehind
# rules out e-mail addresses, paths and the tail of a dotted attribute chain.
BARE_DOMAIN_RE = re.compile(
    r"(?<![\w.@/-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])"
)
HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})$"
)
BTC_LEGACY_RE = re.compile(r"(?<![A-Za-z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])")
BTC_BECH32_RE = re.compile(r"(?<![A-Za-z0-9])bc1[ac-hj-np-z02-9]{11,71}(?![A-Za-z0-9])")
ETH_RE = re.compile(r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])")
BASE64_RE = re.compile(rf"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{{{MIN_BASE64_CHARS},}}={{0,2}}")

# Text immediately before a dotted quad that makes it a version, not a host:
# version="1.2.3.4", __version__ = '1.2.3.4', <Version>1.2.3.4, v1.2.3.4,
# foo==1.2.3.4, AssemblyVersion("1.2.3.4"). The short words are anchored so that
# server= and build_host= do not qualify; "version" can end a longer name.
_VERSION_BEFORE_RE = re.compile(
    r"(?:(?:version|(?<![a-z0-9])(?:ver|release|revision|rev|build))"
    r"(?:_?(?:number|num|string|str|no|id))?_*[\"']?\s*[:=>(]*\s*[\"']?v?"
    r"|(?<![a-z0-9])v|==|~=|>=|<=|!=|\^)\s*[\"']?$",
    re.IGNORECASE,
)
_VERSION_AFTER_RE = re.compile(r"^-?(?:alpha|beta|rc|dev|post|pre)", re.IGNORECASE)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def is_safe_domain(host):
    host = (host or "").lower().rstrip(".")
    labels = host.split(".")
    if labels[-1] in RESERVED_TLDS:
        return True
    return any(".".join(labels[i:]) in SAFE_DOMAINS for i in range(len(labels)))


def is_public_ipv4(value):
    """False for anything that is not a routable unicast address."""
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_loopback
                                 or ip.is_private or ip.is_link_local or ip.is_unspecified)


def looks_like_version(text, start, end):
    """Whether the dotted quad at text[start:end] is a version string."""
    line_start = text.rfind("\n", max(0, start - 40), start) + 1
    before = text[max(line_start, start - 40):start]
    return bool(_VERSION_BEFORE_RE.search(before)
                or _VERSION_AFTER_RE.match(text[end:end + 6]))


def valid_btc_legacy(address):
    """Base58Check. Random base58-looking text is common in minified code and
    lockfiles, and fails this 4-byte checksum all but once in four billion."""
    number = 0
    for char in address:
        index = _B58.find(char)
        if index < 0:
            return False
        number = number * 58 + index
    try:
        raw = number.to_bytes(25, "big")
    except OverflowError:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_polymod(values):
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1ffffff) << 5 ^ value
        for i, gen in enumerate(generators):
            if (top >> i) & 1:
                check ^= gen
    return check


def valid_btc_bech32(address):
    """BIP-173 / BIP-350 checksum over the "bc" prefix."""
    data = [_BECH32.find(char) for char in address[3:]]
    if -1 in data or len(data) < 6:
        return False
    expanded = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    return _bech32_polymod(expanded + data) in (1, 0x2bc830a3)


def normalize_url(raw):
    """(url, host) for a usable URL, or None. Placeholders such as
    http://$HOST/ or http://%s fail the host check, which is the point. The $ is
    what URL_RE leaves behind when a path stops at a ${VARIABLE}."""
    url = raw.rstrip(".,:;!?'\"$")
    while url.endswith((")", "]")) and url.count(url[-1]) > url.count({")": "(", "]": "["}[url[-1]]):
        url = url[:-1].rstrip(".,:;!?'\"$")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host or not url or len(url) > MAX_VALUE_CHARS:
        return None
    if not (HOSTNAME_RE.match(host) or IPV4_RE.fullmatch(host)):
        return None
    return parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower()).geturl(), host


def _url_indicators(text):
    """(indicators, text with each URL blanked) so the host and any path that
    looks like a domain are not counted a second time as bare values."""
    found = []
    chars = None
    for match in URL_RE.finditer(text):
        if chars is None:
            chars = list(text)
        chars[match.start():match.end()] = " " * (match.end() - match.start())
        normalized = normalize_url(match.group())
        if not normalized:
            continue
        url, host = normalized
        if IPV4_RE.fullmatch(host):
            if is_public_ipv4(host):
                found += [("url", url), ("ipv4", host)]
        elif not is_safe_domain(host):
            found += [("url", url), ("domain", host)]
    return found, ("".join(chars) if chars is not None else text)


def _ip_indicators(text):
    found = []
    for match in IPV4_RE.finditer(text):
        value = match.group()
        if is_public_ipv4(value) and not looks_like_version(text, match.start(), match.end()):
            found.append(("ipv4", value))
    return found


def _urls_and_ips(text):
    urls, rest = _url_indicators(text)
    return urls + _ip_indicators(rest)


def decode_base64_strings(text, limit=MAX_BASE64_PER_FILE):
    """Decoded text of each base64 run over 40 characters that decodes to
    something readable. Most long runs are binary blobs or plain identifiers
    that merely use the alphabet, and those decode to noise."""
    decoded = []
    for count, match in enumerate(BASE64_RE.finditer(text)):
        if count >= limit:
            break
        body = match.group().rstrip("=")
        if len(body) % 4 == 1:     # no valid encoding has this length
            continue
        try:
            raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
            candidate = raw.decode("utf-8")
        except (binascii.Error, ValueError):
            continue
        printable = sum(c.isprintable() or c in "\r\n\t" for c in candidate)
        if candidate and printable / len(candidate) >= 0.9:
            decoded.append(candidate)
    return decoded


def extract_from_text(text):
    """Every indicator in one block of text, as a set of (type, value)."""
    found = set()

    # Webhooks first and blanked: they are one indicator, and leaving them in
    # would add discord.com and a second copy of the secret as a plain URL.
    webhooks = list(DISCORD_WEBHOOK_RE.finditer(text))
    rest = text
    for match in webhooks:
        found.add(("discord_webhook", match.group()))
    if webhooks:
        rest = DISCORD_WEBHOOK_RE.sub(" ", text)
    found.update(("telegram_bot_token", m.group()) for m in TELEGRAM_TOKEN_RE.finditer(rest))

    urls, rest = _url_indicators(rest)
    found.update(urls)
    found.update(_ip_indicators(rest))

    for match in BARE_DOMAIN_RE.finditer(rest):
        host = match.group()
        if host.rsplit(".", 1)[-1] in BARE_DOMAIN_TLDS and not is_safe_domain(host):
            found.add(("domain", host))

    found.update(("btc_wallet", m.group()) for m in BTC_LEGACY_RE.finditer(rest)
                 if valid_btc_legacy(m.group()))
    found.update(("btc_wallet", m.group()) for m in BTC_BECH32_RE.finditer(rest)
                 if valid_btc_bech32(m.group()))
    for match in ETH_RE.finditer(rest):
        address = match.group().lower()
        if len(set(address[2:])) > 1:    # 0x000...0 is a constant, not a wallet
            found.add(("eth_wallet", address))

    for decoded in decode_base64_strings(text):
        found.update(_urls_and_ips(decoded))
    return found


# --- install scripts: only the parts that do something ----------------------
#
# Every project names its homepage, docs and maintainers in its metadata. Those
# are the author's own links, and a safe-domain list cannot keep up with them:
# Flask's pyproject.toml alone would report palletsprojects.com and discord.gg.

_SETUP_PY_METADATA = frozenset({
    "name", "version", "description", "long_description", "license", "keywords",
    "classifiers", "url", "download_url", "project_urls", "author", "author_email",
    "maintainer", "maintainer_email", "platforms",
})
_PYPROJECT_METADATA = frozenset({
    "name", "version", "description", "readme", "license", "license-files",
    "authors", "maintainers", "urls", "keywords", "classifiers", "homepage",
    "repository", "documentation",
})
_METADATA_LINE_RE = re.compile(
    r"^\s*(?:url|download_url|homepage|home-page|project_urls|repository|documentation"
    r"|author_email|maintainer_email|email|version)\b\s*[=:].*$",
    re.IGNORECASE | re.MULTILINE,
)
_COMMENT_LINE_RE = re.compile(r"^\s*[#;].*$", re.MULTILINE)


def _setup_py_strings(source):
    """String literals in setup.py, leaving out metadata arguments, docstrings
    and comments. Parsed with ast and never executed."""
    tree = ast.parse(source)
    skipped = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg in _SETUP_PY_METADATA:
                    skipped.update(id(n) for n in ast.walk(keyword.value))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            skipped.add(id(node.value))
    return "\n".join(node.value for node in ast.walk(tree)
                     if isinstance(node, ast.Constant) and isinstance(node.value, str)
                     and id(node) not in skipped)


def _toml_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _toml_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _toml_strings(item)


def _pyproject_strings(source):
    data = tomllib.loads(source)
    for table in (data.get("project"), data.get("tool", {}).get("poetry")):
        if isinstance(table, dict):
            for key in _PYPROJECT_METADATA:
                table.pop(key, None)
    return "\n".join(_toml_strings(data))


def _setup_cfg_text(source):
    kept, in_metadata = [], False
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_metadata = stripped.lower() == "[metadata]"
        if not in_metadata and not stripped.startswith(("#", ";")):
            kept.append(line)
    return "\n".join(kept)


def _package_json_text(source):
    data = json.loads(source)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return ""
    return "\n".join(str(scripts[hook]) for hook in NPM_INSTALL_HOOKS if hook in scripts)


def install_script_text(basename, source):
    """The part of an install script worth searching."""
    parsers = {"setup.py": _setup_py_strings, "pyproject.toml": _pyproject_strings,
               "setup.cfg": _setup_cfg_text, "package.json": _package_json_text}
    try:
        return parsers[basename](source)
    except (SyntaxError, ValueError, RecursionError, AttributeError, TypeError):
        # npm will not run a package.json it cannot parse, so there is nothing
        # in it to fear. The others may be Python 2 or merely unusual: search
        # them anyway rather than skip a file an attacker made malformed.
        if basename == "package.json":
            return ""
        return _METADATA_LINE_RE.sub("", _COMMENT_LINE_RE.sub("", source))


# --- reading untrusted files ------------------------------------------------

def _safe_path(root, rel):
    """Absolute path of a regular file inside the clone, or None. Refuses a
    symlink anywhere along the path, which realpath() would quietly resolve."""
    root = os.path.realpath(root)
    full = os.path.normpath(os.path.join(root, rel.lstrip("/\\")))
    if not full.startswith(root + os.sep) or os.path.realpath(full) != full:
        return None
    try:
        return full if stat.S_ISREG(os.lstat(full).st_mode) else None
    except OSError:
        return None


def _read_text(full):
    """File contents as text, or None for binaries and anything over the limit."""
    if os.path.getsize(full) > MAX_TEXT_BYTES:
        return None
    with open(full, "rb") as handle:
        raw = handle.read(MAX_TEXT_BYTES + 1)
    if len(raw) > MAX_TEXT_BYTES or b"\0" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")


def hash_file(full, deadline=None):
    """SHA-256 of a file, or None if the deadline passed while reading it."""
    digest = hashlib.sha256()
    with open(full, "rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK), b""):
            if deadline is not None and time.monotonic() > deadline:
                return None
            digest.update(chunk)
    return digest.hexdigest()


class IocCollector:
    """One row per (type, value), remembering every file it was seen in."""

    def __init__(self, limit=MAX_IOCS):
        self.limit = limit
        self.truncated = False
        self._files = {}

    def add(self, ioc_type, value, rel):
        if len(value) > MAX_VALUE_CHARS:
            return
        key = (ioc_type, value)
        if key not in self._files and len(self._files) >= self.limit:
            self.truncated = True
            return
        self._files.setdefault(key, set()).add(rel)

    def rows(self):
        order = {name: i for i, name in enumerate(IOC_TYPES)}
        rows = []
        for (ioc_type, value), files in self._files.items():
            paths = sorted(files)
            rows.append({"ioc_type": ioc_type, "value": value, "file_path": paths[0],
                         "file_count": len(paths), "ti_match": None, "ti_source": None})
        return sorted(rows, key=lambda r: (order.get(r["ioc_type"], 99), r["value"]))


def flagged_paths(findings):
    """Distinct files ClamAV or YARA flagged. YARA's "scan incomplete" marker
    has no filename, so it never reaches here."""
    return sorted({f["filename"] for f in findings
                   if f.get("tool") in ("clamav", "yara") and f.get("filename")})


def find_install_scripts(root, deadline=None):
    scripts = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if deadline is not None and time.monotonic() > deadline:
            break
        for name in files:
            if name in INSTALL_SCRIPTS:
                rel = os.path.relpath(os.path.join(current, name), root)
                scripts.append("/" + rel.replace(os.sep, "/"))
    return sorted(scripts)


def extract_iocs(repo_path, findings, is_ignored=None, time_limit=None):
    """Everything this scan can say about the repository's indicators.

    `findings` should already have been through filter_noise(); is_ignored is
    scanner.is_ignored_path, applied again so install scripts under tests/ or
    examples/ follow the same rule as findings do.

    Returns {iocs, status, note, files_scanned, files_hashed, ti_status}.
    status is 'done', or 'partial' if the time limit or the row cap cut it
    short: what was found is kept, and the page says it is incomplete.
    """
    if time_limit is None:
        time_limit = int(os.environ.get("MALDET_IOC_TIMEOUT", DEFAULT_TIME_LIMIT))
    deadline = time.monotonic() + time_limit
    ignored = is_ignored or (lambda _path: False)
    collector = IocCollector()
    timed_out = False
    hashed = scanned = 0

    flagged = [p for p in flagged_paths(findings) if not ignored(p)]
    flagged_set = set(flagged)

    # Hashes first: every flagged file should get one, and they are the
    # indicators most worth having if the limit cuts the rest short.
    for rel in flagged:
        if time.monotonic() > deadline:
            timed_out = True
            break
        full = _safe_path(repo_path, rel)
        if not full:
            continue
        try:
            digest = hash_file(full, deadline)
        except OSError:
            continue
        if digest is None:
            timed_out = True
            break
        collector.add("sha256", digest, rel)
        hashed += 1

    scripts = [p for p in find_install_scripts(repo_path, deadline)
               if p not in flagged_set and not ignored(p)]
    for rel in flagged + scripts:
        if timed_out or time.monotonic() > deadline:
            timed_out = True
            break
        full = _safe_path(repo_path, rel)
        if not full:
            continue
        try:
            text = _read_text(full)
        except OSError:
            continue
        if text is None:
            continue
        # A flagged file is searched whole, since an engine objected to it.
        # An unflagged install script only in the parts that actually run.
        if rel not in flagged_set:
            text = install_script_text(rel.rsplit("/", 1)[-1], text)
        scanned += 1
        for ioc_type, value in extract_from_text(text):
            collector.add(ioc_type, value, rel)

    notes = []
    if timed_out:
        notes.append(f"stopped at the {time_limit}s time limit")
    if collector.truncated:
        notes.append(f"stopped at {MAX_IOCS} indicators")
    return {
        "iocs":          collector.rows(),
        "status":        "partial" if notes else "done",
        "note":          "; ".join(notes) or None,
        "files_scanned": scanned,
        "files_hashed":  hashed,
        "ti_status":     "off",
    }


# --- optional threat intelligence (abuse.ch) --------------------------------

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
TI_REQUEST_TIMEOUT = 5
TI_TIME_BUDGET = 30
TI_MAX_LOOKUPS = 50       # per IOC type; the budget is the real ceiling
SOURCE_MALWAREBAZAAR = "MalwareBazaar"
SOURCE_URLHAUS = "URLhaus"
THREAT_INTEL_TOOL = "threat_intel"


class _TiRejected(Exception):
    """The API refused the key, so every further lookup would fail too."""


class _TiRateLimited(Exception):
    """abuse.ch said to slow down. Its Fair Use Policy limits heavy accounts for
    up to 72 hours and restricts repeat offenders for longer, so carrying on with
    the rest of this scan's lookups is exactly the wrong response."""


def _ti_post(url, data, key, deadline):
    """Parsed JSON, or None if this one lookup failed. Never logs the exception
    text or the request: the key is in the headers and stays out of the output."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        response = requests.post(url, data=data, headers={"Auth-Key": key},
                                 timeout=min(TI_REQUEST_TIMEOUT, remaining))
    except requests.RequestException:
        return None
    if response.status_code in (401, 403):
        raise _TiRejected()
    if response.status_code == 429:
        raise _TiRateLimited()
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _bazaar_lookup(sha256, key, deadline):
    """(answered, match)."""
    body = _ti_post(MALWAREBAZAAR_API, {"query": "get_info", "hash": sha256}, key, deadline)
    if body is None:
        return False, None
    status = body.get("query_status")
    if status == "ok":
        samples = body.get("data")
        signature = samples[0].get("signature") if isinstance(samples, list) and samples \
            and isinstance(samples[0], dict) else None
        return True, str(signature or "known malware sample")[:255]
    return status in ("hash_not_found", "no_results"), None


def _urlhaus_lookup(url, key, deadline):
    """(answered, match)."""
    body = _ti_post(URLHAUS_API, {"url": url}, key, deadline)
    if body is None:
        return False, None
    status = body.get("query_status")
    if status == "ok":
        threat = body.get("threat") or "malware URL"
        state = body.get("url_status")
        return True, str(f"{threat} ({state})" if state else threat)[:255]
    return status in ("no_results", "invalid_url"), None


def enrich_with_threat_intel(iocs, key=None, time_budget=TI_TIME_BUDGET):
    """Fills ti_match/ti_source in place. Returns 'off' without a key, 'done'
    if everything got an answer, 'partial' if some did not, 'failed' if none
    could be checked. Only hashes and already-public URLs leave the machine."""
    key = key if key is not None else os.environ.get("ABUSECH_AUTH_KEY", "")
    key = (key or "").strip()
    if not key:
        return "off"

    plan = ([(i, SOURCE_MALWAREBAZAAR, _bazaar_lookup)
             for i in iocs if i["ioc_type"] == "sha256"][:TI_MAX_LOOKUPS]
            + [(i, SOURCE_URLHAUS, _urlhaus_lookup)
               for i in iocs if i["ioc_type"] == "url"][:TI_MAX_LOOKUPS])
    wanted = sum(i["ioc_type"] in ("sha256", "url") for i in iocs)
    if not wanted:
        return "done"

    deadline = time.monotonic() + time_budget
    answered = 0
    try:
        for ioc, source, lookup in plan:
            ok, match = lookup(ioc["value"], key, deadline)
            answered += ok
            if match:
                ioc["ti_match"], ioc["ti_source"] = match, source
    except _TiRejected:
        print("    Threat intel: abuse.ch rejected ABUSECH_AUTH_KEY, skipping lookups")
    except _TiRateLimited:
        print("    Threat intel: abuse.ch rate limit reached, skipping the remaining lookups")
    if answered == wanted:
        return "done"
    return "partial" if answered else "failed"


def threat_intel_findings(iocs):
    """A finding per match, so a known-bad indicator appears in the findings log
    and counts towards the malware verdict. The issue text starts with the
    source because scanner._score_findings() weights by it, and recomputing a
    score has only what scan_results stored to go on."""
    findings = []
    for ioc in iocs:
        if not ioc.get("ti_match"):
            continue
        what = "this file's SHA-256" if ioc["ioc_type"] == "sha256" else "a URL in this file"
        findings.append({
            "tool":         THREAT_INTEL_TOOL,
            "severity":     "high",
            "issue_text":   f"{ioc['ti_source']}: {what} is listed as malicious "
                            f"({ioc['ti_match']}): {ioc['value']}",
            "filename":     ioc["file_path"],
            "line_number":  0,
            "code_snippet": "",
        })
    return findings

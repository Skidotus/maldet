"""Finds code hidden behind encoding layers, so the malware engines can read it.

Malicious packages rarely show their payload in plain text. The usual shape is
`exec(zlib.decompress(base64.b64decode("eJyLz...")))`: YARA and ClamAV see a
long string of letters and nothing they recognise. This module peels those
layers -- base64 (also reversed, also URL-safe), hex, `\\x41` escapes, lists of
character codes, then zlib / gzip / bz2 / xz -- up to MAX_DEPTH deep, and
writes every layer that looks like code (or like an executable) to a scratch
directory. scanner.run_decoded_payloads() then runs YARA and ClamAV over that
directory and reports matches against the original file and line.

Idea from FlatScan's "recursive static payload resolution"
(https://github.com/Masriyan/FlatScan), applied to source repositories.

Everything here is data transformation: nothing decoded is executed, imported
or unpickled. Files are read under the same rules as ioc_extractor (regular
files only, no symlinks, nothing outside the clone, nothing over 2MB), and
every decompression is capped, so a few bytes that inflate to gigabytes cannot
exhaust the 4GB host.

No database code and no import of scanner.py, so it can be tested on its own.
"""

import base64
import binascii
import bz2
import lzma
import os
import re
import time
import zlib

from ioc_extractor import SKIP_DIRS, _read_text, _safe_path

MAX_DEPTH = 3                  # layers peeled per string
MAX_PAYLOADS = 500             # per scan, written for the engines to read
MAX_CANDIDATES_PER_FILE = 2000
MAX_DECODED_BYTES = 1024 * 1024
MIN_PAYLOAD_CHARS = 16
PREVIEW_CHARS = 400
DEFAULT_TIME_LIMIT = int(os.environ.get("MALDET_DECODE_TIME_LIMIT", "60"))

# Same length floor as ioc_extractor: shorter runs are mostly identifiers.
# Padding is allowed at the front too, which is where a reversed string has it.
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])={0,2}[A-Za-z0-9+/_-]{41,}={0,2}")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){40,}(?![0-9A-Fa-f])")
ESCAPED_HEX_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){20,}")
CHAR_CODES_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\s*,\s*){19,}\d{1,3}(?![\d.])")

# Never hold base64 a source repo would want decoded: images, fonts, media.
SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".ogg",
    ".pdf", ".zip", ".gz", ".tgz", ".7z", ".rar", ".jar", ".whl", ".pyc",
    ".lock",   # integrity hashes are base64 by the thousand, and decode to bytes
})

# Byte signatures of things worth handing to ClamAV even when not readable text.
BINARY_MAGIC = (
    (b"MZ", "Windows executable"),
    (b"\x7fELF", "Linux executable"),
    (b"PK\x03\x04", "zip archive"),
    (b"\xcf\xfa\xed\xfe", "macOS executable"),
    (b"\xca\xfe\xba\xbe", "Java class / macOS executable"),
    (b"\xe3\x00\x00\x00", "Python bytecode (marshal)"),
)

# Lowercase fragments that mark text as code rather than prose or noise. A
# decoded layer needs at least one to be kept, which is what stops every long
# identifier and test vector in a framework becoming a "payload".
CODE_MARKERS = (
    "import ", "exec(", "eval(", "require(", "function", "subprocess", "os.system",
    "popen", "socket", "http://", "https://", "powershell", "cmd.exe", "/bin/sh",
    "/bin/bash", "b64decode", "decompress", "compile(", "__import__", "child_process",
    "document.", "window.", "new-object", "invoke-", "iex ", "wget ", "curl ",
    "chmod ", "from ", "def ", "var ", "let ", "const ", "return ", "getattr(",
    "urllib", "requests.", "fetch(", "xmlhttprequest", "registry", "crontab",
)
COMPRESSION = (
    ("zlib", lambda b: b[:1] == b"\x78" and b[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda")),
    ("gzip", lambda b: b[:2] == b"\x1f\x8b"),
    ("bz2", lambda b: b[:3] == b"BZh"),
    ("xz", lambda b: b[:6] == b"\xfd7zXZ\x00"),
)


def code_score(text):
    low = text.lower()
    return sum(1 for marker in CODE_MARKERS if marker in low)


def _printable_ratio(text):
    if not text:
        return 0.0
    return sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text)


def _as_text(raw):
    """Readable text, or None."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) >= MIN_PAYLOAD_CHARS and _printable_ratio(text) >= 0.9:
        return text
    return None


def _magic(raw):
    for prefix, label in BINARY_MAGIC:
        if raw.startswith(prefix):
            return label
    return None


def _inflate(raw):
    """(name, bytes) if `raw` is a compressed stream, never more than the cap."""
    for name, matches in COMPRESSION:
        if not matches(raw):
            continue
        try:
            if name == "zlib":
                d = zlib.decompressobj()
            elif name == "gzip":
                d = zlib.decompressobj(wbits=31)
            elif name == "bz2":
                d = bz2.BZ2Decompressor()
            else:
                d = lzma.LZMADecompressor()
            if name in ("zlib", "gzip"):
                out = d.decompress(raw, MAX_DECODED_BYTES)
            else:
                out = d.decompress(raw, max_length=MAX_DECODED_BYTES)
            return (name, out) if out else None
        except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
            return None
    return None


def _b64(body):
    body = body.rstrip("=")
    if len(body) % 4 == 1:
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        if "-" in body or "_" in body:
            if "+" in body or "/" in body:
                return None
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _candidates(text):
    """(start offset, method, bytes) for every encoded run in `text`."""
    count = 0
    for match in B64_RE.finditer(text):
        run = match.group().strip("=")
        raw = _b64(run)
        if raw:
            yield match.start(), "base64", raw
        # `b64decode(s[::-1])`: the run only decodes, or only makes sense, reversed
        rev = _b64(run[::-1])
        if rev:
            yield match.start(), "reversed base64", rev
        count += 1
        if count >= MAX_CANDIDATES_PER_FILE:
            return
    for match in HEX_RE.finditer(text):
        yield match.start(), "hex", bytes.fromhex(match.group())
    for match in ESCAPED_HEX_RE.finditer(text):
        yield match.start(), "\\x escapes", bytes.fromhex(match.group().replace("\\x", ""))
    for match in CHAR_CODES_RE.finditer(text):
        values = [int(v) for v in re.findall(r"\d+", match.group())]
        if all(v < 256 for v in values):
            yield match.start(), "character codes", bytes(values)


def peel(raw, chain, depth=1):
    """Every layer worth scanning under one decoded byte string, as
    (chain, bytes, kind) where kind is "text" or a binary label."""
    found = []
    inflated = _inflate(raw)
    if inflated:
        name, raw = inflated
        chain = chain + [name]
    text = _as_text(raw)
    if text is not None:
        # A reversed payload is still printable, so readability cannot tell the
        # two apart; code markers can.
        if code_score(text[::-1]) > code_score(text):
            text, chain = text[::-1], chain + ["reversed"]
        if code_score(text):
            found.append((chain, text.encode("utf-8"), "text"))
        if depth < MAX_DEPTH:
            for _, method, inner in _candidates(text):
                found.extend(peel(inner, chain + [method], depth + 1))
        return found
    label = _magic(raw)
    if label:
        found.append((chain, raw, label))
    return found


def _line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def _preview(raw, kind):
    if kind != "text":
        return f"[{kind}, {len(raw):,} bytes]"
    text = raw.decode("utf-8", errors="replace")
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + " ...[truncated]"


def decode_file(text):
    """Every hidden layer in one file's text, as dicts with line, chain, kind,
    data. The same payload reached by two routes is kept once."""
    seen = set()
    layers = []
    for offset, method, raw in _candidates(text):
        for chain, data, kind in peel(raw, [method]):
            if data in seen:
                continue
            seen.add(data)
            layers.append({"line": _line_of(text, offset), "chain": chain,
                           "kind": kind, "data": data})
    return layers


def iter_text_files(root, is_ignored=None):
    """Relative paths ("/a/b.py") of files worth decoding, in a stable order."""
    ignored = is_ignored or (lambda _path: False)
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if os.path.splitext(name)[1].lower() in SKIP_EXTENSIONS:
                continue
            rel = "/" + os.path.relpath(os.path.join(current, name), root).replace(os.sep, "/")
            if not ignored(rel):
                yield rel


def extract_payloads(repo_path, out_dir, is_ignored=None, time_limit=None):
    """Writes each hidden layer in the repo to out_dir and returns
    {"payloads": {written name: info}, "files_read", "status", "note"}.

    info carries the original file, line, decoding chain, kind and a preview,
    which is what a match on the written file gets reported as. status is
    "complete" or "partial" (time limit or payload cap reached), so a scan that
    stopped early can say so rather than look like it found nothing more."""
    deadline = time.monotonic() + (time_limit or DEFAULT_TIME_LIMIT)
    payloads, files_read, note = {}, 0, ""
    for rel in iter_text_files(repo_path, is_ignored):
        if time.monotonic() > deadline:
            note = "time limit reached"
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
        files_read += 1
        for layer in decode_file(text):
            if len(payloads) >= MAX_PAYLOADS:
                note = f"stopped at {MAX_PAYLOADS} payloads"
                break
            name = f"payload_{len(payloads):04d}.bin"
            with open(os.path.join(out_dir, name), "wb") as handle:
                handle.write(layer["data"])
            payloads[name] = {
                "filename": rel,
                "line":     layer["line"],
                "chain":    " → ".join(layer["chain"]),
                "kind":     layer["kind"],
                "preview":  _preview(layer["data"], layer["kind"]),
            }
        if note:
            break
    return {"payloads": payloads, "files_read": files_read,
            "status": "partial" if note else "complete", "note": note}

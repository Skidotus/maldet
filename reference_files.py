"""Recognises files that DESCRIBE threats rather than carry them.

MalDet looks for suspicious text, and some honest files are full of it because
they are lists: a YARA or Sigma rule file has to contain the patterns it looks
for, a ClamAV signature database is nothing but malware fingerprints, and a DNS
blocklist names mining pools and malware domains in order to block them. Before
this, MalDet rated its own repository High (rules.yar matched 7 of its own
rules) and AdguardTeam/HostlistsRegistry Critical (its filter lists name mining
pools). It is like flagging a "wanted" poster as a criminal.

FlatScan (https://github.com/Masriyan/FlatScan) spots such files by breadth:
one file matching many unrelated kinds of malware is a catalogue, not a sample.
That does not carry over to MalDet. Measured over the local corpus, rules.yar
matches 7 MalDet rules, but nishang's Powerpreter.psm1, a real attack toolkit,
matches 5, and so does the deliberately malicious maldet-demo-package
install.sh: any breadth cut-off low enough for the first hides the other two.

So the test here is what KIND of file it is, and it needs two things at once:
a data-file extension (something no interpreter runs by itself, so the file
cannot carry out an attack on its own) AND content in a recognised rule or list
format. A Python file that happens to contain YARA rules as a string is never a
reference file, because Python runs.

Matches in a reference file are kept on the report, marked and set to low, but
scanner.py gives them no weight in the score and the IOC extractor skips them.

No database code and no import of scanner.py, so it can be tested on its own.
"""

import os
import re

from ioc_extractor import _safe_path, _utf16_encoding

PREFIX_BYTES = 256 * 1024       # enough to recognise a format; blocklists run to tens of MB
MIN_LIST_ENTRIES = 20
LIST_ENTRY_SHARE = 0.9
MAX_LIST_LINES = 5000

# ClamAV's own database formats: the file is signatures by definition.
# Deliberately not .pdb (Windows debug symbols), .idb (IDA databases) or .info.
CLAMAV_DB_EXTENSIONS = frozenset({
    ".ndb", ".hdb", ".hsb", ".ldb", ".cdb", ".fp", ".sfp", ".ign2", ".ftm",
    ".mdb", ".msb", ".ndu", ".ldu", ".wdb", ".cbc", ".cvd", ".cld", ".cud",
    ".hdu", ".hsu", ".mdu", ".msu",
})
YARA_EXTENSIONS = frozenset({".yar", ".yara", ".rule", ".rules", ".txt"})
SIGMA_EXTENSIONS = frozenset({".yml", ".yaml"})
SNORT_EXTENSIONS = frozenset({".rules", ".rule", ".txt"})
LIST_EXTENSIONS = frozenset({".txt", ".list", ".hosts", ".conf", ".csv", ".lst", ""})

# The brace may sit on the next line (YARA Forge writes it that way).
YARA_RULE_RE = re.compile(r"^[ \t]*(?:(?:private|global)\s+)*rule\s+\w+[^{;\n]{0,200}\s*\{", re.MULTILINE)
SIGMA_RE = (re.compile(r"^logsource:", re.MULTILINE), re.compile(r"^detection:", re.MULTILINE))
SNORT_RE = re.compile(r"^\s*(?:alert|drop|reject|pass)\s+(?:tcp|udp|ip|icmp|http|dns|tls|smtp|ftp|ssh)\s",
                      re.MULTILINE)

LIST_COMMENT_PREFIXES = ("#", "!", "//", ";", "[")
LIST_ENTRY_RE = re.compile(
    r"^(?:"
    r"(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+\S+(?:\s+#.*)?"            # hosts file
    r"|\*?\.?[a-z0-9_-]+(?:\.[a-z0-9_*-]+)+\.?"                     # bare domain
    r"|\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"                        # IPv4 / CIDR
    r"|https?://\S+"                                                # URL
    r"|(?:@@)?\|\|?\S+"                                             # adblock network rule
    r"|\S*#[@$%?]?#\S.*"                                            # adblock element-hiding rule
    r"|/\S+/(?:\$\S+)?"                                             # adblock regex rule
    r"|(?:address|server|local)=/\S+"                               # dnsmasq
    r")$",
    re.IGNORECASE,
)


def _read_prefix(full):
    with open(full, "rb") as handle:
        raw = handle.read(PREFIX_BYTES)
    encoding = _utf16_encoding(raw)
    if encoding:
        return raw.decode(encoding, errors="replace")
    if b"\0" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")


def _is_list(text):
    entries = matched = 0
    for line in text.splitlines()[:MAX_LIST_LINES]:
        line = line.strip()
        if not line or line.startswith(LIST_COMMENT_PREFIXES):
            continue
        entries += 1
        matched += bool(LIST_ENTRY_RE.match(line))
    return entries >= MIN_LIST_ENTRIES and matched / entries >= LIST_ENTRY_SHARE


def reference_kind(rel, text):
    """"rule file", "signature database" or "blocklist" if the file at
    relative path `rel`, whose text (or text prefix) is `text`, describes
    threats rather than carrying them; otherwise None."""
    name = os.path.basename(rel).lower()
    ext = os.path.splitext(name)[1]
    if ext in CLAMAV_DB_EXTENSIONS:
        return "signature database"
    if text is None:
        return None
    if ext in YARA_EXTENSIONS and YARA_RULE_RE.search(text) and "condition:" in text:
        return "rule file"
    if ext in SIGMA_EXTENSIONS and all(r.search(text) for r in SIGMA_RE):
        return "rule file"
    if ext in SNORT_EXTENSIONS and len(SNORT_RE.findall(text)) >= 3:
        return "rule file"
    if ext in LIST_EXTENSIONS and _is_list(text):
        return "blocklist"
    return None


def classify_files(repo_path, rels):
    """{relative path: kind} for the given files that are reference files.
    Unreadable files, symlinks and anything outside the clone are skipped."""
    kinds = {}
    for rel in sorted(set(rels)):
        full = _safe_path(repo_path, rel)
        if not full:
            continue
        try:
            kind = reference_kind(rel, _read_prefix(full))
        except OSError:
            continue
        if kind:
            kinds[rel] = kind
    return kinds


# Only plain-sight pattern matches are reinterpreted. A hidden payload decoded
# out of a list is not something a list contains honestly, and a threat-intel
# hash match means the file itself is known malware, whatever its format.
GUARDED_TOOLS = ("yara", "clamav")
HIDDEN_PREFIX = "Hidden payload: "


def mark_references(repo_path, findings):
    """Marks findings that sit in reference files: f["reference"] = kind,
    severity low, and issue_text prefixed so the report says why. Returns the
    number marked. Findings are changed in place."""
    candidates = [f for f in findings
                  if f.get("tool") in GUARDED_TOOLS and f.get("filename")
                  and not (f.get("issue_text") or "").startswith(HIDDEN_PREFIX)]
    kinds = classify_files(repo_path, [f["filename"] for f in candidates])
    for f in candidates:
        kind = kinds.get(f["filename"])
        if kind:
            f["reference"] = kind
            f["severity"] = "low"
            f["issue_text"] = f"Reference in a {kind}, not code that runs: {f['issue_text']}"
    return sum(1 for f in candidates if f.get("reference"))

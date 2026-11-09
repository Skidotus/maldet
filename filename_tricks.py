"""Finds file names built to look like something else.

A payload named to pass for a harmless file is a deliberate act: the
deception is in the name, so a scanner that only reads contents treats the
file as ordinary. Four tricks, each chosen because honest projects almost
never contain it (idea from FlatScan's masquerade.go,
https://github.com/Masriyan/FlatScan):

  bidi       Invisible text-direction characters. "annexe<U+202E>cod.exe" is
             displayed as "annexe.exe.doc". High.
  double     A document or media extension followed by a Windows program
             extension, often with padding so the real one scrolls out of
             view: "invoice.pdf.exe", "photo.jpg      .scr". High. .js is not
             counted: bundlers legitimately emit names like "logo.png.js".
  mixed      One word mixing Latin letters with Cyrillic or Greek ones that
             look identical: a Cyrillic "а" inside "pаypal". Medium.
  homoglyph  An exact look-alike spelling of a commonly impersonated word:
             "lnstaller" (lower-case L for capital I), "5etup", "Micros0ft".
             Only a fixed vocabulary is checked, so "resembles a word" never
             fires; the word spelled correctly never does either. Medium.

Names are only ever read from the directory listing, never opened or run.
A name with a direction character would also display misleadingly on
MalDet's own report, so findings show those characters as visible markers.

No database code and no import of scanner.py, so it can be tested on its own.
"""

import os
import re
import unicodedata

from ioc_extractor import SKIP_DIRS

TOOL = "filename"

BIDI_CHARS = set("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")

DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|rtf|odt|ods|txt|csv|jpe?g|png|gif|bmp|mp3|mp4|mov|avi|zip|rar|7z)"
    r"[\s_.]*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|jse|wsf|wsh|hta|lnk|msi|ps1|cpl)$",
    re.IGNORECASE)

# Names attackers imitate. Kept short on purpose: each entry is a chance to be
# wrong about an honest file name, and these are the ones lures actually use.
IMPERSONATED = (
    "installer", "install", "setup", "update", "updater", "microsoft", "windows",
    "google", "chrome", "firefox", "adobe", "paypal", "apple", "amazon", "outlook",
    "office", "invoice", "payment", "password", "github", "python", "nodejs",
)

# Characters that read as another at a glance. Lower-case l and i both map to
# "l" because "lnstaller" passes for "Installer" (a capital I).
_LOOKALIKE = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "i": "l",
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "l", "ѕ": "s", "ј": "j", "ԁ": "d", "ӏ": "l", "к": "k", "м": "m", "т": "t",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ν": "v", "ρ": "p", "τ": "t", "ι": "l", "κ": "k",
})


def _skeleton(word):
    s = word.lower().translate(_LOOKALIKE)
    return s.replace("rn", "m").replace("vv", "w")


_IMPERSONATED_SKELETONS = {_skeleton(w): w for w in IMPERSONATED}


def visible(name):
    """The name with direction characters shown as <U+202E> markers."""
    return "".join(f"<U+{ord(c):04X}>" if c in BIDI_CHARS else c for c in name)


def _scripts(word):
    found = set()
    for c in word:
        if c.isalpha():
            n = unicodedata.name(c, "")
            for script in ("LATIN", "CYRILLIC", "GREEK"):
                if n.startswith(script):
                    found.add(script)
    return found


def tricks_in(name):
    """[(kind, severity, explanation)] for one file name (not a path)."""
    hits = []
    if any(c in BIDI_CHARS for c in name):
        hits.append(("bidi", "high",
                     "contains invisible text-direction characters, so it displays as a "
                     "different name from the one it has"))
    plain = "".join(c for c in name if c not in BIDI_CHARS)
    m = DOUBLE_EXT_RE.search(plain)
    if m:
        hits.append(("double", "high",
                     f"looks like a .{m.group(1).lower()} file but is a .{m.group(2).lower()} "
                     "program (a document extension placed before the real one)"))
    stem = os.path.splitext(plain)[0]
    for word in re.findall(r"[^\W_]{3,}", stem):
        scripts = _scripts(word)
        if "LATIN" in scripts and len(scripts) > 1:
            hits.append(("mixed", "medium",
                         f"the word '{word}' mixes Latin letters with look-alike Cyrillic or "
                         "Greek ones"))
            break
    for word in re.findall(r"[^\W_]{4,}", stem):
        target = _IMPERSONATED_SKELETONS.get(_skeleton(word))
        if target and word.lower() != target:
            hits.append(("homoglyph", "medium",
                         f"'{word}' is a look-alike spelling of '{target}'"))
            break
    return hits


def find_disguised_names(root, is_ignored=None):
    """Findings in MalDet's standard shape for every disguised file name."""
    ignored = is_ignored or (lambda _path: False)
    findings = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = "/" + os.path.relpath(os.path.join(current, name), root).replace(os.sep, "/")
            if ignored(rel):
                continue
            for kind, severity, why in tricks_in(name):
                findings.append({
                    "tool":         TOOL,
                    "severity":     severity,
                    # Stable per kind, not per file: the classifier and the
                    # summary group findings by this text.
                    "issue_text":   {"bidi": "Disguised file name: hidden text-direction characters",
                                     "double": "Disguised file name: document extension before a program extension",
                                     "mixed": "Disguised file name: look-alike letters from another alphabet",
                                     "homoglyph": "Disguised file name: look-alike spelling of a trusted name",
                                     }[kind],
                    "filename":     visible(rel),
                    "line_number":  0,
                    "code_snippet": f"{visible(name)}: {why}",
                })
    return findings

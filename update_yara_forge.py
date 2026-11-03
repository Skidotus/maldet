"""
Downloads the latest YARA Forge "core" rule package into rules/forge/.

YARA Forge (https://github.com/YARAHQ/yara-forge) publishes a curated bundle
of public YARA rules every few weeks. MalDet ships one release committed to
the repository, so a scan is reproducible and the Docker build needs no
network; run this to move to a newer release, re-run the measurement in
rules/forge/README.md if you want numbers for it, then commit.

The replacement is only written after the new file compiles with the local
`yara`, so a broken release cannot leave the scanner with no Forge rules.
Only the one expected member is read from the zip, and it is written to a
fixed path, so nothing inside the archive chooses where files land.

    python3 update_yara_forge.py            # latest release
    python3 update_yara_forge.py 20261101   # a specific release tag
"""

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile

import requests

REPO = "YARAHQ/yara-forge"
ASSET = "yara-forge-rules-core.zip"
MEMBER = "packages/core/yara-rules-core.yar"
HERE = os.path.dirname(os.path.abspath(__file__))
DEST_DIR = os.path.join(HERE, "rules", "forge")
DEST = os.path.join(DEST_DIR, "yara-rules-core.yar")
VERSION_FILE = os.path.join(DEST_DIR, "VERSION")


def release(tag=None):
    url = (f"https://api.github.com/repos/{REPO}/releases/tags/{tag}" if tag
           else f"https://api.github.com/repos/{REPO}/releases/latest")
    resp = requests.get(url, timeout=30, headers={"Accept": "application/vnd.github+json"})
    resp.raise_for_status()
    return resp.json()


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else None
    rel = release(tag)
    asset = next((a for a in rel.get("assets", []) if a["name"] == ASSET), None)
    if asset is None:
        sys.exit(f"Release {rel.get('tag_name')} has no {ASSET}")

    print(f"Downloading {ASSET} from release {rel['tag_name']} ({asset['size']:,} bytes)...")
    data = requests.get(asset["browser_download_url"], timeout=120)
    data.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(data.content)) as zf:
        if MEMBER not in zf.namelist():
            sys.exit(f"{MEMBER} not found in the zip: {zf.namelist()[:10]}")
        rules = zf.read(MEMBER)

    os.makedirs(DEST_DIR, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=DEST_DIR, suffix=".yar", delete=False) as tmp:
        tmp.write(rules)
        candidate = tmp.name
    try:
        with tempfile.TemporaryDirectory() as td:
            check = subprocess.run(["yarac", "-w", candidate, os.path.join(td, "out.yarc")],
                                   capture_output=True, text=True)
        if check.returncode != 0:
            sys.exit(f"New rules do not compile with the local yara, keeping the old ones:\n"
                     f"{check.stderr[:1000]}")
        # NamedTemporaryFile creates 0600; the scanner may run as another user.
        os.chmod(candidate, 0o644)
        os.replace(candidate, DEST)
    finally:
        if os.path.exists(candidate):
            os.remove(candidate)

    text = rules.decode("utf-8", errors="replace")
    count = len(re.findall(r"^rule\s", text, re.M))
    version = {"release": rel["tag_name"], "published_at": rel.get("published_at"),
               "package": "core", "rules": count}
    with open(VERSION_FILE, "w") as fh:
        json.dump(version, fh, indent=2)
        fh.write("\n")
    print(f"Installed {count:,} rules from {rel['tag_name']} into {DEST}")


if __name__ == "__main__":
    main()

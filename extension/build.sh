#!/usr/bin/env bash
#
# Assembles dist/chrome and dist/firefox from one set of sources.
#
# The two browsers differ in exactly two places -- how the background script
# is declared, and Firefox needing an add-on id -- so the logic is shared and
# only the manifest is swapped. Copying rather than symlinking because both
# browsers load an unpacked directory and follow symlinks inconsistently.

set -euo pipefail
cd "$(dirname "$0")"

rm -rf dist

for target in chrome firefox; do
  out="dist/$target"
  mkdir -p "$out/icons"
  cp src/*.js src/*.css src/*.html "$out/"
  cp icons/*.png "$out/icons/"
  cp "manifest.$target.json" "$out/manifest.json"

  # Every file the manifest names must actually be there. A missing one
  # fails at load time with a message that does not say which file, so it
  # is worth catching here instead.
  python3 - "$out" <<'PY'
import json, os, sys
root = sys.argv[1]
m = json.load(open(os.path.join(root, "manifest.json")))
refs = []
for cs in m.get("content_scripts", []):
    refs += cs.get("js", []) + cs.get("css", [])
bg = m.get("background", {})
refs += bg.get("scripts", []) or ([bg["service_worker"]] if "service_worker" in bg else [])
refs += list(m.get("icons", {}).values())
refs += list(m.get("action", {}).get("default_icon", {}).values())
if "options_ui" in m:
    refs.append(m["options_ui"]["page"])
missing = [r for r in refs if not os.path.exists(os.path.join(root, r))]
if missing:
    sys.exit(f"  MISSING in {root}: {missing}")
print(f"  {root}: {len(refs)} referenced files all present")
PY
done

# Package the bundles so the website can offer them for download.
python3 package.py

echo
echo "Load it:"
echo "  Chrome/Edge  chrome://extensions  -> Developer mode -> Load unpacked -> extension/dist/chrome"
echo "  Firefox      about:debugging#/runtime/this-firefox -> Load Temporary Add-on -> extension/dist/firefox/manifest.json"

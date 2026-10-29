"""Package the built bundles for download from the website.

Run by build.sh, after dist/ has been assembled.

The zips land in static/ rather than extension/dist/ because static/ is what
ships inside the Docker image -- extension/ is dockerignored, being a
client-side artifact the server never runs.

They are committed, so build.sh has to be run before committing any change
to the extension or the site offers a stale build. extension-info.json
carries the version and build date for exactly that reason: a download that
has gone stale says so on the page rather than looking current.
"""

import hashlib
import json
import os
import zipfile
from datetime import date

OUT = os.path.join("..", "static", "downloads")


def main():
    os.makedirs(OUT, exist_ok=True)
    info = {"built": date.today().isoformat(), "files": {}}

    for target in ("chrome", "firefox"):
        src = os.path.join("dist", target)
        with open(os.path.join(src, "manifest.json")) as fh:
            info["version"] = json.load(fh)["version"]

        name = f"maldet-{target}.zip"
        path = os.path.join(OUT, name)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Sorted, so an unchanged build produces an identical archive
            # and does not show up as a diff for no reason.
            for base, dirs, files in os.walk(src):
                dirs.sort()
                for f in sorted(files):
                    full = os.path.join(base, f)
                    zf.write(full, os.path.relpath(full, src))

        data = open(path, "rb").read()
        info["files"][target] = {
            "name": name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        print(f"  static/downloads/{name}  {len(data) // 1024}KB")

    with open(os.path.join(OUT, "extension-info.json"), "w") as fh:
        json.dump(info, fh, indent=2)
        fh.write("\n")
    print(f"  static/downloads/extension-info.json  v{info['version']}, built {info['built']}")


if __name__ == "__main__":
    main()

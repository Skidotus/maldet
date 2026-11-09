# MalDet — Flask app plus the detection engines it shells out to.
#
# Four tools come from the OS: scanner.py shells out to `yara`, `clamscan`
# and `git`, and extract_archives() shells out to `7z`. Bandit, Semgrep and
# pip-audit are Python packages and arrive via requirements.txt instead, so
# they are not installed here.
#
# The OS also supplies Pango, which WeasyPrint loads at import time to render
# the PDF report.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# ClamAV is NOT installed from Debian: see the next RUN.
# No MySQL client: the entrypoint waits for the database through pymysql,
# which is already a dependency.
#
# 7z is awkward across Debian releases: bookworm ships `p7zip-full`
# (providing /usr/bin/7z), while trixie dropped it for `7zip` (providing
# `7zz` instead). Try the former, fall back to the latter, and symlink so
# the `7z` that extract_archives() shells out to exists either way.
# WeasyPrint 70 dlopens Pango, PangoFT2, HarfBuzz, GObject and fontconfig --
# NOT cairo, which it dropped in v53 for its own PDF writer, so libcairo2 and
# libgdk-pixbuf are not needed here. libpango-1.0-0 and libpangoft2-1.0-0 pull
# the rest of that set in transitively; libharfbuzz-subset0 does not come with
# them and is what lets WeasyPrint subset embedded fonts. fonts-dejavu-core
# also arrives transitively, named here because it is the only font in the
# image: without it the report renders as empty boxes rather than failing.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        yara \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz-subset0 \
        fonts-dejavu-core \
    && (apt-get install -y --no-install-recommends p7zip-full \
        || (apt-get install -y --no-install-recommends 7zip \
            && ln -sf "$(command -v 7zz)" /usr/local/bin/7z)) \
    && rm -rf /var/lib/apt/lists/*

# ClamAV from Cisco Talos's own release, not Debian. Debian 13 ships 1.4.3 in
# trixie, trixie-updates and trixie-security alike (checked 2026-11-09), and
# 1.4.4-1.4.6 fix memory-safety bugs in exactly the parsers MalDet feeds
# untrusted files to: the 7z and PESpin unpackers (heap overflows), the PDF,
# HTML and GPT parsers. A booby-trapped file in a scanned repo is the threat
# model, so the scanner's own parsers are worth keeping current.
#
# The package is pinned by SHA-256: the digests GitHub publishes for the
# Cisco-Talos/clamav release, re-computed from both downloads on 2026-11-09,
# so a swapped download fails the build. The release's .sig files were NOT
# checked: they name key 707F0DB480836771, and no authoritative copy of it
# was found, only keyservers, which prove nothing on their own. It installs under /usr/local and looks
# for signatures in /usr/local/share/clamav, which is linked to the
# /var/lib/clamav volume the existing signatures live in. Its freshclam.conf
# is written here; NotifyClamd is left out because there is no clamd.
# To upgrade: change CLAMAV_VERSION and both sums.
ARG CLAMAV_VERSION=1.4.6
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
        amd64) arch=x86_64;  sum=d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2 ;; \
        arm64) arch=aarch64; sum=a29cc95aeb225f0dc1b99024b49f1cc109502cb17aaf168637d0901aa9674fe8 ;; \
        *) echo "FATAL: no official ClamAV package for $(dpkg --print-architecture)"; exit 1 ;; \
    esac; \
    url="https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/clamav-${CLAMAV_VERSION}.linux.${arch}.deb"; \
    python3 -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/tmp/clamav.deb')" "$url"; \
    echo "$sum  /tmp/clamav.deb" | sha256sum -c -; \
    dpkg -i /tmp/clamav.deb; \
    rm /tmp/clamav.deb; \
    rm -rf /usr/local/share/clamav; \
    ln -s /var/lib/clamav /usr/local/share/clamav; \
    printf '%s\n' \
        'DatabaseDirectory /var/lib/clamav' \
        'DatabaseMirror database.clamav.net' \
        'UpdateLogFile /var/log/clamav/freshclam.log' \
        > /usr/local/etc/freshclam.conf; \
    clamscan --version | grep -q "ClamAV ${CLAMAV_VERSION}/\|ClamAV ${CLAMAV_VERSION}$" \
        || { echo "FATAL: clamscan is not ${CLAMAV_VERSION}: $(clamscan --version)"; exit 1; }; \
    freshclam --version

# Fail the build now if any shelled-out tool is missing, rather than letting
# the app start and silently return no findings for that engine. scanner.py
# and dep_checker.py catch subprocess errors and carry on by design, so a
# missing binary looks exactly like a clean scan — which is the worst
# possible failure mode for a security scanner.
RUN set -eu; \
    for tool in git yara clamscan 7z; do \
        command -v "$tool" >/dev/null \
            || { echo "FATAL: '$tool' missing after apt install"; exit 1; }; \
    done; \
    echo "all four system tools present"

# Dependencies before source, so editing a .py file doesn't reinstall
# ~100 packages (Semgrep alone is a slow download).
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# Render a PDF now, for the same reason the system tools are checked above:
# app.py's /report/<id>.pdf route catches an unavailable WeasyPrint and
# returns 503 so the rest of the app keeps working, which means a missing
# shared library would only surface when someone tried to download a report.
# Importing is not enough -- the libraries are dlopened lazily, so this
# writes an actual PDF.
RUN python -c "\
import weasyprint; \
pdf = weasyprint.HTML(string='<h1>MalDet</h1><p>build check</p>').write_pdf(); \
assert pdf[:5] == b'%PDF-', pdf[:5]; \
print('weasyprint renders PDFs:', len(pdf), 'bytes')"

# GuardDog gets its own virtualenv rather than a line in requirements.txt:
# it requires click >=8.4.1,<9, and semgrep pinned click ~=8.1.8 until
# 1.182.1, so installing both into one environment broke semgrep. The pins
# now overlap on click 8.4.2, but the isolation stays -- it costs one layer
# and removes a whole class of resolver conflict from a tool whose only job
# is to run other people's packaging code. scanner.py looks for `guarddog`
# on PATH first, which the symlink satisfies. Verified immediately for the
# same reason as the system tools above — run_guarddog() skips silently when
# the binary is absent, so a failed install would look like a clean scan.
RUN python -m venv /opt/guarddog \
    && /opt/guarddog/bin/pip install --no-cache-dir guarddog \
    && ln -sf /opt/guarddog/bin/guarddog /usr/local/bin/guarddog \
    && guarddog --version

COPY . .

# Run as a non-root user — this is a security tool, and it executes scanners
# over untrusted cloned code, so it has no business running as root. The
# clamav dirs are chowned because freshclam writes the signature DB and its
# log there, and /var/lib/clamav is a named volume whose ownership is seeded
# from this image.
RUN useradd --create-home --shell /bin/bash maldet \
    && mkdir -p /var/lib/clamav /var/log/clamav \
    && chown -R maldet:maldet /var/lib/clamav /var/log/clamav /app \
    && chmod +x /app/docker/entrypoint.sh

USER maldet

# Inside a container 0.0.0.0 is correct: the container's network namespace is
# the isolation boundary, and docker-compose publishes the port to 127.0.0.1
# on the host only. See app.py for why this is an env var rather than a
# hardcoded default.
ENV MALDET_HOST=0.0.0.0 \
    MALDET_PORT=5000

EXPOSE 5000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["python3", "app.py"]

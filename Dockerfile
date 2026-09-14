# MalDet — Flask app plus the detection engines it shells out to.
#
# Only four tools need to come from the OS: scanner.py shells out to `yara`,
# `clamscan` and `git`, and extract_archives() shells out to `7z`. Bandit,
# Semgrep and pip-audit are Python packages and arrive via requirements.txt
# instead, so they are not installed here.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# clamav provides clamscan; clamav-freshclam provides the freshclam binary
# that fetches the signature database (the entrypoint runs it by hand — the
# packaged daemon expects an init system that isn't here).
# No MySQL client: the entrypoint waits for the database through pymysql,
# which is already a dependency.
#
# 7z is awkward across Debian releases: bookworm ships `p7zip-full`
# (providing /usr/bin/7z), while trixie dropped it for `7zip` (providing
# `7zz` instead). Try the former, fall back to the latter, and symlink so
# the `7z` that extract_archives() shells out to exists either way.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        yara \
        clamav \
        clamav-freshclam \
    && (apt-get install -y --no-install-recommends p7zip-full \
        || (apt-get install -y --no-install-recommends 7zip \
            && ln -sf "$(command -v 7zz)" /usr/local/bin/7z)) \
    && rm -rf /var/lib/apt/lists/*

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

"""
Where MySQL lives — resolved in one place.

Exists because of the SSH-tunnel case. Reaching a remote database means
forwarding it to a local port, and port 3306 is usually already taken by a
local MySQL, so the tunnel lands on 3307 or similar:

    ssh -L 3307:127.0.0.1:3306 user@vps     # from the laptop
    DB_PORT=3307 python3 backfill_summaries.py

The failure this prevents is a quiet one. Without a configurable port, every
script connects to 3306 and therefore to the *local* database — same table
names, same schema, plausible-looking results, entirely the wrong data. No
error is raised, so it reads as success.

Resolution order, first match wins:

    1. DB_PORT environment variable  (per-invocation, e.g. a tunnel)
    2. DB_PORT in config.py          (if the local setup needs a fixed port)
    3. 3306                          (the MySQL default)

config.py is gitignored and predates this module, so step 2 uses getattr
rather than a direct import: an existing config.py without DB_PORT must keep
working untouched, not raise ImportError on every script at once.
"""

import os

import pymysql

import config

DEFAULT_DB_PORT = 3306


def _resolve_port():
    raw = os.environ.get("DB_PORT")
    if raw is None:
        raw = getattr(config, "DB_PORT", DEFAULT_DB_PORT)
    try:
        return int(raw)
    except (TypeError, ValueError):
        print(f"    DB_PORT={raw!r} is not a port number, using {DEFAULT_DB_PORT}")
        return DEFAULT_DB_PORT


DB_PORT = _resolve_port()


def connect(**overrides):
    """A connection to the configured database.

    Callers that need their own cursorclass or autocommit pass them through;
    everything else is shared so the host/port/credentials are stated once.
    """
    settings = {
        "host":     config.DB_HOST,
        "port":     DB_PORT,
        "user":     config.DB_USER,
        "password": config.DB_PASSWORD,
        "database": config.DB_NAME,
    }
    settings.update(overrides)
    return pymysql.connect(**settings)


def describe():
    """Human-readable target, for scripts that should say where they are
    writing — the whole point of the port is that it changes which database
    you are talking to."""
    return f"{config.DB_USER}@{config.DB_HOST}:{DB_PORT}/{config.DB_NAME}"

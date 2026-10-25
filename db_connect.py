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

Every connection setting resolves the same way, first match wins:

    1. the environment variable  (per-invocation, e.g. a tunnel)
    2. the same name in config.py
    3. the default below

    DB_HOST  DB_PORT  DB_USER  DB_PASSWORD  DB_NAME

The credentials are overridable for the same reason the port is: a tunnel
points at a *different server*, which has its own MySQL users. Deployed
MalDet generates its password at install time, so it is never the one in a
developer's config.py, and without this the tunnel authenticates as the
local user against the remote database and is simply refused.

    DB_PORT=3307 DB_PASSWORD="$(ssh vps 'grep ^DB_PASSWORD /root/maldet/.env | cut -d= -f2-')" \
        python3 backfill_summaries.py

config.py is gitignored and predates this module, so step 2 uses getattr
rather than a direct import: an existing config.py missing any of these must
keep working untouched, not raise ImportError on every script at once.
"""

import os

import pymysql

import config

DEFAULT_DB_PORT = 3306


def _resolve(name, default=None):
    """The environment first, then config.py, then the default.

    An empty environment variable counts as unset. `DB_PASSWORD= cmd` is how
    a shell says "no value", not "the empty password", and treating it as a
    real value turns a typo into an authentication failure that looks like
    wrong credentials.
    """
    value = os.environ.get(name)
    if value:
        return value
    return getattr(config, name, default)


def _resolve_port():
    raw = _resolve("DB_PORT", DEFAULT_DB_PORT)
    try:
        return int(raw)
    except (TypeError, ValueError):
        print(f"    DB_PORT={raw!r} is not a port number, using {DEFAULT_DB_PORT}")
        return DEFAULT_DB_PORT


DB_HOST     = _resolve("DB_HOST")
DB_PORT     = _resolve_port()
DB_USER     = _resolve("DB_USER")
DB_PASSWORD = _resolve("DB_PASSWORD")
DB_NAME     = _resolve("DB_NAME")


def connect(**overrides):
    """A connection to the configured database.

    Callers that need their own cursorclass or autocommit pass them through;
    everything else is shared so the host/port/credentials are stated once.
    """
    settings = {
        "host":     DB_HOST,
        "port":     DB_PORT,
        "user":     DB_USER,
        "password": DB_PASSWORD,
        "database": DB_NAME,
    }
    settings.update(overrides)
    return pymysql.connect(**settings)


def describe():
    """Human-readable target, for scripts that should say where they are
    writing — the whole point of the port is that it changes which database
    you are talking to. No password, so it is safe to print in a log."""
    return f"{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

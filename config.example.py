# Copy this to config.py and fill in your values
# NEVER push config.py to GitHub

GITHUB_TOKEN = "your_github_token_here"
DB_HOST      = "localhost"

# Optional. Leave this out entirely and MySQL's default 3306 is used, which
# is what a local install wants. Set it when the database is reached through
# an SSH tunnel, since 3306 is normally already taken by the local MySQL:
#
#   ssh -L 3307:127.0.0.1:3306 user@your-vps
#   DB_PORT=3307 python3 backfill_summaries.py
#
# The environment variable wins over this value, so a tunnel can be used for
# one command without editing this file. Worth setting deliberately rather
# than guessing: a wrong port silently connects to a *different* database
# with the same table names, which looks like success.
DB_PORT      = 3306
DB_USER      = "fypuser"
DB_PASSWORD  = "your_db_password"
DB_NAME      = "fyp_scanner"

# No LLM key here, by design. The plain-English findings summary is written
# by Ollama running locally (llm_summary.py) — no API key, no account, no
# per-scan cost, and it works offline. Configure it with environment
# variables rather than here, since none of them are secrets:
#
#   MALDET_OLLAMA_HOST     default http://localhost:11434
#   MALDET_OLLAMA_MODEL    default llama3.2:3b
#   MALDET_OLLAMA_TIMEOUT  default 120 (seconds)
#   MALDET_OLLAMA_DISABLE  set to 1 to skip the LLM entirely
#
# If Ollama isn't installed or isn't running, scans still work — app.py falls
# back to the rule-based build_findings_summary(). If that decision ever
# changes to a hosted API instead, add its key back here.

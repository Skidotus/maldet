# Copy this to config.py and fill in your values
# NEVER push config.py to GitHub

GITHUB_TOKEN = "your_github_token_here"
DB_HOST      = "localhost"
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

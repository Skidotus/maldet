# Copy this to config.py and fill in your values
# NEVER push config.py to GitHub

GITHUB_TOKEN = "your_github_token_here"
DB_HOST      = "localhost"
DB_USER      = "fypuser"
DB_PASSWORD  = "your_db_password"
DB_NAME      = "fyp_scanner"

# No LLM key here yet. The plain-English findings summary
# (app.py:build_findings_summary) is rule-based for now; PRODUCT.md specifies
# Ollama/llama3.2 for it, which runs locally and needs no API key. If that
# decision changes to a hosted API instead, add its key back here.

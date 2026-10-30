#!/usr/bin/env bash
#
# Stops Apache recording which repositories people look at.
#
#   sudo bash docker/apply-apache-logging.sh
#
# Edits the certbot-generated SSL vhost in place, keeping a timestamped
# backup. Safe to run twice: it checks for its own marker first. If the
# resulting config does not pass apache2ctl configtest, the backup is
# restored and nothing is reloaded -- a broken vhost takes the whole site
# down, which is not a thing to find out about later.

set -euo pipefail

VHOST=${VHOST:-/etc/apache2/sites-enabled/000-default-le-ssl.conf}

[ -f "$VHOST" ] || { echo "No vhost at $VHOST"; exit 1; }

if grep -q 'maldet_lookup' "$VHOST"; then
  echo "Already applied — nothing to do."
  exit 0
fi

BACKUP="$VHOST.bak-$(date +%s)"
cp "$VHOST" "$BACKUP"
echo "Backed up to $BACKUP"

python3 - "$VHOST" <<'PY'
import re, sys

path = sys.argv[1]
text = open(path).read()

# The existing unconditional CustomLog has to go, or every lookup is written
# twice -- once by it, once by the new rule.
text, removed = re.subn(
    r'^[ \t]*CustomLog \$\{APACHE_LOG_DIR\}/access\.log combined[ \t]*\n',
    '', text, count=1, flags=re.M)
print(f"  removed {removed} existing CustomLog line(s)")

block = (
    '\n'
    '\t# The extension asks /api/extension/lookup?repo=owner/name on every\n'
    '\t# GitHub repository page someone opens. Apache\'s combined format\n'
    '\t# writes the full request line, which turns this log into a list of\n'
    '\t# which visitor looked at which repositories. These requests are\n'
    '\t# still logged -- status, size, that they happened -- with "%m %U"\n'
    '\t# instead of "%r", so the repository name is not written down.\n'
    '\tSetEnvIf Request_URI "^/api/extension/lookup" maldet_lookup\n'
    '\tLogFormat "%h %l %u %t \\"%m %U\\" %>s %O" maldet_nolookupquery\n'
    '\tCustomLog ${APACHE_LOG_DIR}/access.log combined             env=!maldet_lookup\n'
    '\tCustomLog ${APACHE_LOG_DIR}/access.log maldet_nolookupquery env=maldet_lookup\n'
)

i = text.rindex('</VirtualHost>')
open(path, 'w').write(text[:i] + block + text[i:])
print("  inserted the conditional logging rules")
PY

if apache2ctl configtest 2>&1 | grep -q 'Syntax OK'; then
  echo "Config valid — reloading Apache"
  systemctl reload apache2
  echo
  echo "Done. Check a lookup line no longer carries ?repo= :"
  echo "  tail -f /var/log/apache2/access.log | grep extension/lookup"
else
  echo "CONFIG INVALID — restoring the backup, nothing reloaded:"
  apache2ctl configtest || true
  cp "$BACKUP" "$VHOST"
  exit 1
fi

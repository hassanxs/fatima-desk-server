#!/usr/bin/env bash
# Nightly Fatima Desk backup: server key pair, ID server database and Console
# database, 14-day retention. Run from the deploy user's crontab:
#   15 3 * * * $HOME/fatimadesk-server/backup.sh >> $HOME/fatimadesk-server/backups/backup.log 2>&1
# Databases are copied with SQLite's online backup, so a copy taken while the
# servers run is consistent. Nothing is stopped or restarted.
set -euo pipefail
umask 077
DIR="$(cd "$(dirname "$0")" && pwd)"
BK="$DIR/backups"
STAMP=$(date -u +%F-%H%M)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$BK" "$TMP/fatimadesk-$STAMP"
OUT="$TMP/fatimadesk-$STAMP"

cp "$DIR/data/id_ed25519" "$DIR/data/id_ed25519.pub" "$OUT/"
python3 - "$DIR" "$OUT" <<'EOF'
import sqlite3, sys
src_dir, out = sys.argv[1], sys.argv[2]
for src, name in ((f"{src_dir}/data/db_v2.sqlite3", "db_v2.sqlite3"),
                  (f"{src_dir}/console-data/console.db", "console.db")):
    s = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    d = sqlite3.connect(f"{out}/{name}")
    s.backup(d)
    if d.execute("pragma integrity_check").fetchone()[0] != "ok":
        sys.exit(f"integrity check failed: {name}")
    d.close(); s.close()
EOF
cp "$DIR/docker-compose.yml" "$OUT/"
[ -f "$DIR/data/blocklist.txt" ] && cp "$DIR/data/blocklist.txt" "$OUT/"

tar czf "$BK/fatimadesk-$STAMP.tar.gz" -C "$TMP" "fatimadesk-$STAMP"
find "$BK" -name 'fatimadesk-*.tar.gz' -mtime +14 -delete
echo "$(date -u '+%F %T') backup ok: fatimadesk-$STAMP.tar.gz ($(du -h "$BK/fatimadesk-$STAMP.tar.gz" | cut -f1))"

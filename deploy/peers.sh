#!/bin/sh
# List every Fatima Desk ID registered with this server: ID, first seen, last IP.
# Read-only: opens the database read-only in a throwaway container, then removes
# the helper image again so nothing is left behind on the VPS.
cd "$(dirname "$0")" || exit 1
docker pull -q keinos/sqlite3:3.46.1 >/dev/null || exit 1
docker run --rm -v "$PWD/data:/d:ro" keinos/sqlite3:3.46.1 \
  sqlite3 -header -column /d/db_v2.sqlite3 \
  "select id, created_at as first_seen, json_extract(info, '$.ip') as ip from peer order by created_at;"
status=$?
docker image rm keinos/sqlite3:3.46.1 >/dev/null 2>&1
exit $status

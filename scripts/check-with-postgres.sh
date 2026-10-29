#!/usr/bin/env bash
set -euo pipefail
# A disposable, socket-only cluster; never connects to an application database.
pg_bin="${STUHELPER_TEST_PG_BIN:-/usr/lib/postgresql/18/bin}"
test -x "$pg_bin/initdb"
task_dir="$(mktemp -d /tmp/stuhelper-storage-check.XXXXXX)"
cleanup() {
  "$pg_bin/pg_ctl" -D "$task_dir/data" -m immediate stop >/dev/null 2>&1 || true
  case "$task_dir" in /tmp/stuhelper-storage-check.*) rm -rf -- "$task_dir" ;; esac
}
trap cleanup EXIT INT TERM
mkdir "$task_dir/socket"
"$pg_bin/initdb" -D "$task_dir/data" --auth-local=trust --auth-host=reject --no-locale --encoding=UTF8 >/dev/null
"$pg_bin/pg_ctl" -D "$task_dir/data" -l "$task_dir/server.log" -o "-h '' -k $task_dir/socket -p 55439" -w start >/dev/null
export STUHELPER_STORAGE_TEST_DSN="host=$task_dir/socket port=55439 user=$(id -un) dbname=postgres sslmode=disable"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf 'Storage source: `%s`\n\n' "$(git rev-parse HEAD)"
    printf 'BHpan source dependency: `%s`\n\n' "$(GOWORK=off go list -m github.com/StuHelper/stuhelper-storage-bhpan)"
    printf 'Database: `%s`; GOWORK=off; isolated socket-only test cluster.\n' "$("$pg_bin/postgres" --version)"
  } >> "$GITHUB_STEP_SUMMARY"
fi
make check

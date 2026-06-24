#!/usr/bin/env bash
#
# End-to-end tests for mailu-queue-watch.sh. No Docker/Mailu required: the
# script's QUEUE_SOURCE_CMD / LOG_SOURCE_CMD hooks feed it fixture files.
#
# Usage: tests/run.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/tests/fixtures"
WATCH="$ROOT/bin/mailu-queue-watch.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export MQW_LIB_DIR="$ROOT/lib"

pass=0; fail=0
ok()   { printf '  PASS %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }
check(){ # check <desc> <haystack> <needle>
    case "$2" in *"$3"*) ok "$1" ;; *) bad "$1 (missing: $3)"; printf '       in: %s\n' "$2" ;; esac
}

make_config() { # make_config <dir>
    cat > "$1/conf" <<EOF
COMPOSE_DIR="/nonexistent"
WINDOW="15m"
LOG_FILE="$1/metrics.log"
ALERT_FILE="$1/alerts.log"
STATE_DIR="$1/state"
QUEUE_WARN=20;  QUEUE_CRIT=50
DEFERRED_WARN=10;  DEFERRED_CRIT=30
SENDER_SENT_WARN=10;  SENDER_SENT_CRIT=25
SENDER_QUEUE_WARN=20;  SENDER_QUEUE_CRIT=50
RCPT_DOMAINS_WARN=10;  RCPT_DOMAINS_CRIT=20
BOUNCE_DEFER_RATE_WARN=20;  BOUNCE_DEFER_RATE_CRIT=40
SPAM_BLOCK_WARN=1;  SPAM_BLOCK_CRIT=5
ALERT_COOLDOWN_MINUTES=30
EOF
}

run_incident() { # run_incident <dir> <extra-args...>
    QUEUE_SOURCE_CMD="cat '$FIX/postqueue-incident.json'" \
    LOG_SOURCE_CMD="cat '$FIX/smtp-incident.log'" \
        bash "$WATCH" --config "$1/conf" "${@:2}"
}
run_quiet() { # run_quiet <dir> <extra-args...>
    QUEUE_SOURCE_CMD="cat '$FIX/postqueue-quiet.json'" \
    LOG_SOURCE_CMD="cat '$FIX/smtp-quiet.log'" \
        bash "$WATCH" --config "$1/conf" "${@:2}"
}

echo "shellcheck:"
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -s bash "$WATCH" "$ROOT/bin/mailu-queue-report.sh" "$ROOT/install.sh"; then
        ok "shellcheck clean"
    else
        bad "shellcheck reported issues"
    fi
else
    echo "  (shellcheck not installed, skipping)"
fi

echo "T1: incident metrics (--print)"
d="$WORK/t1"; mkdir -p "$d"; make_config "$d"
out="$(run_incident "$d" --print)"
check "queue_total"          "$out" "queue_total=63"
check "deferred_queue"       "$out" "deferred_queue=60"
check "top sasl sender"      "$out" "top_sasl=noreply@example.com"
check "top sasl count"       "$out" "top_sasl_count=30"
check "rcpt domain fanout"   "$out" "queue_top_domain_count=25"
check "rate limit counted"   "$out" "rate_limits_15m=1"
check "severity critical"    "$out" "severity=critical"

echo "T2: quiet metrics (--print)"
d="$WORK/t2"; mkdir -p "$d"; make_config "$d"
out="$(run_quiet "$d" --print)"
check "queue_total small"    "$out" "queue_total=2"
check "severity ok"          "$out" "severity=ok"

echo "T3: incident full run writes alert + state"
d="$WORK/t3"; mkdir -p "$d"; make_config "$d"
run_incident "$d" >/dev/null
if [ -s "$d/metrics.log" ]; then ok "metrics.log written"; else bad "metrics.log empty"; fi
check "alert is critical"    "$(cat "$d/alerts.log" 2>/dev/null)" "severity=critical"
check "alert reason: rate limit"   "$(cat "$d/alerts.log")" "rate_limit_seen"
check "alert reason: spam blocks"  "$(cat "$d/alerts.log")" "spam_blacklist_blocks"
check "alert reason: fanout"       "$(cat "$d/alerts.log")" "rcpt_domain_fanout_gt_20"
check "notify-state critical"      "$(cat "$d/state/notify-state" 2>/dev/null)" "critical"
if [ -d "$d/state/snapshots" ]; then bad "snapshot taken from fixtures (should skip)"; else ok "snapshot skipped under fixtures"; fi

echo "T4: quiet full run -> ok, no alert appended"
d="$WORK/t4"; mkdir -p "$d"; make_config "$d"
run_quiet "$d" >/dev/null
if [ -f "$d/alerts.log" ]; then bad "alert log created on quiet run"; else ok "no alert log on quiet run"; fi
check "notify-state ok"      "$(cat "$d/state/notify-state" 2>/dev/null)" "ok"

echo "T5: cooldown suppresses re-notify within window"
d="$WORK/t5"; mkdir -p "$d"; make_config "$d"
run_incident "$d" >/dev/null
s1="$(cut -d' ' -f1 "$d/state/notify-state")"
run_incident "$d" >/dev/null
s2="$(cut -d' ' -f1 "$d/state/notify-state")"
if [ "$s1" = "$s2" ]; then ok "notify timestamp unchanged on 2nd critical (cooldown held)"
else bad "notify re-fired within cooldown ($s1 -> $s2)"; fi
# alert log still appends every run (local record): one block header per run
n="$(grep -c '] severity=critical reasons=' "$d/alerts.log")"
if [ "$n" -eq 2 ]; then ok "alert log records both samples ($n)"; else bad "expected 2 alert records, got $n"; fi

echo "T6: dry-run does not touch files"
d="$WORK/t6"; mkdir -p "$d"; make_config "$d"
out="$(run_incident "$d" --dry-run)"
check "dry-run shows alert"  "$out" "ALERT (dry-run)"
if [ -f "$d/metrics.log" ]; then bad "dry-run wrote metrics.log"; else ok "dry-run wrote nothing"; fi

echo "T7: text-format postqueue (-p) parsing path"
d="$WORK/t7"; mkdir -p "$d"; make_config "$d"
out="$(QUEUE_SOURCE_CMD="cat '$FIX/postqueue-incident.txt'" \
       LOG_SOURCE_CMD="cat '$FIX/smtp-incident.log'" \
       bash "$WATCH" --config "$d/conf" --print)"
check "text queue_total"     "$out" "queue_total=5"
check "text deferred"        "$out" "deferred_queue=3"

echo
printf 'RESULT: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

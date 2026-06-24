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
BULK_SENDER_MSGS=10;  MULTI_SENDER_WARN=3;  MULTI_SENDER_CRIT=5
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
    if shellcheck -s bash "$ROOT"/bin/*.sh "$ROOT/install.sh" "$ROOT/tests/run.sh" "$ROOT/tests/gen-fixtures.sh"; then
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
check "bulk senders = 1"     "$out" "bulk_senders=1"
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
check "plain-language summary line" "$out" "sent 30 messages in 15m and 88% are failing"
check "summary lists red flags"     "$out" "rate-limited, rejected as spam/blacklisted"
if [ -f "$d/metrics.log" ]; then bad "dry-run wrote metrics.log"; else ok "dry-run wrote nothing"; fi

echo "T7: text-format postqueue (-p) parsing path"
d="$WORK/t7"; mkdir -p "$d"; make_config "$d"
out="$(QUEUE_SOURCE_CMD="cat '$FIX/postqueue-incident.txt'" \
       LOG_SOURCE_CMD="cat '$FIX/smtp-incident.log'" \
       bash "$WATCH" --config "$d/conf" --print)"
check "text queue_total"     "$out" "queue_total=5"
check "text deferred"        "$out" "deferred_queue=3"

echo "T8: multiple bulk senders at once (compromised-account-dump pattern)"
d="$WORK/t8"; mkdir -p "$d"; make_config "$d"
out="$(QUEUE_SOURCE_CMD="printf ''" \
       LOG_SOURCE_CMD="cat '$FIX/smtp-multisender.log'" \
       bash "$WATCH" --config "$d/conf" --print)"
check "6 bulk senders"       "$out" "bulk_senders=6"
check "empty queue"          "$out" "queue_total=0"
check "severity critical"    "$out" "severity=critical"

echo "T9: front-log real source IPs (mailu-front-ips.sh)"
FRONT="$ROOT/bin/mailu-front-ips.sh"
out="$(FRONT_LOG_SOURCE_CMD="cat '$FIX/front.log'" bash "$FRONT" --config /dev/null)"
check "attacker IP surfaced"     "$out" "203.0.113.66"
check "attacker line count = 5"  "$out" "5  203.0.113.66"
check "legit IP surfaced"        "$out" "198.51.100.20"
case "$out" in
    *192.168.0.9*|*172.20.0.5*) bad "internal IP leaked into external list" ;;
    *) ok "internal/private IPs excluded" ;;
esac
out2="$(FRONT_LOG_SOURCE_CMD="cat '$FIX/front.log'" bash "$FRONT" --config /dev/null --user 'noreply@')"
check "user filter keeps attacker" "$out2" "203.0.113.66"
case "$out2" in
    *198.51.100.20*) bad "user filter did not exclude the legit IP" ;;
    *) ok "user filter narrows to suspect account" ;;
esac

echo "T10: fixture hygiene (only reserved domains/IPs may be committed)"
# Allowed: *.example (RFC2606 TLD), example.com, example.org.
bad_dom="$(grep -rhoE '@[A-Za-z0-9.-]+|helo=<[^>]+>|mx\.[A-Za-z0-9.-]+' "$FIX" \
    | grep -oE '[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+' \
    | grep -vE '(^|\.)example$' | grep -vE '^example\.(com|org)$' | sort -u || true)"
if [ -z "$bad_dom" ]; then ok "no non-reserved domains in fixtures"
else bad "non-reserved domain(s) in fixtures: $bad_dom"; fi
# Allowed IPs: RFC5737 (203.0.113/198.51.100/192.0.2), RFC1918, 0.0.0.0, loopback.
bad_ip="$(grep -rhoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$FIX" \
    | grep -vE '^(203\.0\.113|198\.51\.100|192\.0\.2)\.' \
    | grep -vE '^(10|127)\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^0\.0\.0\.0$' | sort -u || true)"
if [ -z "$bad_ip" ]; then ok "no routable/real IPs in fixtures"
else bad "non-reserved IP(s) in fixtures: $bad_ip"; fi

echo "T11: mailu-queue-drain.sh exact match + apply (dry-run/capture)"
DRAIN="$ROOT/bin/mailu-queue-drain.sh"
qsrc="QUEUE_SOURCE_CMD=\"cat '$FIX/postqueue-incident.json'\""
o="$(eval "$qsrc" bash "$DRAIN" --config /dev/null --dry-run noreply@example.com)"
check "sender exact match = 60"  "$o" "Matched 60 message"
o="$(eval "$qsrc" bash "$DRAIN" --config /dev/null --dry-run noreply@example)"
check "no partial match"         "$o" "Matched 0 message"
o="$(eval "$qsrc" bash "$DRAIN" --config /dev/null --dry-run --recipient customer1@example.com)"
check "recipient exact match = 1" "$o" "Matched 1 message"
capt="$WORK/ids"
eval "$qsrc" DRAIN_APPLY_CMD="\"cat > '$capt'\"" bash "$DRAIN" --config /dev/null -y noreply@example.com >/dev/null
got="$(grep -c . "$capt" 2>/dev/null || echo 0)"
if [ "$got" -eq 60 ]; then ok "apply received all 60 ids"; else bad "apply got $got ids (expected 60)"; fi

echo
printf 'RESULT: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

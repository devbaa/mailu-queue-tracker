#!/usr/bin/env bash
#
# mailu-alert-test.sh -- send a timestamped test alert to the configured
# notification channels, so you can confirm Telegram/Slack delivery is live and
# see any delay (compare the embedded send-time to when the message arrives).
#
# Usage:
#   mailu-alert-test.sh [--config PATH] [--telegram] [--slack]
#                       [-m "extra note"] [--print]
#
#   --telegram   send only to Telegram      (default: every configured channel)
#   --slack      send only to Slack
#   -m TEXT      append a custom note to the message
#   --print      print the message that WOULD be sent; send nothing
#
# The message carries local time (with UTC offset), the timezone, UTC, and the
# epoch, so there is no ambiguity about when it was sent.

set -uo pipefail

CONFIG="${MQW_CONFIG:-/etc/mailu-queue-watch.conf}"
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
SLACK_WEBHOOK_URL=""

ONLY=""
NOTE=""
PRINT=0

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --config) CONFIG="$2"; shift 2 ;;
        --config=*) CONFIG="${1#*=}"; shift ;;
        --telegram) ONLY="telegram"; shift ;;
        --slack) ONLY="slack"; shift ;;
        -m) NOTE="$2"; shift 2 ;;
        --print|--show) PRINT=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# shellcheck source=/dev/null
[ -f "$CONFIG" ] && . "$CONFIG"

host="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
local_ts="$(date -Is)"                       # e.g. 2026-06-24T13:05:12+03:00
tzname="$(date +%Z)"                          # e.g. EEST / UTC
utc_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"       # e.g. 2026-06-24T10:05:12Z
epoch="$(date +%s)"

msg="mailu-queue-tracker test
sent: ${local_ts} ${tzname}
UTC:  ${utc_ts}  (epoch ${epoch})
host: ${host}"
[ -n "$NOTE" ] && msg="${msg}
note: ${NOTE}"

if [ "$PRINT" -eq 1 ]; then
    printf '%s\n' "$msg"
    exit 0
fi

send_telegram() {
    local resp code body
    resp="$(curl -sS -m 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" --data-urlencode "text=${msg}" \
        -w '\n%{http_code}' 2>/dev/null)"
    code="${resp##*$'\n'}"; body="${resp%$'\n'*}"
    if [ "$code" = 200 ] && printf '%s' "$body" | grep -q '"ok":true'; then
        echo "Telegram: OK (delivered to chat ${TELEGRAM_CHAT_ID})"
    else
        echo "Telegram: FAILED (http ${code:-?}) ${body}"
        return 1
    fi
}

send_slack() {
    local payload resp code body
    payload="$(printf '%s' "$msg" | sed ':a;N;$!ba;s/\\/\\\\/g;s/"/\\"/g;s/\n/\\n/g')"
    resp="$(curl -sS -m 15 -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"${payload}\"}" "$SLACK_WEBHOOK_URL" \
        -w '\n%{http_code}' 2>/dev/null)"
    code="${resp##*$'\n'}"; body="${resp%$'\n'*}"
    if [ "$code" = 200 ]; then
        echo "Slack: OK"
    else
        echo "Slack: FAILED (http ${code:-?}) ${body}"
        return 1
    fi
}

rc=0
tried=0
if [ "$ONLY" = "telegram" ] || { [ -z "$ONLY" ] && [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; }; then
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        tried=1; send_telegram || rc=1
    else
        echo "Telegram: not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)"; rc=1
    fi
fi
if [ "$ONLY" = "slack" ] || { [ -z "$ONLY" ] && [ -n "$SLACK_WEBHOOK_URL" ]; }; then
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        tried=1; send_slack || rc=1
    else
        echo "Slack: not configured (set SLACK_WEBHOOK_URL)"; rc=1
    fi
fi

if [ "$tried" -eq 0 ]; then
    echo "no notification channel configured in $CONFIG (set TELEGRAM_* and/or SLACK_WEBHOOK_URL)" >&2
    exit 1
fi
exit "$rc"

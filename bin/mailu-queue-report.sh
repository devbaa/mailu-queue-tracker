#!/usr/bin/env bash
#
# mailu-queue-report.sh -- summarise what mailu-queue-watch has recorded.
# Handy for the weekly review: recent alerts, noisiest SASL senders, and the
# samples where spam/blacklist blocks or rate limits showed up.
#
# Usage: mailu-queue-report.sh [--config PATH] [--lines N]

set -uo pipefail

CONFIG="${MQW_CONFIG:-/etc/mailu-queue-watch.conf}"
LINES=50

while [ $# -gt 0 ]; do
    case "$1" in
        --config) CONFIG="$2"; shift 2 ;;
        --config=*) CONFIG="${1#*=}"; shift ;;
        --lines) LINES="$2"; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

LOG_FILE="/var/log/mailu-queue-watch.log"
ALERT_FILE="/var/log/mailu-queue-alerts.log"
# shellcheck source=/dev/null
[ -f "$CONFIG" ] && . "$CONFIG"

rule() { printf '\n== %s ==\n' "$1"; }

rule "Recent alerts (last $LINES)"
if [ -f "$ALERT_FILE" ]; then
    grep 'severity=' "$ALERT_FILE" | tail -n "$LINES" || echo "(none)"
else
    echo "no alert log at $ALERT_FILE"
fi

rule "Noisiest SASL senders across all samples"
if [ -f "$LOG_FILE" ]; then
    grep '^top_sasl ' "$LOG_FILE" \
        | awk '{ c[$3] += $2 } END { for (u in c) printf "%8d  %s\n", c[u], u }' \
        | sort -nr | head -30
else
    echo "no metrics log at $LOG_FILE"
fi

rule "Samples with spam/blacklist blocks"
[ -f "$LOG_FILE" ] && { grep -oE 'time=[^ ]+ .*spam_blocks_[^ ]*=[1-9][0-9]*' "$LOG_FILE" | tail -n "$LINES" || echo "(none)"; }

rule "Samples with rate-limit rejections"
[ -f "$LOG_FILE" ] && { grep -oE 'time=[^ ]+ .*rate_limits_[^ ]*=[1-9][0-9]*' "$LOG_FILE" | tail -n "$LINES" || echo "(none)"; }

rule "Peak per-sender SASL volume seen"
[ -f "$LOG_FILE" ] && { grep -oE 'top_sasl_count=[0-9]+' "$LOG_FILE" | cut -d= -f2 | sort -nr | head -1 | sed 's/^/max messages in one window: /'; }

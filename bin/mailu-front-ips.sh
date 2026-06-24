#!/usr/bin/env bash
#
# mailu-front-ips.sh -- show the real external client IPs from the Mailu `front`
# log, with the usernames that authenticated from each.
#
# The `smtp` container only ever logs the front (XCLIENT), so a compromised
# account's true source IP lives in the front log. Use this to find it, then
# firewall / fail2ban it.
#
# Usage:
#   mailu-front-ips.sh [--config PATH] [--since 2h] [--user REGEX]
#                      [--top N] [--all] [--exclude IP[,IP...]]
#
#   --since   docker log window (default: WINDOW from config, else 24h)
#   --user    only count lines matching this regex (e.g. a suspect account)
#   --top     how many IPs to show (default 20)
#   --all     include private/internal IPs (hidden by default)
#   --exclude IPs to always drop (e.g. the front's own public IP)

set -uo pipefail

SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SELF_DIR="$(dirname "$SELF")"
_find_lib() {
    local name="$1" c
    for c in "${MQW_LIB_DIR:-}" "$SELF_DIR/../lib" "$SELF_DIR/lib" \
             /usr/local/lib/mailu-queue-watch /usr/lib/mailu-queue-watch; do
        [ -n "$c" ] && [ -f "$c/$name" ] && { printf '%s\n' "$c/$name"; return 0; }
    done
    return 1
}

CONFIG="${MQW_CONFIG:-/etc/mailu-queue-watch.conf}"
COMPOSE_DIR="/opt/mailu"
COMPOSE_CMD="docker compose"
FRONT_SERVICE="front"
WINDOW="24h"

SINCE=""
USER_RE=""
TOP=20
INCL=0
EXCLUDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --config)  CONFIG="$2"; shift 2 ;;
        --config=*) CONFIG="${1#*=}"; shift ;;
        --since)   SINCE="$2"; shift 2 ;;
        --user)    USER_RE="$2"; shift 2 ;;
        --top)     TOP="$2"; shift 2 ;;
        --all)     INCL=1; shift ;;
        --exclude) EXCLUDE="$2"; shift 2 ;;
        -h|--help) sed -n '2,21p' "$SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# shellcheck source=/dev/null
[ -f "$CONFIG" ] && . "$CONFIG"
[ -n "$SINCE" ] || SINCE="${WINDOW:-24h}"

PARSE_FRONT_AWK="$(_find_lib parse-front.awk)" || {
    printf 'fatal: parse-front.awk not found (set MQW_LIB_DIR)\n' >&2; exit 3; }

read -r -a _compose <<<"$COMPOSE_CMD"
get_front_logs() {
    if [ -n "${FRONT_LOG_SOURCE_CMD:-}" ]; then eval "$FRONT_LOG_SOURCE_CMD"; return; fi
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" logs --since="$SINCE" "$FRONT_SERVICE" ) 2>/dev/null || true
}

logs="$(get_front_logs)"
if [ -n "$USER_RE" ]; then
    logs="$(printf '%s\n' "$logs" | grep -Ei -- "$USER_RE" || true)"
fi

table="$(printf '%s\n' "$logs" \
    | awk -f "$PARSE_FRONT_AWK" -v incl="$INCL" -v excl="$EXCLUDE" \
    | sort -nr | head -n "$TOP")"

hidden_note="(private/internal IPs hidden; use --all to include)"
[ "$INCL" -eq 1 ] && hidden_note="(including private/internal IPs)"

printf 'Top external source IPs from "%s" log, since %s %s\n' "$FRONT_SERVICE" "$SINCE" "$hidden_note"
[ -n "$USER_RE" ] && printf 'filtered to lines matching: %s\n' "$USER_RE"
printf '%6s  %-18s  %-6s  %s\n' "lines" "ip" "users" "sample_users"
if [ -z "$table" ]; then
    echo "  (no external client IPs found -- is this the front log? try --all)"
else
    printf '%s\n' "$table" | awk -F'\t' '{printf "%6d  %-18s  %-6d  %s\n", $1, $2, $3, $4}'
fi

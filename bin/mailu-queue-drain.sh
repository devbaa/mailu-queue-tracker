#!/usr/bin/env bash
#
# mailu-queue-drain.sh -- delete (or hold) all queued messages for one email
# address, matched by envelope sender (default) or recipient.
#
# Usage:
#   mailu-queue-drain.sh [options] <email-address>
#
#   -r, --recipient   match the recipient address instead of the sender
#       --hold        hold messages (postsuper -h) instead of deleting them
#   -n, --dry-run     only report how many match; change nothing
#   -y, --yes         do not prompt for confirmation
#       --config PATH config file (default /etc/mailu-queue-watch.conf)
#   -h, --help
#
# Exact, case-insensitive match: "example.com" will NOT match
# "noreply@mx.example.com". Requires `postqueue -j` (Postfix >= 3.1; Mailu ships it).

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
SMTP_SERVICE="smtp"

FIELD="sender"
OP="-d"; OP_WORD="delete"
DRY=0; ASSUME_YES=0
ADDR=""

usage() { sed -n '2,18p' "$SELF" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        -r|--recipient) FIELD="recipient"; shift ;;
        --hold) OP="-h"; OP_WORD="hold"; shift ;;
        -n|--dry-run) DRY=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        --config) CONFIG="$2"; shift 2 ;;
        --config=*) CONFIG="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
        *) if [ -z "$ADDR" ]; then ADDR="$1"; else printf 'one address only\n' >&2; exit 2; fi; shift ;;
    esac
done

[ -n "$ADDR" ] || { usage; exit 2; }
# shellcheck source=/dev/null
[ -f "$CONFIG" ] && . "$CONFIG"

MATCH_AWK="$(_find_lib match-queue.awk)" || {
    printf 'fatal: match-queue.awk not found (set MQW_LIB_DIR)\n' >&2; exit 3; }
read -r -a _compose <<<"$COMPOSE_CMD"

get_queue() {
    if [ -n "${QUEUE_SOURCE_CMD:-}" ]; then eval "$QUEUE_SOURCE_CMD"; return; fi
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" exec -T "$SMTP_SERVICE" postqueue -j ) 2>/dev/null || true
}
apply() {   # reads queue ids on stdin, deletes/holds them in the smtp container
    if [ -n "${DRAIN_APPLY_CMD:-}" ]; then eval "$DRAIN_APPLY_CMD"; return; fi
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" exec -T "$SMTP_SERVICE" postsuper "$OP" - ) 2>/dev/null
}

ids="$(get_queue | awk -f "$MATCH_AWK" -v addr="$ADDR" -v field="$FIELD")"
n=0
[ -n "$ids" ] && n="$(printf '%s\n' "$ids" | grep -c .)"

printf 'Matched %d message(s) where %s = %s\n' "$n" "$FIELD" "$ADDR"
[ "$n" -eq 0 ] && exit 0
if [ "$DRY" -eq 1 ]; then echo "(dry-run: nothing changed)"; exit 0; fi

if [ "$ASSUME_YES" -ne 1 ]; then
    printf '%s %d message(s) from %s? [y/N] ' "$OP_WORD" "$n" "$ADDR"
    read -r ans </dev/tty 2>/dev/null || ans=""
    case "$ans" in y|Y|yes|YES) ;; *) echo "aborted"; exit 0 ;; esac
fi

printf '%s\n' "$ids" | apply
printf 'Done (%s %d message(s) from %s).\n' "$OP_WORD" "$n" "$ADDR"

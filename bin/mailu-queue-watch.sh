#!/usr/bin/env bash
#
# mailu-queue-watch.sh -- detect abusive / compromised-account SMTP activity on
# a Mailu (Postfix) host by tracking queue behaviour and delivery outcomes.
#
# It samples, every run (intended cadence: every 5 minutes via systemd timer):
#   * total / deferred queue size and per-sender queue backlog   (postqueue)
#   * recipient-domain fan-out per sender                        (postqueue)
#   * sent / bounced / deferred counts in the recent window      (smtp logs)
#   * remote "spam / blacklisted / blocked" rejections           (smtp logs)
#   * Postfix / Mailu rate-limit rejections                      (smtp logs)
#   * top authenticated (SASL) senders by volume                 (smtp logs)
#
# Metrics are appended to LOG_FILE. When thresholds are crossed an alert is
# appended to ALERT_FILE, an evidence snapshot is taken, and (rate-limited by a
# cooldown) a notification is sent via Telegram / Slack / a custom command.
#
# Alerts are metadata-only: no recipient lists or message contents are emitted.
#
# Usage: mailu-queue-watch.sh [--config PATH] [--dry-run] [--print] [-h|--help]

set -uo pipefail

# ---------------------------------------------------------------------------
# Locate ourselves and the bundled awk parser.
# ---------------------------------------------------------------------------
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SELF_DIR="$(dirname "$SELF")"

_find_lib() {
    local name="$1" c
    for c in \
        "${MQW_LIB_DIR:-}" \
        "$SELF_DIR/../lib" \
        "$SELF_DIR/lib" \
        /usr/local/lib/mailu-queue-watch \
        /usr/lib/mailu-queue-watch; do
        [ -n "$c" ] && [ -f "$c/$name" ] && { printf '%s\n' "$c/$name"; return 0; }
    done
    return 1
}

# ---------------------------------------------------------------------------
# Defaults (override via the config file).
# ---------------------------------------------------------------------------
CONFIG="${MQW_CONFIG:-/etc/mailu-queue-watch.conf}"
DRY_RUN=0
PRINT_ONLY=0

# -- environment / Mailu wiring --
COMPOSE_DIR="/opt/mailu"
COMPOSE_CMD="docker compose"
SMTP_SERVICE="smtp"
FRONT_SERVICE="front"
WINDOW="15m"
SNAPSHOT_WINDOW="30m"

# -- output locations --
LOG_FILE="/var/log/mailu-queue-watch.log"
ALERT_FILE="/var/log/mailu-queue-alerts.log"
STATE_DIR="/var/lib/mailu-queue-watch"

# -- thresholds (see docs/thresholds.md; tune to your normal volume) --
QUEUE_WARN=200;            QUEUE_CRIT=500
DEFERRED_WARN=100;         DEFERRED_CRIT=300
SENDER_SENT_WARN=50;       SENDER_SENT_CRIT=150     # SASL messages in WINDOW
SENDER_QUEUE_WARN=100;     SENDER_QUEUE_CRIT=300    # messages queued by one sender
RCPT_DOMAINS_WARN=25;      RCPT_DOMAINS_CRIT=50     # distinct rcpt domains, one sender
BOUNCE_DEFER_RATE_WARN=20; BOUNCE_DEFER_RATE_CRIT=40 # percent over WINDOW
SPAM_BLOCK_WARN=1;         SPAM_BLOCK_CRIT=5         # remote spam/blacklist hits

# -- log match patterns (extended regex, case-insensitive) --
RATELIMIT_REGEX='too many|rate.?limit|sasl login name rejected|sender address rejected.*rate|recipient address rate'
SPAM_REGEX='spam|blacklist|blocklist|blocked|policy rejection|reputation|hostkarma|spamhaus|barracuda|listed on|access denied|554 5.7.1'

# -- notifications --
ALERT_COOLDOWN_MINUTES=30
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
SLACK_WEBHOOK_URL=""
ALERT_COMMAND=""        # optional: receives the alert text on stdin

# -- evidence / export --
SNAPSHOT_ON_ALERT=1
PROM_TEXTFILE=""        # e.g. /var/lib/node_exporter/textfile_collector/mailu_queue.prom

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
usage() { sed -n '2,20p' "$SELF" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --config) CONFIG="$2"; shift 2 ;;
        --config=*) CONFIG="${1#*=}"; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --print) PRINT_ONLY=1; DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# shellcheck source=/dev/null
[ -f "$CONFIG" ] && . "$CONFIG"

PARSE_QUEUE_AWK="$(_find_lib parse-queue.awk)" || {
    printf 'fatal: parse-queue.awk not found (set MQW_LIB_DIR)\n' >&2
    exit 3
}

now="$(date -Is)"
now_epoch="$(date +%s)"

# ---------------------------------------------------------------------------
# Data sources. Both can be overridden for testing via the environment, which
# is how tests/run.sh feeds fixtures without a running Mailu.
# ---------------------------------------------------------------------------
read -r -a _compose <<<"$COMPOSE_CMD"

get_queue() {
    if [ -n "${QUEUE_SOURCE_CMD:-}" ]; then
        eval "$QUEUE_SOURCE_CMD"
        return
    fi
    # Prefer the JSON listing (Postfix >= 3.1); fall back to the text mailq.
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" exec -T "$SMTP_SERVICE" postqueue -j ) 2>/dev/null && return
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" exec -T "$SMTP_SERVICE" postqueue -p ) 2>/dev/null || true
}

get_logs() {
    if [ -n "${LOG_SOURCE_CMD:-}" ]; then
        eval "$LOG_SOURCE_CMD"
        return
    fi
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" logs --since="$WINDOW" "$SMTP_SERVICE" ) 2>/dev/null || true
}

# Count stdin lines matching an extended regex; always succeeds, prints an int.
count_re()  { grep -Ec  "$1" || true; }
count_rei() { grep -Eci "$1" || true; }

# ---------------------------------------------------------------------------
# Collect metrics.
# ---------------------------------------------------------------------------
queue_raw="$(get_queue)"
logs_raw="$(get_logs)"

# queue_* via the awk parser
queue_total=0 deferred_queue=0
queue_top_sender=none queue_top_sender_count=0
queue_unique_domains=0 queue_top_domain_sender=none queue_top_domain_count=0
while IFS='=' read -r k v; do
    case "$k" in
        queue_total)             queue_total="$v" ;;
        deferred_queue)          deferred_queue="$v" ;;
        queue_top_sender)        queue_top_sender="$v" ;;
        queue_top_sender_count)  queue_top_sender_count="$v" ;;
        queue_unique_domains)    queue_unique_domains="$v" ;;
        queue_top_domain_sender) queue_top_domain_sender="$v" ;;
        queue_top_domain_count)  queue_top_domain_count="$v" ;;
    esac
done < <(printf '%s\n' "$queue_raw" | awk -f "$PARSE_QUEUE_AWK")

# delivery outcomes from the recent log window
sent_count="$(printf '%s\n'        "$logs_raw" | count_re 'status=sent')"
bounced_count="$(printf '%s\n'     "$logs_raw" | count_re 'status=bounced')"
deferred_log_count="$(printf '%s\n' "$logs_raw" | count_re 'status=deferred')"
rate_limit_count="$(printf '%s\n'  "$logs_raw" | count_rei "$RATELIMIT_REGEX")"
spam_block_count="$(printf '%s\n'  "$logs_raw" | count_rei "$SPAM_REGEX")"

# bounce+defer rate over the window (percent of delivery attempts)
delivery_total=$(( sent_count + bounced_count + deferred_log_count ))
if [ "$delivery_total" -gt 0 ]; then
    bounce_defer_rate=$(( (bounced_count + deferred_log_count) * 100 / delivery_total ))
else
    bounce_defer_rate=0
fi

# top authenticated SASL senders in the window
top_sasl="$(printf '%s\n' "$logs_raw" \
    | grep -oE 'sasl_username=[^,[:space:]]+' \
    | cut -d= -f2 | sort | uniq -c | sort -nr | head -10 || true)"
top_sasl_count="$(printf '%s\n' "$top_sasl" | head -1 | awk '{print $1+0}')"
top_sasl_user="$(printf '%s\n'  "$top_sasl" | head -1 | awk '{print $2}')"
[ -z "$top_sasl_user" ] && top_sasl_user="none"

# ---------------------------------------------------------------------------
# Evaluate thresholds.
# ---------------------------------------------------------------------------
severity="ok"
reasons=()
rank() { case "$1" in critical) echo 2 ;; warning) echo 1 ;; *) echo 0 ;; esac; }
escalate() {                       # escalate <severity> <reason>
    local want="$1"
    if [ "$(rank "$want")" -gt "$(rank "$severity")" ]; then severity="$want"; fi
    reasons+=("$2")
}
# threshold <value> <warn> <crit> <reason_base>  (crit/warn use '>')
threshold() {
    local val="$1" warn="$2" crit="$3" base="$4"
    if   [ "$val" -gt "$crit" ]; then escalate critical "${base}_gt_${crit}"
    elif [ "$val" -gt "$warn" ]; then escalate warning  "${base}_gt_${warn}"
    fi
}

threshold "$queue_total"            "$QUEUE_WARN"            "$QUEUE_CRIT"            queue_total
threshold "$deferred_queue"         "$DEFERRED_WARN"         "$DEFERRED_CRIT"         deferred_queue
threshold "$top_sasl_count"         "$SENDER_SENT_WARN"      "$SENDER_SENT_CRIT"      sasl_sender_sent
threshold "$queue_top_sender_count" "$SENDER_QUEUE_WARN"     "$SENDER_QUEUE_CRIT"     sender_queue_backlog
threshold "$queue_top_domain_count" "$RCPT_DOMAINS_WARN"     "$RCPT_DOMAINS_CRIT"     rcpt_domain_fanout
threshold "$bounce_defer_rate"      "$BOUNCE_DEFER_RATE_WARN" "$BOUNCE_DEFER_RATE_CRIT" bounce_defer_rate_pct

if [ "$rate_limit_count" -gt 0 ]; then escalate critical "rate_limit_seen"; fi

if   [ "$spam_block_count" -ge "$SPAM_BLOCK_CRIT" ]; then escalate critical "spam_blacklist_blocks_ge_${SPAM_BLOCK_CRIT}"
elif [ "$spam_block_count" -ge "$SPAM_BLOCK_WARN" ]; then escalate warning  "spam_blacklist_terms_seen"
fi

reasons_str="${reasons[*]:-none}"

# ---------------------------------------------------------------------------
# A single key=value metrics line (easy to grep / ship to a log pipeline).
# ---------------------------------------------------------------------------
metric_line="time=$now severity=$severity queue_total=$queue_total deferred_queue=$deferred_queue \
sent_${WINDOW}=$sent_count bounced_${WINDOW}=$bounced_count deferred_${WINDOW}=$deferred_log_count \
bounce_defer_rate_pct=$bounce_defer_rate rate_limits_${WINDOW}=$rate_limit_count spam_blocks_${WINDOW}=$spam_block_count \
top_sasl=${top_sasl_user} top_sasl_count=${top_sasl_count} \
queue_top_sender=${queue_top_sender} queue_top_sender_count=${queue_top_sender_count} \
queue_top_domain_sender=${queue_top_domain_sender} queue_top_domain_count=${queue_top_domain_count} \
queue_unique_domains=${queue_unique_domains}"

if [ "$PRINT_ONLY" -eq 1 ]; then
    printf '%s\n' "$metric_line"
    printf '%s\n' "$top_sasl" | sed 's/^/top_sasl /'
    exit 0
fi

# ---------------------------------------------------------------------------
# Persist metrics.
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p "$STATE_DIR"
    {
        printf '%s\n' "$metric_line"
        printf '%s\n' "$top_sasl" | sed 's/^/top_sasl /'
    } >> "$LOG_FILE"
else
    printf '%s\n' "$metric_line"
fi

# Optional Prometheus node_exporter textfile export (written atomically).
write_prom() {
    [ -n "$PROM_TEXTFILE" ] || return 0
    local tmp="${PROM_TEXTFILE}.$$"
    if {
        echo "# HELP mailu_queue_total Messages currently in the Postfix queue."
        echo "# TYPE mailu_queue_total gauge"
        echo "mailu_queue_total $queue_total"
        echo "mailu_queue_deferred $deferred_queue"
        echo "mailu_queue_unique_recipient_domains $queue_unique_domains"
        echo "mailu_messages_sent $sent_count"
        echo "mailu_messages_bounced $bounced_count"
        echo "mailu_messages_deferred $deferred_log_count"
        echo "mailu_bounce_defer_rate_percent $bounce_defer_rate"
        echo "mailu_rate_limit_rejections $rate_limit_count"
        echo "mailu_spam_block_rejections $spam_block_count"
        echo "mailu_top_sasl_sender_messages $top_sasl_count"
        echo "mailu_severity{level=\"$severity\"} 1"
    } > "$tmp" 2>/dev/null; then
        mv -f "$tmp" "$PROM_TEXTFILE" 2>/dev/null || rm -f "$tmp" 2>/dev/null
    else
        rm -f "$tmp" 2>/dev/null
    fi
}
[ "$DRY_RUN" -eq 0 ] && write_prom

# Nothing more to do when healthy: record recovery so the next event re-alerts.
if [ "$severity" = "ok" ]; then
    [ "$DRY_RUN" -eq 0 ] && printf '%s ok\n' "$now_epoch" > "$STATE_DIR/notify-state" 2>/dev/null
    exit 0
fi

# ---------------------------------------------------------------------------
# Build the (metadata-only) alert text.
# ---------------------------------------------------------------------------
alert_text="Mailu queue alert
time=$now
severity=$severity
reasons=$reasons_str
queue_total=$queue_total
deferred_queue=$deferred_queue
sent_${WINDOW}=$sent_count
bounced_${WINDOW}=$bounced_count
deferred_${WINDOW}=$deferred_log_count
bounce_defer_rate=${bounce_defer_rate}%
rate_limits_${WINDOW}=$rate_limit_count
spam_blocks_${WINDOW}=$spam_block_count
top_sasl_sender=$top_sasl_user ($top_sasl_count msgs/${WINDOW})
queue_top_sender=$queue_top_sender ($queue_top_sender_count queued)
top_recipient_fanout=$queue_top_domain_sender ($queue_top_domain_count domains)"

# Append to the alert log (full detail kept locally).
if [ "$DRY_RUN" -eq 0 ]; then
    {
        echo "[$now] severity=$severity reasons=$reasons_str"
        printf '%s\n' "$metric_line"
        echo "top_sasl:"
        printf '%s\n' "$top_sasl"
        echo "---"
    } >> "$ALERT_FILE"
else
    printf '\n--- ALERT (dry-run) ---\n%s\n' "$alert_text"
fi

# ---------------------------------------------------------------------------
# Evidence snapshot (so the exact moment of the anomaly is preserved).
# ---------------------------------------------------------------------------
take_snapshot() {
    [ "$SNAPSHOT_ON_ALERT" -eq 1 ] || return 0
    [ -n "${QUEUE_SOURCE_CMD:-}" ] && return 0   # skip when fed from fixtures
    local ts d
    ts="$(date +%Y%m%d-%H%M%S)"
    d="$STATE_DIR/snapshots/$ts"
    mkdir -p "$d" || return 0
    printf '%s\n' "$metric_line" > "$d/metrics.txt"
    printf '%s\n' "$queue_raw"   > "$d/queue.txt"
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" logs --since="$SNAPSHOT_WINDOW" "$SMTP_SERVICE" ) \
        > "$d/smtp.log" 2>/dev/null || true
    ( cd "$COMPOSE_DIR" 2>/dev/null && "${_compose[@]}" logs --since="$SNAPSHOT_WINDOW" "$FRONT_SERVICE" ) \
        > "$d/front.log" 2>/dev/null || true
}
[ "$DRY_RUN" -eq 0 ] && take_snapshot

# ---------------------------------------------------------------------------
# Notify -- rate-limited by cooldown, but always on escalation.
# ---------------------------------------------------------------------------
should_notify() {
    local cur_rank last_epoch last_sev last_rank cooldown_s
    cur_rank="$(rank "$severity")"
    last_epoch=0; last_sev="ok"
    if [ -r "$STATE_DIR/notify-state" ]; then
        read -r last_epoch last_sev < "$STATE_DIR/notify-state" || true
        [ -n "$last_epoch" ] || last_epoch=0
        [ -n "$last_sev" ] || last_sev="ok"
    fi
    last_rank="$(rank "$last_sev")"
    cooldown_s=$(( ALERT_COOLDOWN_MINUTES * 60 ))
    # notify on escalation, or once the cooldown since the last notification elapsed
    if [ "$cur_rank" -gt "$last_rank" ] || [ $(( now_epoch - last_epoch )) -ge "$cooldown_s" ]; then
        return 0
    fi
    return 1
}

send_telegram() {
    if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then return 0; fi
    curl -fsS -m 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=${alert_text}" >/dev/null 2>&1 || true
}
send_slack() {
    [ -n "$SLACK_WEBHOOK_URL" ] || return 0
    local payload
    payload="$(printf '%s' "$alert_text" | sed ':a;N;$!ba;s/\\/\\\\/g;s/"/\\"/g;s/\n/\\n/g')"
    curl -fsS -m 15 -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"${payload}\"}" "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
}
send_command() {
    [ -n "$ALERT_COMMAND" ] || return 0
    printf '%s\n' "$alert_text" | sh -c "$ALERT_COMMAND" >/dev/null 2>&1 || true
}

if [ "$DRY_RUN" -eq 0 ] && should_notify; then
    send_telegram
    send_slack
    send_command
    printf '%s %s\n' "$now_epoch" "$severity" > "$STATE_DIR/notify-state" 2>/dev/null || true
fi

exit 0

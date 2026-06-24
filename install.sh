#!/usr/bin/env bash
#
# install.sh -- install / update / remove mailu-queue-tracker on a Mailu host.
#
#   sudo ./install.sh              # install or update, enable the 5-minute timer
#   sudo ./install.sh --no-enable  # install/update but do not start the timer
#   sudo ./install.sh --uninstall  # remove scripts/units; keep config and logs
#   sudo ./install.sh --purge      # remove everything incl. config, state, logs
#
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
SBIN_DIR="/usr/local/sbin"
LIB_DIR="/usr/local/lib/mailu-queue-watch"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG="/etc/mailu-queue-watch.conf"
STATE_DIR="/var/lib/mailu-queue-watch"

ENABLE=1
UNINSTALL=0
PURGE=0
LOG_FILE="/var/log/mailu-queue-watch.log"
ALERT_FILE="/var/log/mailu-queue-alerts.log"
for a in "$@"; do
    case "$a" in
        --no-enable) ENABLE=0 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) UNINSTALL=1; PURGE=1 ;;
        -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$a" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
have_systemd() { command -v systemctl >/dev/null 2>&1; }

if [ "$UNINSTALL" -eq 1 ]; then
    if have_systemd; then
        systemctl disable --now mailu-queue-watch.timer 2>/dev/null || true
    fi
    rm -f "$SBIN_DIR/mailu-queue-watch.sh" "$SBIN_DIR/mailu-queue-report.sh" \
          "$SBIN_DIR/mailu-front-ips.sh"
    rm -rf "$LIB_DIR"
    rm -f "$SYSTEMD_DIR/mailu-queue-watch.service" "$SYSTEMD_DIR/mailu-queue-watch.timer"
    if have_systemd; then systemctl daemon-reload || true; fi
    echo "Removed binaries, library and systemd units."
    if [ "$PURGE" -eq 1 ]; then
        rm -f "$CONFIG" "$LOG_FILE" "$ALERT_FILE"
        rm -rf "$STATE_DIR"
        echo "Purged config, default logs and state ($CONFIG, $STATE_DIR)."
        echo "If you set custom LOG_FILE/ALERT_FILE/STATE_DIR paths, remove those manually."
    else
        echo "Left in place (remove manually, or use --purge): $CONFIG, logs, $STATE_DIR"
    fi
    exit 0
fi

echo "Installing scripts to $SBIN_DIR ..."
for s in "$SRC"/bin/*.sh; do
    install -m 0755 "$s" "$SBIN_DIR/$(basename "$s")"
done

echo "Installing parsers to $LIB_DIR ..."
install -d -m 0755 "$LIB_DIR"
for a in "$SRC"/lib/*.awk; do
    install -m 0644 "$a" "$LIB_DIR/$(basename "$a")"
done

if [ -f "$CONFIG" ]; then
    echo "Keeping existing config $CONFIG"
else
    echo "Installing config $CONFIG (edit it: set COMPOSE_DIR and notification secrets)"
    install -m 0600 "$SRC/etc/mailu-queue-watch.conf.example" "$CONFIG"
fi

install -d -m 0750 "$STATE_DIR"

if have_systemd; then
    echo "Installing systemd units ..."
    install -m 0644 "$SRC/systemd/mailu-queue-watch.service" "$SYSTEMD_DIR/"
    install -m 0644 "$SRC/systemd/mailu-queue-watch.timer"   "$SYSTEMD_DIR/"
    systemctl daemon-reload
    if [ "$ENABLE" -eq 1 ]; then
        systemctl enable --now mailu-queue-watch.timer
        echo "Enabled mailu-queue-watch.timer (runs every 5 minutes)."
    else
        echo "Units installed. Enable with: systemctl enable --now mailu-queue-watch.timer"
    fi
else
    echo "systemd not found -- skipping units. Schedule mailu-queue-watch.sh via cron instead."
fi

cat <<EOF

Done. Next steps:
  1. Edit $CONFIG  (COMPOSE_DIR, thresholds, Telegram/Slack).
  2. Test once:    mailu-queue-watch.sh --config $CONFIG --print
  3. Watch:        tail -f /var/log/mailu-queue-watch.log /var/log/mailu-queue-alerts.log
EOF

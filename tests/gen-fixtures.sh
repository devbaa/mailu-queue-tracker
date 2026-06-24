#!/usr/bin/env bash
# Regenerate the test fixtures in tests/fixtures/. Run from anywhere.
# Fixtures are committed so tests are deterministic; rerun this only to change them.
set -euo pipefail
cd "$(dirname "$0")/fixtures"

# --- incident: `postqueue -j` JSON, one compromised sender fanning out -------
{
  for i in $(seq 1 60); do
    dom="honeypot-$(( i % 25 + 1 )).example"     # 25 distinct recipient domains
    printf '{"queue_name": "deferred", "queue_id": "4inc%03d", "arrival_time": 1718000000, "message_size": 2048, "forced_expire": false, "sender": "noreply@example.com", "recipients": [{"address": "victim%d@%s", "delay_reason": "host mx.%s said: 554 5.7.1 Message blocked using Spamhaus"}]}\n' "$i" "$i" "$dom" "$dom"
  done
  # a little legitimate traffic in parallel
  for i in 1 2 3; do
    printf '{"queue_name": "active", "queue_id": "4ok%03d", "arrival_time": 1718000100, "message_size": 800, "forced_expire": false, "sender": "billing@example.com", "recipients": [{"address": "customer%d@example.com"}]}\n' "$i" "$i"
  done
} > postqueue-incident.json

# --- incident: smtp log lines ------------------------------------------------
{
  for i in $(seq 1 30); do
    printf 'Jun 24 10:%02d:00 mail postfix/smtpd[111]: 4inc%03d: client=tor-exit.example[10.0.0.9], sasl_method=PLAIN, sasl_username=noreply@example.com\n' "$(( i % 60 ))" "$i"
  done
  for i in 1 2 3; do
    printf 'Jun 24 10:05:00 mail postfix/smtpd[111]: 4ok%03d: client=app.example[10.0.0.2], sasl_method=PLAIN, sasl_username=billing@example.com\n' "$i"
  done
  for i in $(seq 1 30); do
    printf 'Jun 24 10:%02d:01 mail postfix/smtp[222]: 4inc%03d: to=<victim%d@honeypot.example>, relay=mx.honeypot.example[203.0.113.7]:25, status=deferred (host mx.honeypot.example said: 554 5.7.1 blocked using Spamhaus reputation list)\n' "$(( i % 60 ))" "$i" "$i"
  done
  for i in $(seq 1 8); do
    printf 'Jun 24 10:06:%02d mail postfix/smtp[222]: 4bnc%03d: to=<x%d@blocklist.example>, status=bounced (blacklisted: listed on barracuda)\n' "$i" "$i" "$i"
  done
  for i in 1 2 3 4 5; do
    printf 'Jun 24 10:07:0%d mail postfix/smtp[222]: 4snt%03d: to=<ok%d@example.com>, status=sent (250 OK)\n' "$i" "$i" "$i"
  done
  printf 'Jun 24 10:08:00 mail postfix/smtpd[111]: warning: 10.0.0.9: too many errors after AUTH from tor-exit.example[10.0.0.9]: Recipient address rate limit exceeded\n'
} > smtp-incident.log

# --- quiet: healthy queue + logs --------------------------------------------
{
  printf '{"queue_name": "active", "queue_id": "4q001", "arrival_time": 1718000000, "message_size": 900, "forced_expire": false, "sender": "billing@example.com", "recipients": [{"address": "a@example.com"}]}\n'
  printf '{"queue_name": "active", "queue_id": "4q002", "arrival_time": 1718000001, "message_size": 900, "forced_expire": false, "sender": "billing@example.com", "recipients": [{"address": "b@example.org"}]}\n'
} > postqueue-quiet.json

{
  for i in 1 2 3 4 5; do
    printf 'Jun 24 09:0%d:00 mail postfix/smtpd[111]: 4q%03d: client=app.example[10.0.0.2], sasl_method=PLAIN, sasl_username=billing@example.com\n' "$i" "$i"
    printf 'Jun 24 09:0%d:01 mail postfix/smtp[222]: 4q%03d: to=<user%d@example.com>, status=sent (250 OK)\n' "$i" "$i" "$i"
  done
  printf 'Jun 24 09:06:00 mail postfix/smtp[222]: 4q099: to=<late@example.org>, status=deferred (connection timed out)\n'
} > smtp-quiet.log

# --- multi-sender: several accounts sending bulk at once (no rate-limit/spam) -
# Models the "compromised-account dump" pattern: 6 distinct noreply@ senders,
# ~12 submissions each, none dominating. Mirrors the real-world incident where
# Mailu's rate limiter rejected at RCPT so the queue stayed empty.
{
  for u in alpha bravo charlie delta echo foxtrot; do
    for i in $(seq 1 12); do
      printf 'Jun 24 11:%02d:%02d mail postfix/smtpd[700]: 4ms%s%02d: client=mailu_front_1[10.0.0.9], sasl_method=PLAIN, sasl_username=noreply@%s.example\n' "$i" "$i" "$u" "$i" "$u"
    done
  done
} > smtp-multisender.log

# --- front log: real client IPs behind XCLIENT (uses RFC5737 example IPs) ----
# 203.0.113.66 = attacker (auths as several noreply@ accounts); 198.51.100.20 =
# a legit user; 192.168.0.9 / 172.20.0.5 = internal proxy hops (must be hidden).
{
  for u in alpha bravo charlie alpha delta; do
    printf 'mailu_front_1  | 2026/06/22 21:09:47 [info] 30#30: *1 client login:"noreply@%s.example" while in http auth state, client: 203.0.113.66, server: 0.0.0.0:587, login: "noreply@%s.example"\n' "$u" "$u"
  done
  printf 'mailu_front_1  | 2026/06/22 21:10:00 [info] 30#30: *9 client login:"info@legit.example" while in http auth state, client: 198.51.100.20, server: 0.0.0.0:993, login: "info@legit.example"\n'
  printf 'mailu_front_1  | 2026/06/22 21:10:01 [info] 30#30: *9 client login:"info@legit.example" while in http auth state, client: 198.51.100.20, server: 0.0.0.0:993, login: "info@legit.example"\n'
  # internal hops that must NOT appear as "external" source IPs
  printf 'mailu_front_1  | 2026/06/22 21:10:02 upstream auth request to admin client: 192.168.0.9\n'
  printf 'mailu_front_1  | 2026/06/22 21:10:03 proxy connect to backend 172.20.0.5:25\n'
} > front.log

# --- incident: classic `postqueue -p` text listing (text-parser path) --------
cat > postqueue-incident.txt <<'TXT'
-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
4inc001        2048 Tue Jun 24 10:00:01  noreply@example.com
                         (host mx.honeypot-1.example said: 554 5.7.1 blocked using Spamhaus)
                                          victim1@honeypot-1.example

4inc002        2048 Tue Jun 24 10:00:02  noreply@example.com
                         (host mx.honeypot-2.example said: 554 5.7.1 blacklisted)
                                          victim2@honeypot-2.example

4inc003        2048 Tue Jun 24 10:00:03  noreply@example.com
                         (host mx.honeypot-3.example said: 554 blocked)
                                          victim3@honeypot-3.example

4ok001*         800 Tue Jun 24 10:05:00  billing@example.com
                                          customer1@example.com

4ok002*         800 Tue Jun 24 10:05:01  billing@example.com
                                          customer2@example.com

-- 7 Kbytes in 5 Requests.
TXT

echo "fixtures regenerated in $(pwd)"
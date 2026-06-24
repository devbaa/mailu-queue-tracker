# parse-queue.awk -- extract queue metrics from `postqueue -j` or `postqueue -p`.
#
# Auto-detects the input format:
#   * JSON  -- one JSON object per line (`postqueue -j`, Postfix >= 3.1). Robust.
#   * text  -- the classic `postqueue -p` mailq listing. Best-effort fallback.
#
# Emits `key=value` lines on stdout (parse with `read`, never `eval` -- the
# sender/recipient values are attacker-controlled):
#   queue_total                total messages in the queue
#   deferred_queue             messages in the deferred queue
#   queue_top_sender           envelope sender with the most queued messages
#   queue_top_sender_count     that sender's queued message count
#   queue_unique_domains       distinct recipient domains across the queue
#   queue_top_domain_sender    sender addressing the most distinct rcpt domains
#   queue_top_domain_count     that sender's distinct recipient-domain count
#
# Written for mawk compatibility: only match()/substr()/index()/split() are used
# (no gensub, no length(array) in conditionals).

BEGIN { fmt = "" }

# Return the first JSON string value for "key" in string s ("" if absent).
function jval(s, key,   p, rest, c, q1, q2) {
    p = index(s, "\"" key "\"")
    if (p == 0) return ""
    rest = substr(s, p + length(key) + 2)   # skip past the key and its closing quote
    c = index(rest, ":")
    if (c == 0) return ""
    rest = substr(rest, c + 1)
    q1 = index(rest, "\"")
    if (q1 == 0) return ""
    rest = substr(rest, q1 + 1)
    q2 = index(rest, "\"")
    if (q2 == 0) return ""
    return substr(rest, 1, q2 - 1)
}

function domain_of(addr,   at) {
    at = index(addr, "@")
    if (at == 0) return ""
    return tolower(substr(addr, at + 1))
}

# Record one recipient domain, both globally and against its sender.
function add_rcpt(sender, addr,   dom) {
    dom = domain_of(addr)
    if (dom == "") return
    if (!((dom) in domains_global)) {
        domains_global[dom] = 1
        unique_domains++
    }
    if (sender == "") sender = "<>"
    if (!((sender SUBSEP dom) in sender_dom_seen)) {
        sender_dom_seen[sender SUBSEP dom] = 1
        sender_dom_count[sender]++
    }
}

# ---- format detection on the first non-blank line --------------------------
fmt == "" {
    probe = $0
    sub(/^[ \t]+/, "", probe)
    if (probe == "") next
    if (substr(probe, 1, 1) == "{") fmt = "json"
    else fmt = "text"
}

# ---- JSON mode -------------------------------------------------------------
fmt == "json" {
    if (index($0, "{") == 0) next
    total++

    if (match($0, /"queue_name"[ \t]*:[ \t]*"deferred"/)) deferred++

    sender = jval($0, "sender")
    skey = (sender == "" ? "<>" : sender)
    sender_count[skey]++

    # walk every "address":"..." occurrence on the line
    rest = $0
    while ((p = index(rest, "\"address\"")) > 0) {
        rest = substr(rest, p + 9)        # past "address"
        c = index(rest, ":");  if (c == 0) break
        rest = substr(rest, c + 1)
        q1 = index(rest, "\""); if (q1 == 0) break
        rest = substr(rest, q1 + 1)
        q2 = index(rest, "\""); if (q2 == 0) break
        add_rcpt(skey, substr(rest, 1, q2 - 1))
        rest = substr(rest, q2 + 1)
    }
    next
}

# ---- text mode (`postqueue -p`) -------------------------------------------
# (mawk lacks {n,} interval regexes, so these patterns avoid them.)
fmt == "text" && /^Mail queue is empty/ { next }
# Entry line: starts with a queue id (hex/base-52), optional */! status flag.
fmt == "text" && /^[0-9A-Za-z][0-9A-Za-z]+[*!]?[ \t]/ {
    total++
    cur_sender = $NF                       # sender is the last field on the id line
    sender_count[cur_sender]++
    next
}
# Deferred reason line, e.g. "(host x said: 554 blocked ...)".
fmt == "text" && /^[ \t]*\(/ {
    deferred++
    next
}
# Recipient line: indented, contains an address, not a reason line.
fmt == "text" && /^[ \t]+/ && /@/ {
    add_rcpt(cur_sender, $NF)
    next
}

END {
    top_sender = "none"; top_sender_count = 0
    for (s in sender_count) {
        if (sender_count[s] > top_sender_count) {
            top_sender_count = sender_count[s]; top_sender = s
        }
    }
    top_dom_sender = "none"; top_dom_count = 0
    for (s in sender_dom_count) {
        if (sender_dom_count[s] > top_dom_count) {
            top_dom_count = sender_dom_count[s]; top_dom_sender = s
        }
    }
    printf "queue_total=%d\n", total + 0
    printf "deferred_queue=%d\n", deferred + 0
    printf "queue_top_sender=%s\n", top_sender
    printf "queue_top_sender_count=%d\n", top_sender_count + 0
    printf "queue_unique_domains=%d\n", unique_domains + 0
    printf "queue_top_domain_sender=%s\n", top_dom_sender
    printf "queue_top_domain_count=%d\n", top_dom_count + 0
}

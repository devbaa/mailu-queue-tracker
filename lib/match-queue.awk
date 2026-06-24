# match-queue.awk -- print the queue_id of every `postqueue -j` message whose
# sender (default) or a recipient (field=recipient) exactly equals `addr`.
#
# -v addr=<email>            address to match (compared case-insensitively)
# -v field=sender|recipient  which envelope field to match (default sender)
#
# Exact match, so "example.com" does NOT match "noreply@mx.example.com".
# mawk-compatible (index/substr/tolower only).

function jval(s, key,   p, rest, c, q1, q2) {
    p = index(s, "\"" key "\"")
    if (p == 0) return ""
    rest = substr(s, p + length(key) + 2)
    c = index(rest, ":");  if (c == 0)  return ""
    rest = substr(rest, c + 1)
    q1 = index(rest, "\""); if (q1 == 0) return ""
    rest = substr(rest, q1 + 1)
    q2 = index(rest, "\""); if (q2 == 0) return ""
    return substr(rest, 1, q2 - 1)
}

BEGIN { addr = tolower(addr); if (field == "") field = "sender" }

{
    if (index($0, "{") == 0) next
    qid = jval($0, "queue_id")
    if (qid == "") next

    hit = 0
    if (field == "recipient") {
        rest = $0
        while ((p = index(rest, "\"address\"")) > 0) {
            rest = substr(rest, p + 9)
            c = index(rest, ":");  if (c == 0) break
            rest = substr(rest, c + 1)
            q1 = index(rest, "\""); if (q1 == 0) break
            rest = substr(rest, q1 + 1)
            q2 = index(rest, "\""); if (q2 == 0) break
            if (tolower(substr(rest, 1, q2 - 1)) == addr) { hit = 1; break }
            rest = substr(rest, q2 + 1)
        }
    } else {
        if (tolower(jval($0, "sender")) == addr) hit = 1
    }
    if (hit) print qid
}

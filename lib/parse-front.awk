# parse-front.awk -- surface real client IPs from the Mailu `front` log (or any
# log) and correlate each with the usernames seen on the same line.
#
# The Mailu front proxies submission/IMAP/POP to the backend with XCLIENT, so
# the `smtp` log only ever shows the front's address. The real external client
# IP is in the front log. This extracts IPv4 addresses, drops private/internal
# ranges (unless incl=1), and tallies per-IP line counts plus the usernames
# that authenticated from each.
#
# Emits TSV: <count>\t<ip>\t<distinct_users>\t<sample_users>
# (sorting/formatting is done by the caller). mawk-compatible.
#
# -v incl=1   include private/internal IPs (default: hide them)
# -v excl="a,b"  comma-separated IPs to always drop (e.g. the front's own IP)
#
# Note: IPv4 only -- IPv6 is intentionally not auto-extracted because it cannot
# be told apart from syslog timestamps (HH:MM:SS) without false positives.

function is_private(ip) {
    return (ip ~ /^10\./ || ip ~ /^127\./ || ip ~ /^192\.168\./ || ip ~ /^169\.254\./ ||
            ip ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ || ip ~ /^0\./ || ip ~ /^255\./)
}
function valid4(ip,   p, n, i) {
    n = split(ip, p, ".")
    if (n != 4) return 0
    for (i = 1; i <= 4; i++) {
        if (p[i] !~ /^[0-9]+$/) return 0
        if (p[i] + 0 > 255) return 0
    }
    return 1
}

BEGIN {
    if (excl != "") { m = split(excl, ee, ","); for (i = 1; i <= m; i++) exclude[ee[i]] = 1 }
}

{
    # best-effort username on this line (first recognised form wins)
    user = ""
    if (match($0, /sasl_username=[^,[:space:]]+/))      user = substr($0, RSTART + 14, RLENGTH - 14)
    else if (match($0, /user=<[^>]+>/))                 user = substr($0, RSTART + 6,  RLENGTH - 7)
    else if (match($0, /login:[ \t]*"[^"]+"/)) {
        user = substr($0, RSTART, RLENGTH); sub(/^login:[ \t]*"/, "", user); sub(/"$/, "", user)
    }
    else if (match($0, /login=[^,[:space:]]+/))         user = substr($0, RSTART + 6, RLENGTH - 6)

    s = $0
    while (match(s, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
        ip = substr(s, RSTART, RLENGTH)
        s  = substr(s, RSTART + RLENGTH)
        if (!valid4(ip))            continue
        if (ip in exclude)          continue
        if (!incl && is_private(ip)) continue
        ipcount[ip]++
        if (user != "") {
            key = ip SUBSEP user
            if (!(key in seen)) {
                seen[key] = 1; nusers[ip]++
                if (scount[ip] < 3) {
                    sample[ip] = (sample[ip] == "" ? user : sample[ip] "," user); scount[ip]++
                }
            }
        }
    }
}

END {
    for (ip in ipcount)
        printf "%d\t%s\t%d\t%s\n", ipcount[ip], ip, nusers[ip] + 0, (sample[ip] == "" ? "-" : sample[ip])
}

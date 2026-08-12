# Diagnosis Playbook

Load this reference only for status-code, record-existence, CNAME, or record-type interpretation. Keep every conclusion tied to the exact qname, qtype, resolver, transport, vantage, role, time, and probe ID.

## Status Semantics

| Result | Protocol fact | Decision rule |
|---|---|---|
| `NOERROR` with requested RRset | Name and type answered | Follow CNAMEs and compare the final RRset and TTLs |
| `NOERROR` with no requested RRset | NODATA: name exists, requested type absent | Confirm the same qtype at authority; do not call it NXDOMAIN |
| `NXDOMAIN` | Queried name does not exist in that response | Check authoritative result and negative-cache SOA TTL |
| `SERVFAIL` | Server could not complete the query | Branch to delegation, DNSSEC, reachability, or transport evidence; do not infer which one |
| `REFUSED` | Server policy rejected the query | Check server role, source scope, recursion policy, and whether the server is authoritative |
| Timeout/no parse | No usable response observed | Treat as transport or tooling evidence, never as an RCODE |

`NXDOMAIN` applies to the queried name, while NODATA applies to the requested type. A stale negative cache can outlive a correction until its negative TTL expires. Compare cache age and authoritative data before attributing a mismatch.

## Record-Type Distinctions

| Type | What to verify | Common trap |
|---|---|---|
| A/AAAA | IPv4/IPv6 address set and TTL | Different address families are not conflicting answers |
| CNAME | Entire chain, loop, terminal type, TTL | A CNAME loop or missing terminal RRset looks like an address failure |
| MX | Preference plus exchange host; then A/AAAA separately | Treating the exchange hostname as an address |
| TXT | Ordered character strings as returned | Joining or reordering chunks before comparison |
| SRV | Priority, weight, port, target | Comparing only the target |
| CAA | Flags, tag, value | Ignoring flag/tag differences |
| PTR | Reverse owner under `in-addr.arpa`/`ip6.arpa` | Querying the address as a forward name |
| NS | Delegation set and authoritative answer | Confusing parent delegation with child apex NS |
| SOA | Primary, serial, timers, negative-cache field | Treating serial mismatch as immediate proof of outage |
| DS/DNSKEY/RRSIG | Chain link, key tag/algorithm, signature time | Treating DNSSEC data presence as successful validation |

## Decision Rules

1. Normalize the qname, trailing dot, case, qtype, RCODE, and answer tuples before comparing.
2. Compare identical qname/qtype cohorts. Do not compare A with AAAA or an alias with its terminal name.
3. If recursive and authoritative answers differ, repeat both from the same vantage and record TTLs; cache and GeoDNS remain alternatives.
4. If each vantage is internally stable but differs across vantages, label regional/GeoDNS behavior. GeoDNS differences are not proof of hijacking.
5. If evidence is contradictory or lacks probe IDs, report the contradiction and stop short of attribution.

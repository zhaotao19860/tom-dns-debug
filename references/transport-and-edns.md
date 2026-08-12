# Transport and EDNS

Load this reference only when UDP/TCP results differ, responses truncate, EDNS behavior changes, MTU or address-family reachability is suspected, or injection is being considered.

Every command below is user-executed only after review, except the trace shape described under "Reading A Delegation Trace". The skill may generate a bounded comparison, but it must not execute anything outside that allowlist because those argv shapes are not accepted by `run_probe`.

## Controlled Comparisons

| Dimension | Read-only pair | Decision rule |
|---|---|---|
| UDP vs TCP | `dig +time=2 +tries=1 name.example A` / add `+tcp` | Keep qname, qtype, resolver, and vantage identical |
| EDNS vs no EDNS | `dig +time=2 +tries=1 +bufsize=1232 name.example A` / replace with `+noedns` | Record payload size, TC flag, RCODE, answer, and timeout separately |
| IPv4 vs IPv6 path | Add `-4` / `-6` to otherwise identical queries | This changes network path, not qtype; A and AAAA are separate dimensions |
| Small vs DNSSEC-sized | Compare a small A query with `+dnssec` DS/DNSKEY evidence | Size correlation is a clue, not proof of MTU failure |

These commands are manual read-only branch probes. Do not pass unsupported argv to `run_probe`, do not execute them through another tool, and do not remove its safety validation. Wait for user-supplied output.

## Reading A Delegation Trace

`dig +trace +time=2 +tries=2 A name.example` is accepted by `run_probe` and runs under `--trace` or `--baseline`. Its output is not one answer but one referral block per level, each preceded by the server that answered it.

| In the output | What it means | Decision rule |
|---|---|---|
| First block of NS records | The root's referral, from a root server | Absence here is a local reachability or filtering problem, not a zone problem |
| Each following block | One step down: `com`, then `example.com` | The hop where blocks stop is the hop to investigate; earlier hops are proven reachable |
| `;; Received … from <address>#53` | Which server produced that block | Record it as the hop's `from_server`; a hop answered by an unexpected address is a clue, not proof |
| A block of only NSEC or RRSIG records | The server is proving the next label does not exist | Not a delegation: the hop carries `referral: false` and no zone, and the NSEC owner name is a neighbour in sort order, never a zone the walk reached |
| Final block carrying the answer | The zone's own servers answered | A trace that ends in a referral loop or NXDOMAIN names the failing level |

A trace uses its own longer timeout because it makes many queries in sequence; a trace that exceeds the layer budget is recorded in `skipped`, and the remaining layers still stand on their own.

## Symptom Map

| Observation | Supported interpretation | Required next comparison |
|---|---|---|
| UDP has TC and TCP succeeds | Normal truncation/fallback path is available | Verify the client actually retries over TCP |
| UDP times out; TCP succeeds | UDP filtering, fragmentation, EDNS, or path issue is plausible | Compare EDNS sizes and another resolver/path |
| EDNS fails; `+noedns` works | EDNS intolerance or size/path issue is plausible | Repeat and compare RCODE versus timeout |
| IPv6 path fails; IPv4 works | Address-family path difference exists | Keep resolver endpoint and query identity explicit |
| UDP answer differs from TCP | Transport divergence exists | Repeat; compare authority and an independent vantage |
| One large response fails | MTU/fragmentation is plausible | Compare smaller EDNS size and TCP; do not assert MTU without stable evidence |

## Decision Rules

1. Change one dimension at a time and repeat each observation with unique probe IDs.
2. Treat timeout, FORMERR, BADVERS, NOTIMP, truncation, and answer divergence as different facts.
3. A UDP/TCP mismatch can result from cache timing, middleboxes, resolver behavior, or manipulation. Suspected injection requires stable repetition plus comparable authoritative or independent-vantage support.
4. Regional or hijacking claims require stable comparable multi-vantage evidence. GeoDNS differences are not proof of hijacking.
5. Anycast location is approximate, and IPv4/IPv6 may reach different Anycast nodes.
6. Never capture packets under this skill. List controlled packet capture only as a separately authorized future check.

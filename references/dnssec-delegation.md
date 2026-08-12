# DNSSEC and Delegation

Load this reference only when SERVFAIL, parent/child NS disagreement, missing Glue, lame authority, or DS/DNSKEY/RRSIG evidence makes delegation or DNSSEC material.

Every command below is user-executed only after review, except the shapes listed under "What The Collector Already Does". The skill may generate a bounded command and explain name exposure, but it must not execute anything outside that allowlist, because those argv shapes are not accepted by `run_probe`.

## What The Collector Already Does

These four shapes are accepted by `run_probe` and run automatically under `--dnssec` or `--baseline`. Only the exact form is accepted; a reordered or extended variant is rejected.

| Automatic query | Purpose |
|---|---|
| `dig +dnssec +time=2 +tries=2 DS zone.example` | Does the parent register a signature fingerprint |
| `dig +dnssec +time=2 +tries=2 DNSKEY zone.example` | Which keys does the child publish |
| `dig +dnssec +time=2 +tries=2 A name.zone.example [@resolver]` | Does the answer arrive signed and flagged AD |
| `dig +dnssec +cd +time=2 +tries=2 A name.zone.example [@resolver]` | Does the same answer arrive once validation is disabled |
| `dig +norecurse +time=2 +tries=2 A name.zone.example @server` | The zone's own answer, past every cache (`--authoritative`) |
| `dig +trace +time=2 +tries=2 A name.zone.example` | Which hop from the root fails (`--trace`) |

The verdict recorded in `dnssec.validation` follows one table and nothing else:

| DS present | `+dnssec` result | `+cd` result | Verdict | Meaning |
|---|---|---|---|---|
| yes | NOERROR with AD | — | `secure` | Signed and validated by a checking resolver |
| no | NOERROR | — | `insecure` | Unsigned; the owner's choice, not a fault |
| yes | SERVFAIL | NOERROR | `bogus` | Validation failed; a checking resolver returns nothing |
| any | AD absent without SERVFAIL, or DS unknown | any | `indeterminate` | Report as unverified; name the three possible causes, do not guess |

A local resolver that does not validate can never produce `secure` on its own; the cross-check goes through a validating public resolver, and the report says which one decided.

## Delegation Evidence

| Layer | Read-only query | Record as |
|---|---|---|
| Parent delegation | `dig +time=2 +tries=1 +norecurse zone.example NS @parent-server` | `role=parent_delegation`, NS set, Glue from additional section |
| Child apex | `dig +time=2 +tries=1 +norecurse zone.example NS @child-server` | `role=child_authority`, AA flag, NS set |
| Each authority | `dig +time=2 +tries=1 +norecurse name.zone.example A @child-server` | `role=authoritative`, RCODE, AA flag, answer |
| SOA consistency | `dig +time=2 +tries=1 +norecurse zone.example SOA @child-server` | Per-server serial and timers |

Use validated literal server addresses or already-observed NS names. These branch commands are manual read-only queries; their `+tries=1` form and argument order sit outside the allowlist deliberately, so do not pass them to `run_probe`, whose allowlist is intentionally narrower. Wait for the user to return selected output before recording an observation.

Glue is needed when an in-bailiwick nameserver name cannot be reached without resolving through the delegated zone. Compare parent additional-section Glue with independently resolved server addresses. Missing optional out-of-bailiwick additional data is not missing Glue.

A server is lame for the tested zone only when it is delegated but does not answer authoritatively for that zone. Timeout alone does not prove lame delegation; distinguish reachability, REFUSED, SERVFAIL, and a non-authoritative NOERROR response.

## DNSSEC Chain

| Link | Read-only query | Decision rule |
|---|---|---|
| Parent DS | `dig +dnssec +time=2 +tries=1 zone.example DS @parent-server` | Record DS key tag, algorithm, digest type/value |
| Child DNSKEY | `dig +dnssec +time=2 +tries=1 zone.example DNSKEY @child-server` | Match candidate key tag/algorithm; presence alone is not validation |
| Signed RRset | `dig +dnssec +time=2 +tries=1 name.zone.example A @child-server` | Record RRset, RRSIG signer, inception, expiration |
| Validating resolver | Same qname/qtype at the configured validator | Record RCODE, AD/CD behavior only if explicitly observed |

## Decision Rules

1. Start at the parent delegation. Compare the parent NS set, Glue, and child apex NS set before diagnosing the resolver.
2. For DNSSEC, establish DS -> DNSKEY -> RRSIG continuity and check signature time against a known system clock. Unknown clock accuracy is a limitation.
3. A validating SERVFAIL plus a successful checking-disabled response is a DNSSEC clue, not the broken link. Identify the specific DS/DNSKEY/RRSIG mismatch before naming it.
4. No DS means an unsigned delegation unless policy evidence says otherwise; it is not automatically a failure.
5. Record each authority separately. Never collapse contradictory servers into one observation.
6. Never edit zones, reload servers, clear caches, restart daemons, read protected logs, or use privileged diagnostics.

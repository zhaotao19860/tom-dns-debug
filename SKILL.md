---
name: tom-dns-debug
description: Use when checking DNS health or diagnosing NXDOMAIN, NODATA, SERVFAIL, REFUSED, timeout, DNS hijacking, poisoning, interception, resolver disagreement, regional anomalies, or local-versus-authoritative differences on Linux, macOS, Windows, or Kubernetes.
---

# DNS Debug

Diagnose DNS with bounded local read-only evidence. Separate protocol facts from hypotheses, preserve provenance, and make the smallest defensible claim.

## Safety And Session Notice

Before collection, give a session notice containing:

- Normalized target.
- Expected duration: total deadline and per-command timeout.
- Concrete query scope: record types, samples, UDP/TCP, local observations, and resolver IPs from `build_probe_plan`.
- Whether public resolvers are included or excluded.
- Which names leave this machine and to whom, when remote observation is requested.
- Exact output directory.
- No configuration or system changes: no elevation, cache clearing, restart, capture, or mutation.
- No automatic upload or transmission; artifacts stay local until the user controls a handoff.

The notice is consent for that stated scope; proceed without a second confirmation. Before an internal, single-label, `.local`, RFC 1918, or otherwise private name reaches a public resolver, give an internal-name exposure warning. Prefer the configured resolver unless public comparison is material.

Never use sudo. Never modify configuration. Never clear caches. Never restart services. Never capture packets. Packet capture requires separate authorization outside this skill. Never read protected logs, request credentials, install packages, call vendor APIs except the disclosed remote-observation endpoint, or use external automation. No upload by the skill.

Remote observation is the only outbound step. It needs both `--regions` and `--acknowledge-remote-query`, sends only the queried name and record type to `api.globalping.io`, and never sends collected evidence, resolver addresses, or search domains. Internal, single-label, `.local`, and RFC 1918 names are refused even when acknowledged. `safety[]` records `remote_query_disclosure` either way, so the bundle always states whether anything left this machine.

Automatic execution is limited to `collect_evidence` and argv accepted by `run_probe`. Unsupported commands are user-executed only after review; generate them, explain disclosure and scope, and wait for pasted output.

## Run

### 1. Normalize And Scope

Record the symptom, time window, affected client, expected result, network context, resolver, region, VPN, split DNS, DoH, container, and Kubernetes context when known. A URL supplies only its hostname.

Use raw input only as the immediate argument to `normalize_target`:

```python
raw_input = user_supplied_target
normalized = normalize_target(raw_input)
del raw_input
probe_target = normalized["hostname"] or normalized["ip"]
input_was_url = normalized["is_url"]
```

Retain only `probe_target` and non-sensitive normalized fields. Never store or repeat URL-only material. Never pass the normalized mapping to `collect_evidence(probe_target, options)`.

Run `detect_capabilities` and `build_probe_plan` before the session notice. Default limits are five seconds per command and twenty seconds total.

### 2. Choose A Profile

- Specific failure: query the implicated `A`, `AAAA`, `NS`, or `SOA` type. Distinguish NXDOMAIN, NODATA, SERVFAIL, and REFUSED.
- Generic health check: use `--health-check`; it covers A/AAAA, CNAME results, NS, and SOA with two samples over UDP/TCP where supported.
- Full picture: use `--baseline` for all five layers below. Layers run concurrently under one total budget, so `started_at` values overlap; each layer keeps its own deadline and anything unrun is recorded in `skipped`.
- MX, TXT, SRV, CAA, PTR, and RRSIG remain manual unless an allowlisted collector supports them.

| Layer | Decision it settles | Flag |
| --- | --- | --- |
| Local resolver | what this machine actually resolves now | always on |
| DNSSEC | signed or not, valid or bogus, checked or not | `--dnssec` |
| Public DNS | whether 8.8.8.8, 180.76.76.76, and 114.114.114.114 agree | `--public-resolvers` |
| Delegation | which hop from the root fails | `--trace` |
| Authoritative | the zone's own answer, past every cache | `--authoritative` |
| Remote observation | what other countries resolve; outbound, opt-in twice | `--regions CN,US,DE` |

Specific example:

```bash
python3 scripts/dns_probe.py --target "$probe_target" --output-dir "$output_dir" --record-type A --samples 2 --timeout 5 --no-public-resolvers
```

Health example:

```bash
python3 scripts/dns_probe.py --target "$probe_target" --output-dir "$output_dir" --health-check --timeout 5 --no-public-resolvers
```

Baseline example:

```bash
python3 scripts/dns_probe.py --target "$probe_target" --output-dir "$output_dir" --baseline
```

Use repeated `--resolver IP` only for resolver comparison named in the notice. For a disclosed internal target and explicit public resolver, add `--acknowledge-internal-public-query` only after the warning.

Remote observation, only for a public name and only after the notice names the host and the regions:

```bash
python3 scripts/dns_probe.py --target "$probe_target" --output-dir "$output_dir" --baseline --regions US,DE --acknowledge-remote-query
```

Then analyze:

```bash
python3 scripts/dns_analyze.py --input "$output_dir/dns-debug-report.json" --output "$output_dir/dns-debug-report.md" --finalize-bundle
```

The importable module interfaces are `normalize_target`, `detect_capabilities`, `build_probe_plan`, `run_probe`, `collect_evidence`, `write_bundle`, `compare_regional_answers`, `classify_evidence`, and `render_report`. Resolve scripts relative to this `SKILL.md`; do not copy or install them.

### 3. Handle Missing Tools

For missing supported tools, use the available supported fallback automatically. If no supported tool exists or there is no terminal, still collect environment and skipped metadata, then generate the minimal OS-specific user-run command sheet. Record every skipped reason; do not install anything. Convert returned manual output into the same evidence schema.

### 4. Load Only The Needed Reference

- Load when status codes or record meaning is central: [diagnosis playbook](references/diagnosis-playbook.md).
- Load when delegation, Glue, lame authority, DS/DNSKEY/RRSIG, or DNSSEC is implicated: [DNSSEC and delegation](references/dnssec-delegation.md).
- Load when UDP/TCP, truncation, EDNS, MTU, IPv4/IPv6, timeout, or injection is implicated: [transport and EDNS](references/transport-and-edns.md).
- Load when local resolver behavior, Linux, macOS, Windows, BIND, Unbound, dnsmasq, systemd-resolved, CoreDNS, Kubernetes, VPN, split DNS, DoH, or multi-interface behavior is implicated: [local and platform](references/local-and-platform.md).
- Before classification or reporting, load [evidence and report contract](references/evidence-and-report.md).

### 5. Analyze Conservatively

Preserve `schema_version`, `probes`, `skipped`, `safety`, and `findings`. Each finding keeps `supporting_probe_ids`, `contradictory_probe_ids`, and `next_checks`; every factual claim needs an evidence citation.

A stable local `NOERROR` result can confirm only the tested qname/qtype/resolver/vantage. Regional claims require comparable repeated evidence from two vantage labels. GeoDNS/CDN variation is not proof of hijacking. Resolver-versus-authoritative or UDP-versus-TCP divergence is a clue, not proof. Anycast and inferred geography are approximate.

Remote records live under `remote_observations` with a pinned resolver and a country vantage, and face the same comparison rule as local ones. DNSSEC verdicts are `secure`, `insecure` (unsigned, not a fault), `bogus`, or `indeterminate`; report the last one as unverified rather than guessing.

### 6. Report And Handoff

Produce the Chinese report at `dns-debug-report.md`, state confirmed, high probability, or unverified, and keep advice non-mutating. Manually review all artifacts.

After local privacy review, the user may choose to paste or share selected redacted content. Explain that sharing may expose names, addresses, topology, and resolver details. Never upload or send automatically.

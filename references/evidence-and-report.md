# Evidence and Report Contract

Load this reference before classification, report generation, or evidence handoff.

## Evidence Schema

Keep schema version `1.0` additive. Never guess unknown fields.

| Field | Decision contract |
|---|---|
| `schema_version`, `collected_at`, `redaction` | Preserve collector values and final redaction state. |
| `target`, `environment`, `resolvers` | Retain only normalized target and collection context. |
| `collection_scope` | Record profile, record types, sample count, the layers actually run, and the concurrency note. |
| `analysis_scope` | Record whether regional analysis was requested, plus `layers` and `regions`. |
| `probes` | Preserve stable ID, argv, qname, qtype, resolver, transport, role, layer, sample, timing, output, parser state, and errors. |
| `skipped` | Record every unrun branch, reason, and reviewed manual command when available. |
| `safety` | Preserve public-query, internal-name, and remote-query exposure decisions. |
| `observations` | Store normalized manual, authoritative, or remote-vantage evidence. |
| `remote_observations` | Store remote-vantage records only; present only when a remote measurement returned records. |
| `findings` | Add analyzer output only after classification. |

Manual observations use: `id`, `qname`, `qtype`, `status`, `answers`, `ttls`, `resolver`, `transport`, `vantage`, and `role`; add `argv`, output, error, DNSSEC, EDNS, nameservers, and timestamps only when known.

Probes run concurrently, so `started_at` values overlap and are not a serial timeline; each probe's own `duration_ms` is the only per-query timing. Each layer holds a separate deadline, and a layer that runs out of budget leaves its remaining queries in `skipped` with the reason stated.

## Layers And Roles

| Layer | Role recorded | Settles |
|---|---|---|
| `local` | `local`, `recursive` | What this machine resolves now |
| `dnssec` | `recursive` | Signed or not, valid or bogus, checked or not |
| `public` | `recursive` | Whether the named public resolvers agree |
| `trace` | `trace` | Which hop from the root fails; hops carry `level`, `zone`, `nameservers`, `from_server` |
| `authoritative` | `authoritative`, `child_authority`, `parent_delegation` | The zone's own answer, past every cache |
| `regional` | `recursive` | What other countries resolve |

The role is carried by the probe plan, never inferred at analysis time: comparisons between a resolver and an authority depend on it.

## Remote Observation

| Contract item | Rule |
|---|---|
| Trigger | Both `--regions` and `--acknowledge-remote-query`; either alone sends nothing |
| Sent | Only the queried name and record type; never command output, resolver addresses, or search domains |
| Refused outright | Internal, single-label, `.local`, and RFC 1918 names, even when acknowledged |
| Record shape | `layer: regional`, `role: recursive`, `vantage`: country code, `resolver`: the pinned resolver, plus `probe_location` |
| Comparability | Two probes per country and one pinned resolver, so each country has a stable answer to compare |
| Disclosure | `safety[]` always carries `remote_query_disclosure` with `sent`, `endpoint`, `regions`, and `sent_fields`, whether or not anything was sent; a refusal adds `reason_code` so the report states the real reason |
| Failure | A failed or timed-out measurement is a skipped layer with a stated reason; it never changes the local conclusion |

## Collection Profiles

| User intent | Automatic decision |
|---|---|
| Specific failure or record | Query the stated `A`, `AAAA`, `NS`, or `SOA` type. Use two samples when intermittency is plausible. |
| Generic DNS health check | Use the health profile: `A`, `AAAA`, `NS`, and `SOA`; two independent samples; UDP and TCP where supported. A responses also preserve the CNAME chain. |
| Full baseline | Run the five layers above in one pass: local, DNSSEC, public resolvers, delegation trace, authoritative. |
| MX, TXT, SRV, CAA, PTR, RRSIG | Generate a reviewed user-run command unless a future allowlisted collector explicitly supports it. |
| Public comparison | Use only resolver IPs declared in the session notice. Standard DNS queries are allowed; vendor APIs are not needed for it. |
| Direct authoritative or trace check | Automatic under `--authoritative` and `--trace`. Any other shape stays user-executed only after review. |
| Other-country comparison | Only under both remote-observation switches, and never for an internal name. |

## Classification

Evidence precedence:

1. Explicit RCODE and parsed answer facts.
2. Direct authoritative evidence for identical qname/qtype and vantage.
3. Stable repeated recursive evidence with matching dimensions.
4. Timing and environment clues, labeled as hypotheses.

Every finding keeps `category`, `severity`, `confidence`, `status`, `summary`, `supporting_probe_ids`, `contradictory_probe_ids`, and `next_checks`.

`resolution_succeeded` is scoped, not global: matching non-empty `NOERROR` samples over UDP/TCP or independent repeats can confirm only that qname/qtype/resolver/vantage combination. NODATA is not NXDOMAIN. A successful recursive response does not prove authoritative, DNSSEC, regional, HTTP, or application health.

Run regional comparison only when a region label, remote vantage, or explicit regional analysis request exists. A claim needs two vantage labels, repeated unique probe IDs, identical qname/qtype/resolver class/transport/role, and a close time window. GeoDNS/CDN consistency, resolver-versus-authoritative divergence, and UDP-versus-TCP divergence are clues, not proof of hijacking. Anycast and resolver egress locations are approximate.

A DNSSEC verdict maps to exactly one category:

| Verdict | Category | Status |
|---|---|---|
| `secure` | `dnssec_valid` | confirmed |
| `insecure` | `dnssec_unsigned` | confirmed; unsigned is the owner's choice, never a fault |
| `bogus` | `dnssec_validation_failure` | confirmed |
| `indeterminate` | `dnssec_indeterminate` | unverified; state the possible causes and give a manual check |

## Chinese Report

Call `classify_evidence`, then `render_report(..., language="zh-CN")`. Any other language raises. The section order is fixed:

```markdown
# DNS 诊断报告

**域名**：…　**时间**：…　**用时**：…　**查询次数**：…

## 结论
## 检查项一览
## 查到了什么
## 问题出在哪
## 没查到的部分
## 分享前请注意
## 接下来可以做什么
```

`问题出在哪` is rendered only when a non-normal finding exists; successful resolution and missing evidence are never causes. Every other section is always present.

The report is written for a reader who does not know the protocol: no `key=value` strings, no nested brackets, no probe IDs, no raw JSON. Addresses go in lists, paired facts in tables. `检查项一览` carries one row per layer with an icon whose meaning is stated below the table: ✅ confirmed, ❌ confirmed problem, ⚠️ high probability, ❓ unverified, ⚪ not applicable. The headline in `结论` must agree with the rows actually rendered. Findings cite how many queries observed the behaviour, not which ones. `分享前请注意` names the internal addresses and names that actually appear in this report, not a generic caution, and states whether anything was sent to a remote service. The report ends by pointing at `dns-debug-report.json` for the raw records.

Finalize with `--finalize-bundle`, then manually review every artifact for internal names, addresses, topology, free-form output, and secrets. Sharing can expose those details. The skill never uploads or sends automatically, and the one remote step sends only the queried name and record type.

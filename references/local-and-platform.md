# Local and Platform Checks

Load this reference only when local resolver selection, OS behavior, a named DNS service, VPN/split DNS/DoH, multiple interfaces, containers, or Kubernetes may explain the symptom.

Every command below is user-executed only after review. The skill may generate a minimal command sheet, but it must not execute any of these commands because their argv shapes are not accepted by `run_probe`. The user runs only selected commands available without elevation and returns only selected output.

## Minimal OS Commands

| Platform | Read-only command | Evidence purpose |
|---|---|---|
| Linux with systemd-resolved | `resolvectl status` | Per-link resolvers, search/routing domains, default route |
| Linux lookup | `resolvectl query name.example` or `getent ahosts name.example` | Local resolver/NSS result |
| macOS resolver state | `scutil --dns` | Scoped resolvers, search domains, interface order |
| macOS lookup | `dscacheutil -q host -a name name.example` | Local resolver result |
| Windows resolver state | `ipconfig /all` and `Get-DnsClientServerAddress` | Per-adapter DNS servers and suffixes |
| Windows lookup | `Resolve-DnsName name.example -Type A -DnsOnly` | Local DNS result and server response |

If no terminal or supported probe tool exists, provide only the two rows for the user's OS as a user-run command sheet and ask for pasted local output, not an upload. Do not install a tool or execute a substitute. Convert returned output to the same evidence schema used by `observations`; unknown resolver, transport, RCODE, or TTL stays unknown.

## Service and Cluster Checks

| Context | Minimal read-only check | Decision rule |
|---|---|---|
| BIND | `named -V`; query the known listening address with `dig` | Version plus direct behavior; do not read or edit protected config/logs |
| Unbound | `unbound -V`; query the known listening address with `dig` | Compare local validating result with authority |
| dnsmasq | `dnsmasq --version`; query the known listening address | Distinguish forwarding/cache behavior from upstream answer |
| systemd-resolved | `resolvectl status` and `resolvectl query name.example` | Preserve link, protocol, and server shown |
| CoreDNS binary | `coredns -version`; query its already-known service/listen IP | Treat plugin configuration as unknown unless supplied |
| Kubernetes DNS pods | `kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide` | Read pod readiness/node placement in the current authorized context |
| Kubernetes DNS service | `kubectl get service -n kube-system kube-dns -o wide` | Read ClusterIP and ports; do not modify objects |
| Pod lookup | `kubectl exec -n NAMESPACE POD -- nslookup name.example` | User executes only for an existing authorized pod and read-only lookup command |

The skill must not execute any `kubectl` command, including `kubectl exec`. Do not request cluster credentials, change context, create debug pods, inspect secrets, edit ConfigMaps, restart workloads, or read protected logs. If the user is not already authorized, mark the branch unavailable.

## Resolver Selection Clues

| Context | What to preserve | Comparison |
|---|---|---|
| VPN | Connection state supplied by user, interface, resolver, search/routing domains | On-VPN observation versus an independently supplied off-VPN observation; never toggle VPN |
| Split DNS | Suffix/routing-domain match and selected link/resolver | Internal name through intended local resolver before any public query |
| DoH | Whether the application/OS is known to use DoH and which local path bypasses it | Application result versus OS DNS result; do not disable DoH |
| Multi-interface | Interface/link, route scope, resolver order | Same query attributed to each observed resolver path |
| Container | Container namespace and configured resolver shown by user-readable state | Container result versus host result |
| Kubernetes | Pod namespace/node, cluster DNS service, search suffix/`ndots` if supplied | Pod result versus direct cluster DNS service query |

## Decision Rules

1. Attribute every local observation to an OS path, application path, interface/link, resolver, and time when known.
2. A browser result may use DoH while command-line tools use OS DNS; disagreement does not identify which path is wrong.
3. Split DNS can intentionally return NODATA/NXDOMAIN publicly while resolving internally. Give the internal-name exposure warning before any public-resolver test.
4. Multiple interfaces and VPNs can select different resolvers without a DNS server fault. Never alter state to test this.
5. CoreDNS/Kubernetes evidence must stay within the current read-only authorization. Missing access is a limitation, not a request for credentials.

# Netkit

**See what your network is doing. Understand what to do next.**

[![CI](https://github.com/Alifarid0011/netkit/actions/workflows/ci.yml/badge.svg)](https://github.com/Alifarid0011/netkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Linux network workbench written in Go: layered connection diagnostics, a live terminal dashboard, packet capture, reverse proxying, explicit Tor routing, and an experimental MikroTik RouterOS client.

```text
$ netkit doctor --explain https://example.com
NETWORK DIAGNOSIS  https://example.com

  PASS  dns                                  … ms
  PASS  tcp      <resolved address>:443       … ms
  PASS  tls      <resolved address>:443       … ms
  PASS  http     <resolved address>:443       … ms  200 OK
```

Illustrative output; timings and addresses come from your actual connection. A timeout is an observation, not proof that a firewall is responsible.

## Install on Linux

Download the archive for your CPU from [Releases](https://github.com/Alifarid0011/netkit/releases). Verify its SHA-256 checksum against `SHA256SUMS`, extract it, and run:

```sh
./install.sh                         # ~/.local/bin/netkit, no sudo
# ./install.sh --prefix /usr/local   # requires permission to this prefix
netkit version
```

Ensure `$HOME/.local/bin` is on PATH. Existing binaries are preserved unless `--force` is passed. To remove the user-local installation: `rm "$HOME/.local/bin/netkit"`. The installer installs only the binary, not a service or system networking configuration. Go source installation:

```sh
go install github.com/Alifarid0011/netkit/cmd/netkit@v0.1.0
```

Requires Go 1.24+ for source builds; release binaries do not need Go or CGO. Linux amd64 and arm64 archives are provided. Backends are optional by feature:

| Feature | Linux program |
|---|---|
| Interfaces, routes, listeners, dashboard | `ip`, `ss` (iproute2) |
| ICMP | `ping` |
| Capture and saved PCAP decoding | `tcpdump` |
| Firewall inspection | `nft` |
| Dedicated Tor process | `tor` |
| Doctor, TCP probe, reverse proxy, RouterOS HTTPS | No external backend |

On Debian/Ubuntu these are typically provided by `iproute2 iputils-ping tcpdump nftables tor`. Install only what you use through your distribution's package manager.

## Diagnose by layer

```sh
netkit ip --explain
netkit ports
netkit doctor example.com                  # bare host defaults to HTTPS
netkit doctor --timeout 2s https://example.com
netkit doctor 127.0.0.1:5432                # DNS/TCP only
netkit probe --count 5 --interval 500ms example.com:443
netkit probe --watch --count 1 example.com:443
netkit ping --count 4 example.com
netkit tui
```

The dashboard refreshes every three seconds. Type `i`, `p`, `h`, or `q` followed by Enter for interfaces, listeners, explanations, or quit. Ctrl+C also exits. It is read-only and observes the current process's network namespace. It needs an interactive ANSI terminal; scriptable commands work without one.

`doctor` checks up to 16 resolved addresses individually, validates TLS certificates, does not follow HTTP redirects, and reports HTTP status. A host with one working address and one failed address returns failure to keep partial reachability visible. TCP probes measure connection setup, not bandwidth or ICMP latency. Local listeners are not necessarily reachable from another machine. Process attribution may be unavailable without permission.

## Capture and learn

```sh
netkit capture --interface eth0 --duration 10s --count 100 --filter 'tcp port 443' --explain
netkit capture --interface eth0 --duration 10s --output sample.pcap
netkit pcap sample.pcap
```

Capturing requires the appropriate Linux capabilities/root or distribution tcpdump permission setup. Netkit does not automatically elevate itself. Offline decoding needs no capture privileges. A new PCAP is created with mode `0600` and existing files are never overwritten. Stop conditions are explicit; default capture is 10 seconds or 100 packets, whichever comes first. Count-only capture has a five-minute deadline. Ctrl+C asks tcpdump to flush before stopping.

The interface only sees traffic available at that capture point. Switched traffic and hardware-offloaded traffic may be absent; TLS payloads remain encrypted. tcpdump reports capture-drop statistics on stderr. Saved PCAPs contain packet payloads; handle them as sensitive data. Live decoding does not request hex/ASCII payload dumps. There is no remote MikroTik/TZSP capture in this release.

## Foreground reverse proxy

```sh
netkit proxy --listen 127.0.0.1:8080 --to http://127.0.0.1:3000 --explain
```

Uses Go's reverse proxy with streaming, HTTP upgrades, header timeouts, and graceful shutdown. Default bind is loopback. Ctrl+C stops it. It does not install a daemon, modify routes, or terminate public HTTPS. Request method and elapsed time are logged; URLs and headers are deliberately omitted. Do not expose it as an unauthenticated public service accidentally. Standard HTTP proxy environment settings apply to upstream HTTP connections.

## Managed Linux firewall

```sh
netkit firewall list
netkit firewall plan --action block --protocol tcp --port 8080 --source 192.0.2.0/24 --explain
```

Plans contain static nftables batch statements for a dedicated `inet netkit` table. They do **not** inspect live state or guarantee reachability. An accept in one base chain does not override a drop in another.

```sh
# First preview the intended rule:
netkit firewall plan --action block --protocol tcp --port 8080 --explain
# Apply in the CURRENT namespace, removing after 30 seconds or Ctrl+C:
sudo "$(command -v netkit)" firewall apply --action block --protocol tcp --port 8080 --confirm
# Explicitly persist it instead; keep the returned ownership ID:
sudo "$(command -v netkit)" firewall apply --action block --protocol tcp --port 8080 --confirm --keep
sudo "$(command -v netkit)" firewall remove --id 'netkit-v1-RETURNED_ID' --confirm
```

`apply` requires explicit `--confirm`. Temporary mode is the default; `--duration` accepts 1 second to 10 minutes. Its cleanup runs only while the foreground process is alive: a crash, SIGKILL or machine shutdown can prevent automatic removal. `--keep` deliberately disables that cleanup. A firewall change may sever an SSH connection: use local access or a recovery path, and test plans in a lab first. Netkit does not elevate itself.

Rules use random ownership IDs and are removed by their current kernel handle. The table and chain must carry Netkit's exact ownership comments and expected configuration; foreign tables are refused. Batches apply atomically and never flush unrelated rules or change global policies. Removing the last rule leaves the empty managed table/chain in place. Coordinate other firewall managers: ownership checking and mutation are not a persisted compare-and-swap transaction. If mutation succeeds but later handle lookup fails, the error includes the rule ID for inspection/removal.

Real isolated network-namespace tests verify add/remove, IPv4/IPv6 matching, unrelated-table preservation, foreign-table refusal, actual TCP blocking/restoration and external-drop precedence. No host firewall was changed during development. iptables-legacy mutation and kill-resistant rollback remain unsupported.

## MikroTik RouterOS 7 (experimental)

HTTPS REST only, verified certificate, optional custom CA. No insecure TLS switch and no following redirects with credentials.

```sh
export NETKIT_ROUTER_URL=https://router.example.net
export NETKIT_ROUTER_USER=netkit-reader
# Read a secret without putting its value in shell history:
read -r -s -p 'Router password: ' NETKIT_ROUTER_PASSWORD; echo
export NETKIT_ROUTER_PASSWORD
netkit router list --resource system/identity
netkit router list --resource interface --ca router-ca.pem
netkit router list --resource ip/firewall/filter --json
unset NETKIT_ROUTER_PASSWORD
```

Alternatively use `--password-stdin` with a secret-manager pipe. Password values are never command-line flags. A limited RouterOS account is recommended. Output can contain private device configuration; protect saved output.

```sh
# Preview; no connection or write:
netkit router add --action block --chain input --protocol tcp --port 8080
# Explicit experimental write; the created rule is DISABLED:
netkit router add --action block --chain input --protocol tcp --port 8080 --apply
# Preview then explicitly remove a rule created by Netkit:
netkit router remove --id '*A'
netkit router remove --id '*A' --apply
```

Read allowlist: `system/identity`, `system/resource`, `interface`, `ip/address`, `ip/route`, `ip/firewall/filter`, `ip/firewall/nat`.

Writes currently create IPv4 filter rules only (allow/block, input/forward, optional source/destination CIDRs, protocol/port); NAT and address/route writes are not implemented. Rules append and are disabled by default; enable manually after review. Deletion verifies the stable `.id` and exact Netkit ownership comment. This is an ownership convention, not protection from another administrator changing the same object between check and delete.

**Validated against TLS fixtures, not a real RouterOS/CHR lab.** REST writes are not atomic, have no automatic rollback, and are not protected by console Safe Mode. A failed request may already have taken effect: inspect before retrying. Version/capability discovery, v6 support, persisted plans and concurrent-operator conflict detection are not implemented. Use a lab before real remote changes.

References: [RouterOS REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/), [RouterOS configuration management](https://manual.mikrotik.com/docs/getting-started/configuration-management/).

## Explicit Tor routing

```sh
netkit tor start --port 19050 --explain       # terminal 1; wait for Bootstrapped 100%
netkit tor check --explain                    # terminal 2
netkit tor check --socks socks5h://127.0.0.1:9050 --json
```

Runs an installed Tor client in the foreground with an isolated configuration and private user-cache data directory. `tor check` sends one HTTPS request to `check.torproject.org/api/ip` through SOCKS with remote DNS. It reports whether the endpoint sees a Tor exit and that request's IP. It does not route other Netkit commands, your browser, or the whole system through Tor; it does not promise a different IP each time. Stop with Ctrl+C. There is no automatic installation, control-port identity rotation, or global proxy setting.

## Automation and exit codes

```sh
netkit ip --json
netkit doctor https://example.com --json
```

Successful JSON is `{"schema_version":1,"data":...}`; errors use `{"schema_version":1,"error":"..."}`. Stage/connection failures remain structured results with exit `1`. Errors are on stderr in human mode; help uses stdout at the root and stderr for command flag help. JSON is never mixed with explanation text; `--explain` goes to stderr. Streaming commands do not support `--json`.

Exit `0`: completed successfully; `1`: operational/observation failure; `2`: CLI usage/validation error. Put command-specific flags before positional arguments. `--json` and `--explain` work anywhere. Use `netkit COMMAND --help` for options. Bash completion: `source completions/netkit.bash` from the source checkout.

## Develop and contribute

```sh
go test -race ./...
go vet ./...
go build ./cmd/netkit
bash packaging/build.sh v0.1.0
```

Tests cover local HTTP/TLS failures and redirects, TCP cancellation, typed backend arguments, PCAP fixtures, capture flushing, RouterOS authentication/ownership, SOCKS remote DNS, and proxy streaming. Namespace integration is opt-in locally (`NETKIT_TEST_NFT=1 go test -race ./internal/linux`) and runs in a dedicated isolated namespace in CI. A namespace guard prevents the helper from touching its parent network namespace. See [CONTRIBUTING.md](CONTRIBUTING.md) and [ROADMAP.md](ROADMAP.md).

Created by **Ali Farid** · [GitHub](https://github.com/Alifarid0011) · MIT license.

# Netkit: Linux network workbench

Status: implementation authorized by user on 2026-11-01. Netkit is a working name; availability is not verified.

## Intent

Build an installable, open-source Go terminal tool for Linux network administration and troubleshooting. It must explain observations and changes accurately, serve experienced operators without mandatory tutorials, and help learners understand Linux networking. No claim of replacing every networking tool.

## Approaches and choice

Considered a cross-platform diagnostic toolkit and a Linux-focused administration tool. The user selected Linux and deep network management. Use one shared command/service layer for a scriptable CLI and interactive terminal dashboard. Prefer Go's standard library for DNS, TCP, TLS, HTTP and reverse proxying; use maintained netlink support for Linux interface, route and socket inspection. Use nftables as the managed firewall backend; show existing iptables rules read-only when supported, without silently migrating them. Builder chooses small maintained libraries after checking compatibility and licenses.

## First release scope

- `ip`: interfaces, addresses, link state, routes and default routes; read-only initially. Distinguish configured addresses from externally observed public IP. Public-IP lookup is explicit and names its provider.
- `ports`: local listening TCP/UDP sockets, bind address and process identity where permissions allow. Distinguish local listening from remote reachability and unknown process attribution.
- `doctor TARGET`: DNS resolution, per-address TCP reachability, TLS validation and HTTP checks when meaningful. Preserve errors and timings per stage; do not claim a TCP timeout proves a firewall block.
- `probe HOST:PORT --watch`: bounded TCP connection sampling with loss/failure and latency history. Separate ICMP ping mode using an available system ping executable; label the measurement method and capability errors.
- `proxy --listen ADDRESS --to URL`: foreground HTTP reverse proxy, request/status/duration logs, streaming and upgrade support, cancellation and graceful shutdown. Default loopback binding. No managed daemon, automatic public TLS or arbitrary TCP tunnelling in v1.
- `firewall list|plan|apply|remove`: inspect firewall rules, preview and manage a narrow set of TCP/UDP ingress allow/block rules. Managed rules live in a dedicated nftables table and are identified independently of display order. Define precedence explicitly: managed ingress rules cannot promise to override other tables, and external drop rules may still block traffic. No global ruleset flush or policy changes.
- `tui`: keyboard-driven views for interfaces/routes, listeners, live probes and managed firewall plans. Help, status, permission errors and running operations remain visible; no prerequisite root process.

## Explainable operation

Every relevant command accepts `--explain`: show what was queried, how the observation was obtained, what it means, and important limits. Changes show exact proposed operations before execution. Lessons accompany actual results, not invented diagnoses. Default human output is concise; `--json` has a documented versioned schema, explicit units and stable error/exit conventions. Diagnostics go to stderr so stdout JSON remains machine-readable. Disable colour for non-TTY/NO_COLOR. CLI and help are English in v1; locale support is deferred.

## Change and privilege model

Inspection works without root where Linux permits. Privileged operations run only on explicit request; never elevate the whole TUI automatically. Firewall plans contain the target namespace, current relevant state and exact rule changes. Validate and apply a batch atomically with nftables; reject stale plans. Capture pre-change state for owned rules, not for unrelated rulesets. Undo removes/restores only the tool's own recorded changes, detects external modifications and reports conflicts rather than overwriting them.

Before mutation support ships, verify interaction with common base-chain priorities, existing connection tracking and SSH connectivity inside isolated test network namespaces. For remote administration expose a bounded rollback timer for managed changes with explicit confirmation; do not claim this makes arbitrary firewall changes risk-free. Never change this machine's live network as part of development tests.

## Architecture and limits

Linux amd64/arm64 first. Thin CLI/TUI adapters call typed services; inspection, probing, proxy and firewall packages expose concrete result types and accept contexts. Use cancellation, bounded concurrency, deadlines and capped event histories. Build commands through typed arguments, never shell-interpolated strings. No database or background daemon required for v1; local restrictive-permission state stores managed firewall transactions. Detect missing backend tools and nftables availability explicitly. Unsupported systems fail clearly.

Do not include credential interception, internet-wide scanning, Linux route/address mutation, VPN management, containers or Kubernetes orchestration in v1. These are separate future scopes, not implied completed features.

## Requested scope extension: capture and MikroTik

The user additionally requests packet capture and MikroTik configuration. This extends delivery beyond the original first release. Linux foundations still ship first; the following are separate milestones of the same product, not claims of existing support.

### Packet capture

Provide local capture on an explicitly selected interface, bounded by duration/count/file size, with capture filters and PCAP export for Wireshark. Show source/destination, protocol, ports, observed traffic rates and TCP flags. Explain capture location and visibility limits: encrypted payload remains encrypted, and a switched network does not expose every host's traffic. Display capture-drop statistics and distinguish capture loss from network loss. Prefer a standard capture backend and expose its required capabilities; keep the main interface unprivileged. Offline PCAP reading should work without capture privileges. Packet decoders must handle truncated/malformed inputs without panics; include fuzzing and fixture tests. Do not silently record packet payloads in general application logs.

### MikroTik RouterOS

Initial proposed target is RouterOS v7 over HTTPS REST with certificate verification and explicit device profiles. RouterOS v6/API-SSL support requires a separate adapter if the user's devices need it. Detect version and capabilities; do not guess supported commands. Passwords must not appear in command-line arguments, logs, exported plans or shell history. Use interactive secret input or a documented credential provider; save profile metadata separately.

First remote support reads interfaces, addresses, routes, filter/NAT rules, rule counters and device identity. Follow with typed plans for a bounded set of filter and NAT rules; then address/route changes after isolated integration testing. Preserve RouterOS rule order and stable .id references; reject changed preconditions. Show destination device and exact changes before apply. REST request sequences are not an atomic transaction. Linux nftables rollback is not reused as a promise of RouterOS rollback; investigate and test a device-side bounded rollback strategy before exposing remote writes that may sever management access. RouterOS console Safe Mode has specific session semantics and is not assumed to protect REST writes. Initially support only explicitly managed objects and avoid resetting devices or rewriting unrelated policy.

Remote capture is a separate opt-in operation using the RouterOS sniffer and TZSP where supported. Bound duration and resource use, exclude capture-stream feedback, restrict receiver binding/source, and do not overwrite or stop another operator's sniffer session. Restore owned sniffer changes on normal completion; report cleanup failure accurately. Account for hardware-offloaded traffic not reaching the CPU capture point. Do not promise that packet capture sees all routed/switched traffic.

MikroTik tests use HTTP fixtures for authentication, certificates, paging/replies, ordering, stale plans and partial failures, plus an explicitly configured RouterOS/CHR lab for real behaviour. No write or capture is started on a real router merely by connecting. Without a real lab, document mock-only validation and do not label remote mutation production-ready.

Official references: https://manual.mikrotik.com/docs/developer-guides/rest-api/ ; https://manual.mikrotik.com/docs/developer-guides/api/ ; https://manual.mikrotik.com/docs/getting-started/configuration-management/ ; https://help.mikrotik.com/docs/spaces/ROS/pages/8323088/Packet%20Sniffer .

## Installation and verification

Provide release tarballs and SHA-256 checksums for Linux amd64/arm64, a documented user-local install/uninstall path, shell completions, manual install instructions and a version command. Do not overwrite existing binaries without an explicit installer option; no curl-to-root installation. Package-manager distribution may follow once the CLI stabilizes. License: MIT proposed. Publication and real version numbers follow verified implementation.

Tests: pure result formatting and parsers, cancellation/timeouts, DNS/TCP/HTTP/TLS failures with local fixtures, reverse proxy streaming/upgrades and shutdown, race tests, fuzzing for untrusted parsing. Linux network-namespace integration tests cover firewall isolation, atomic apply, stale plans, remove/undo and rollback; tests requiring privileges are explicitly reported as skipped when unavailable. CI builds both architectures and runs unprivileged tests; privileged tests need a supported isolated runner. TUI state transitions get automated tests and manual terminal checks. Document tested kernels/distributions and limits; no claim of bug-free operation.

## Delivery order and builder decisions

Deliver a usable diagnostic CLI and installer first; then dashboard/proxy; then firewall mutation after namespace tests. README must track actual support, examples and limitations per release. Builder chooses the final package layout, test harness, maintained TUI/netlink libraries and release automation. No further product choice is required before planning; implementation is authorized. See roadmap for deferred integration requirements.

## Tor extension

User requested Tor connection and exit-IP changes. Initial implementation runs an installed Tor client in foreground and routes an explicit HTTPS exit-IP check via SOCKS with remote DNS. It does not alter system routing or guarantee a fresh exit identity.

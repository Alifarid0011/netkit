# Roadmap

## v0.1.0: usable foundation

- [x] DNS/TCP/TLS/HTTP diagnosis and TCP/ICMP probes
- [x] Interfaces, routes, listeners and terminal dashboard
- [x] Bounded local capture, saved PCAP decoding
- [x] Foreground HTTP reverse proxy
- [x] nftables inspection, plans and owned-rule apply/remove with foreground timed cleanup
- [x] Experimental RouterOS HTTPS reads and disabled filter creation/owned deletion
- [x] Dedicated Tor startup and explicit SOCKS-routed exit-IP check
- [x] Linux amd64/arm64 archives, local installer and tests

## Next: prove privileged operations

- [x] Isolated nftables tests for atomic apply, owned removal, actual blocking and unrelated-table preservation
- [ ] Kill-resistant firewall rollback and persisted stale-state conflict detection
- [ ] RouterOS/CHR lab matrix, version/capability discovery and management-disconnect recovery
- [ ] RouterOS NAT/address/route plans and writes after lab validation
- [ ] Bounded RouterOS sniffer/TZSP reception with session ownership and cleanup
- [x] Keyboard action menu, editable forms, scrolling results, resize handling and mutation confirmations
- [ ] Richer live charts and concurrent operation management
- [ ] Persistent device profiles with credential-provider integration
- [ ] RPM/DEB packaging and package-manager distribution

Linux firewall mutation was tested inside isolated namespaces. RouterOS writes remain fixture-tested only. Planned features are not implemented capabilities.

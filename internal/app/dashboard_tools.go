package app

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type dashboardField struct {
	Label, Flag, Default, Hint string
	Secret, Required           bool
}
type dashboardTool struct {
	ID, Title, Summary, Explain string
	Command                     []string
	Fields                      []dashboardField
	Mutation                    bool
}

func field(label, flag, value, hint string) dashboardField {
	return dashboardField{Label: label, Flag: flag, Default: value, Hint: hint}
}
func required(label, flag, value, hint string) dashboardField {
	f := field(label, flag, value, hint)
	f.Required = true
	return f
}
func dashboardTools() []dashboardTool {
	routerFields := []dashboardField{required("Router URL", "--url", envDefault("NETKIT_ROUTER_URL", "https://router.example.net"), "HTTPS RouterOS 7 endpoint"), required("Username", "--user", envDefault("NETKIT_ROUTER_USER", "admin"), "Use a limited RouterOS account"), {Label: "Password", Flag: "-", Secret: true, Hint: "Masked; session memory only. Blank uses NETKIT_ROUTER_PASSWORD"}, field("CA file", "--ca", "", "Optional custom CA PEM; TLS is always verified")}
	cloneRouter := func(extra ...dashboardField) []dashboardField {
		result := append([]dashboardField{}, routerFields...)
		return append(result, extra...)
	}
	return []dashboardTool{
		{ID: "interfaces", Title: "Interfaces & routes", Summary: "Addresses, link state and IPv4/IPv6 routes", Explain: "Shows configured addresses in this network namespace. These are not necessarily the public exit IP. Enter refreshes; results can be scrolled.", Command: []string{"ip"}},
		{ID: "listeners", Title: "Listening ports", Summary: "Local TCP/UDP listeners and process information", Explain: "A local listener is not proof of remote reachability. A route or firewall can still block traffic; process names may require permission.", Command: []string{"ports"}},
		{ID: "doctor", Title: "Connection doctor", Summary: "Find the failing layer: DNS, TCP, TLS or HTTP", Explain: "Tests each resolved address. Bare hostnames use HTTPS. A timeout is not proof of a firewall block. HTTP redirects are reported without following them.", Command: []string{"doctor"}, Fields: []dashboardField{required("Destination", "", "example.com", "Hostname, host:port, or http(s) URL")}},
		{ID: "probe", Title: "TCP latency probe", Summary: "Repeated connection measurements", Explain: "Measures TCP connection setup, not ICMP or bandwidth. Esc stops the job; partial command output remains visible.", Command: []string{"probe"}, Fields: []dashboardField{required("Destination", "", "example.com:443", "Use host:port"), required("Samples", "--count", "5", "1..1000"), required("Interval", "--interval", "500ms", "Time between samples; 0..1m")}},
		{ID: "ping", Title: "ICMP ping", Summary: "Reachability and ICMP round-trip times", Explain: "Uses Linux ping. ICMP can be filtered even when TCP works. Esc stops the active process.", Command: []string{"ping"}, Fields: []dashboardField{required("Host", "", "example.com", "Hostname or IP"), required("Count", "--count", "4", "1..100")}},
		{ID: "capture", Title: "Packet capture", Summary: "Capture traffic with a filter and a time limit", Explain: "Requires tcpdump and capture privileges. Only traffic visible on the interface is captured; encrypted payload remains encrypted. Blank output shows decoded metadata, otherwise saves a new private PCAP.", Command: []string{"capture"}, Fields: []dashboardField{required("Interface", "--interface", "any", "Interface name or any"), field("Filter", "--filter", "tcp", "tcpdump expression, e.g. tcp port 443"), required("Duration", "--duration", "10s", "Explicit stop duration"), required("Packet limit", "--count", "100", "Stop at this count or duration"), field("PCAP output", "--output", "", "Optional new file; existing files are never overwritten")}},
		{ID: "pcap", Title: "Read saved PCAP", Summary: "Inspect a capture without capture privileges", Explain: "Offline tcpdump decoding of a local capture. No live interface is opened.", Command: []string{"pcap"}, Fields: []dashboardField{required("PCAP file", "", "", "Path to an existing capture")}},
		{ID: "proxy", Title: "Reverse proxy", Summary: "Forward HTTP requests to a local upstream", Explain: "Runs until Esc. Defaults to loopback. It does not configure system routes or firewall rules. Requests are logged without headers or URL query strings.", Command: []string{"proxy"}, Fields: []dashboardField{required("Listen", "--listen", "127.0.0.1:8080", "Local bind address"), required("Upstream", "--to", "http://127.0.0.1:3000", "HTTP(S) URL")}},
		{ID: "firewall-list", Title: "Firewall rules", Summary: "Inspect the current nftables ruleset", Explain: "Read-only; may require CAP_NET_ADMIN. Netkit does not automatically elevate the dashboard.", Command: []string{"firewall", "list"}},
		{ID: "firewall-plan", Title: "Plan firewall rule", Summary: "Preview an owned ingress rule without applying it", Explain: "A static nftables plan. An accept here cannot override a drop in another table. Plan does not promise network reachability.", Command: []string{"firewall", "plan"}, Fields: firewallFields()},
		{ID: "firewall-apply", Title: "Temporary firewall", Summary: "Apply an owned rule with foreground timed cleanup", Explain: "Changes this namespace's ingress firewall. Confirmation is required. Rule is removed after the duration or cancellation while Netkit stays alive; crash/SIGKILL can prevent cleanup. Requires CAP_NET_ADMIN.", Command: []string{"firewall", "apply", "--confirm"}, Fields: append(firewallFields(), required("Duration", "--duration", "30s", "1s..10m; no persistent mode in dashboard")), Mutation: true},
		{ID: "firewall-remove", Title: "Remove owned rule", Summary: "Delete exactly one Netkit-managed firewall rule", Explain: "Requires the stable netkit-v1-... ownership ID. Other tables and unowned rules are not removed.", Command: []string{"firewall", "remove", "--confirm"}, Fields: []dashboardField{required("Ownership ID", "--id", "", "netkit-v1- followed by 32 hex digits")}, Mutation: true},
		{ID: "router-list", Title: "MikroTik inspect", Summary: "Read RouterOS 7 through verified HTTPS", Explain: "Experimental; TLS-fixture tested, not real-device validated. Credentials stay in memory and never enter command previews. Supported resource examples: interface, ip/address, ip/route, ip/firewall/filter, ip/firewall/nat.", Command: []string{"router", "list"}, Fields: cloneRouter(required("Resource", "--resource", "system/identity", "Supported REST menu path"))},
		{ID: "router-add", Title: "MikroTik filter", Summary: "Create a DISABLED RouterOS IPv4 filter", Explain: "Experimental real write, not protected by Safe Mode or automatic rollback. New rule is disabled. Enable manually after inspection; appends to existing rule order.", Command: []string{"router", "add", "--apply"}, Fields: cloneRouter(required("Action", "--action", "block", "allow or block"), required("Chain", "--chain", "input", "input or forward"), required("Protocol", "--protocol", "tcp", "tcp, udp or icmp"), field("Port", "--port", "8080", "Destination port; blank for no port filter"), field("Source CIDR", "--source", "", "Optional IPv4 CIDR")), Mutation: true},
		{ID: "router-remove", Title: "MikroTik remove", Summary: "Remove one owned RouterOS filter by stable ID", Explain: "Experimental real deletion. Only exact Netkit-owned filters are accepted. Coordinate other administrators; ownership check and deletion are not atomic.", Command: []string{"router", "remove", "--apply"}, Fields: cloneRouter(required("Rule .id", "--id", "", "Stable RouterOS ID such as *A")), Mutation: true},
		{ID: "tor-check", Title: "Tor exit check", Summary: "Check this request's public exit IP via SOCKS", Explain: "One HTTPS request goes through SOCKS with remote DNS. Other tools and your system traffic are not automatically routed through Tor; no fresh exit identity is promised.", Command: []string{"tor", "check"}, Fields: []dashboardField{required("SOCKS URL", "--socks", "socks5h://127.0.0.1:19050", "An already-running Tor SOCKS endpoint")}},
		{ID: "tor-start", Title: "Start Tor client", Summary: "Run an isolated local Tor process", Explain: "Requires installed tor. Wait for Bootstrapped 100%; only explicitly SOCKS-routed requests use Tor. Esc stops this foreground client. It can take time to bootstrap.", Command: []string{"tor", "start"}, Fields: []dashboardField{required("SOCKS port", "--port", "19050", "Loopback port, 1024..65535"), field("Data directory", "--data-dir", "", "Optional private 0700 directory")}},
	}
}
func firewallFields() []dashboardField {
	return []dashboardField{required("Action", "--action", "block", "allow or block"), required("Protocol", "--protocol", "tcp", "tcp or udp"), required("Port", "--port", "8080", "Destination port, 1..65535"), field("Source CIDR", "--source", "", "Optional IPv4 or IPv6 source range")}
}
func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func (t dashboardTool) arguments(values []string) ([]string, error) {
	if len(values) != len(t.Fields) {
		return nil, errors.New("form fields are incomplete")
	}
	args := append([]string{}, t.Command...)
	var positionals []string
	for i, f := range t.Fields {
		value := strings.TrimSpace(values[i])
		if f.Secret {
			continue
		}
		if f.Required && value == "" {
			return nil, fmt.Errorf("%s is required", f.Label)
		}
		if len(value) > 4096 || strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("%s is too long or contains NUL", f.Label)
		}
		if value == "" {
			continue
		}
		if f.Flag == "--url" {
			u, err := url.Parse(value)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				return nil, errors.New("router URL must be HTTPS without embedded credentials")
			}
		}
		if f.Flag == "" {
			positionals = append(positionals, value)
		} else {
			args = append(args, f.Flag+"="+value)
		}
	}
	args = append(args, positionals...)
	return args, nil
}

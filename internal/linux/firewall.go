package linux

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ErrMutationUnsupported is retained for callers of earlier plan-only builds.
// Managed mutation is now verified by opt-in isolated namespace tests.
var ErrMutationUnsupported = errors.New("firewall mutation is unavailable: isolated namespace integration has not been verified; use firewall plan and apply reviewed operations independently")

type Rule struct {
	Action   string `json:"action"`
	Protocol string `json:"protocol"`
	Source   string `json:"source,omitempty"`
	Port     int    `json:"port"`
}

type Plan struct {
	Rule           Rule     `json:"rule"`
	Commands       []string `json:"commands"`
	Warning        string   `json:"warning"`
	ApplySupported bool     `json:"apply_supported"`
}

// FirewallPlan is a static proposal, not a transaction or a claim about current
// state. The first two commands require an absent netkit table. ManagedApply
// inspects ownership and omits table/chain creation when they already exist.
func FirewallPlan(rule Rule) (Plan, error) {
	if rule.Action != "allow" && rule.Action != "block" {
		return Plan{}, errors.New("action must be allow or block")
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return Plan{}, errors.New("protocol must be tcp or udp")
	}
	if rule.Port < 1 || rule.Port > 65535 {
		return Plan{}, errors.New("port must be between 1 and 65535")
	}
	source := ""
	if rule.Source != "" {
		prefix, err := netip.ParsePrefix(rule.Source)
		if err != nil {
			return Plan{}, fmt.Errorf("source must be an IPv4 or IPv6 CIDR: %w", err)
		}
		prefix = prefix.Masked()
		rule.Source = prefix.String()
		family := "ip"
		if prefix.Addr().Is6() {
			family = "ip6"
		}
		source = family + " saddr " + rule.Source + " "
	}
	verdict := "accept"
	if rule.Action == "block" {
		verdict = "drop"
	}
	return Plan{Rule: rule, Commands: []string{
		`add table inet netkit { comment "netkit-managed-v1"; }`,
		`add chain inet netkit ingress { type filter hook input priority 0; policy accept; comment "netkit-ingress-v1"; }`,
		"add rule inet netkit ingress " + source + rule.Protocol + " dport " + strconv.Itoa(rule.Port) + " " + verdict,
	}, Warning: "Static plan only; inspect current state and namespace before use. Table creation requires the dedicated netkit table to be absent. Earlier matching rules take precedence; accepts do not override drops in other base chains. Apply appends an owned rule with a random ID. Remove resolves that ID to its current kernel handle. Concurrent external changes require coordination; persisted stale-plan checks and rollback timers are not implemented.", ApplySupported: true}, nil
}

// FirewallList returns the installed nftables ruleset including stable handles.
// It is read-only; permissions are controlled by the operating system.
func FirewallList(ctx context.Context) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "nft", "-a", "list", "ruleset")
	out := &cappedOutput{limit: 4 << 20}
	cmd.Stdout = out
	diagnostic := &cappedOutput{limit: 4096}
	cmd.Stderr = diagnostic
	if err := cmd.Run(); err != nil {
		if bounded.Err() != nil {
			return "", bounded.Err()
		}
		return "", fmt.Errorf("nft read-only listing (may require CAP_NET_ADMIN): %w: %s", err, strings.TrimSpace(diagnostic.text.String()))
	}
	if out.truncated {
		return "", errors.New("nft ruleset exceeds 4 MiB output limit")
	}
	return out.text.String(), nil
}

func FirewallApply(ctx context.Context, rule Rule) error {
	_, err := ManagedApply(ctx, rule)
	return err
}

func FirewallRemove(ctx context.Context, id string) error { return ManagedRemove(ctx, id) }

func nftRun(ctx context.Context, input string, args ...string) (string, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "nft", args...)
	cmd.Stdin = strings.NewReader(input)
	out := &cappedOutput{limit: 4 << 20}
	diag := &cappedOutput{limit: 4096}
	cmd.Stdout = out
	cmd.Stderr = diag
	if err := cmd.Run(); err != nil {
		if bounded.Err() != nil {
			return "", bounded.Err()
		}
		return "", fmt.Errorf("nft (requires CAP_NET_ADMIN): %w: %s", err, strings.TrimSpace(diag.text.String()))
	}
	if out.truncated {
		return "", errors.New("nft output exceeds 4 MiB limit")
	}
	return out.text.String(), nil
}

type cappedOutput struct {
	text      strings.Builder
	limit     int
	truncated bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit - w.text.Len()
	if len(p) > remaining {
		p = p[:remaining]
		w.truncated = true
	}
	_, _ = w.text.Write(p)
	return n, nil
}

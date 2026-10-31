package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	linuxnet "github.com/Alifarid0011/netkit/internal/linux"
	"github.com/Alifarid0011/netkit/internal/routeros"
	"github.com/Alifarid0011/netkit/internal/transport"
)

func firewall(ctx context.Context, args []string, o output) int {
	if len(args) == 0 {
		return o.fail(errors.New("firewall requires list, plan, apply or remove"), 2)
	}
	action := args[0]
	if action == "list" {
		if len(args) > 1 {
			return o.fail(errors.New("firewall list takes no arguments"), 2)
		}
		result, err := linuxnet.FirewallList(ctx)
		if err != nil {
			return o.fail(err, 1)
		}
		o.note("Reads nftables in this namespace; may require CAP_NET_ADMIN. No iptables-legacy commands.")
		if err = o.result(result); err != nil {
			return o.fail(err, 1)
		}
		return 0
	}
	if action != "plan" && action != "apply" && action != "remove" {
		return o.fail(errors.New("firewall requires list, plan, apply or remove"), 2)
	}
	f := flags("firewall "+action, o)
	verdict := f.String("action", "block", "allow or block")
	protocol := f.String("protocol", "tcp", "tcp or udp")
	source := f.String("source", "", "optional source CIDR")
	port := f.Int("port", 0, "destination port (1..65535)")
	confirm := f.Bool("confirm", false, "explicitly allow local firewall modification")
	id := f.String("id", "", "managed rule ownership ID to remove")
	keep := f.Bool("keep", false, "keep applied rule until explicitly removed")
	duration := f.Duration("duration", 30*time.Second, "automatic removal delay unless --keep (1s..10m)")
	if err := parse(f, args[1:]); err != nil {
		return flagError(o, err)
	}
	if f.NArg() != 0 {
		return o.fail(errors.New("firewall takes flags only"), 2)
	}
	if action == "remove" {
		if !*confirm {
			return o.fail(errors.New("firewall remove requires --confirm"), 2)
		}
		if err := linuxnet.ManagedRemove(ctx, *id); err != nil {
			return o.fail(err, 1)
		}
		if err := o.result(map[string]string{"removed": *id}); err != nil {
			return o.fail(err, 1)
		}
		return 0
	}
	plan, err := linuxnet.FirewallPlan(linuxnet.Rule{Action: *verdict, Protocol: *protocol, Source: *source, Port: *port})
	if err != nil {
		return o.fail(err, 2)
	}
	o.note("Dedicated owned nftables ingress rules only; no global flush or policy replacement. Other tables may still drop accepted packets. Coordinate other firewall managers; no persisted compare-and-swap guarantee.")
	if action == "plan" {
		if err := o.result(plan); err != nil {
			return o.fail(err, 1)
		}
		return 0
	}
	if !*confirm {
		return o.fail(errors.New("firewall apply requires --confirm; review firewall plan first"), 2)
	}
	if !*keep && (*duration < time.Second || *duration > 10*time.Minute) {
		return o.fail(errors.New("temporary duration must be 1s..10m"), 2)
	}
	applied, err := linuxnet.ManagedApply(ctx, plan.Rule)
	if err != nil {
		if applied.ID != "" {
			err = fmt.Errorf("%w (managed rule ID: %s)", err, applied.ID)
			if !*keep {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				cleanupErr := linuxnet.ManagedRemove(cleanup, applied.ID)
				cancel()
				if cleanupErr != nil {
					err = fmt.Errorf("%w; temporary cleanup failed: %v", err, cleanupErr)
				} else {
					err = fmt.Errorf("%w; temporary rule removed", err)
				}
			}
		}
		return o.fail(err, 1)
	}
	if *keep {
		if err := o.result(applied); err != nil {
			return o.fail(err, 1)
		}
		return 0
	}
	fmt.Fprintf(o.diagnostics, "Temporary rule %s active; automatic removal after %s or Ctrl+C. Process kill/crash prevents cleanup.\n", applied.ID, *duration)
	timer := time.NewTimer(*duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := linuxnet.ManagedRemove(cleanup, applied.ID); err != nil {
		return o.fail(fmt.Errorf("cleanup failed for rule %s: %w", applied.ID, err), 1)
	}
	if err := o.result(map[string]any{"applied": applied, "removed": true}); err != nil {
		return o.fail(err, 1)
	}
	return 0
}

func router(ctx context.Context, args []string, o output) int {
	if len(args) == 0 {
		return o.fail(errors.New("router requires list, add or remove"), 2)
	}
	action := args[0]
	if action != "list" && action != "add" && action != "remove" {
		return o.fail(errors.New("router requires list, add or remove"), 2)
	}
	f := flags("router "+action, o)
	endpoint := f.String("url", os.Getenv("NETKIT_ROUTER_URL"), "RouterOS HTTPS origin (or NETKIT_ROUTER_URL)")
	user := f.String("user", os.Getenv("NETKIT_ROUTER_USER"), "RouterOS user (or NETKIT_ROUTER_USER)")
	ca := f.String("ca", "", "custom PEM CA certificate file")
	passwordStdin := f.Bool("password-stdin", false, "read password from stdin (otherwise NETKIT_ROUTER_PASSWORD)")
	resource := f.String("resource", "system/identity", "allowed REST resource to list")
	apply := f.Bool("apply", false, "explicitly perform an experimental remote write")
	ruleAction := f.String("action", "block", "allow or block")
	chain := f.String("chain", "input", "input or forward")
	protocol := f.String("protocol", "tcp", "tcp, udp, icmp or empty")
	source := f.String("source", "", "optional source CIDR")
	destination := f.String("destination", "", "optional destination CIDR")
	port := f.Int("port", 0, "optional destination port")
	id := f.String("id", "", "stable owned rule .id, e.g. *A")
	if err := parse(f, args[1:]); err != nil {
		return flagError(o, err)
	}
	if f.NArg() != 0 {
		return o.fail(errors.New("router takes flags only"), 2)
	}
	rule := routeros.Rule{Action: *ruleAction, Chain: *chain, Protocol: *protocol, Source: *source, Destination: *destination, Port: *port}
	if *endpoint != "" {
		u, err := url.Parse(*endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return o.fail(errors.New("router URL must be HTTPS without credentials, query or fragment"), 2)
		}
	}
	if action == "add" {
		if err := routeros.ValidateRule(rule); err != nil {
			return o.fail(err, 2)
		}
	}
	if action == "remove" {
		if err := routeros.ValidateID(*id); err != nil {
			return o.fail(err, 2)
		}
	}

	if action != "list" && !*apply {
		o.note("Preview only. Created rules are disabled. --apply sends a real RouterOS write; REST changes are not atomic and are not protected by console Safe Mode.")
		if err := o.result(map[string]any{"preview": true, "action": action, "device": *endpoint, "rule": rule, "id": *id, "warning": "Experimental: fixture-tested only, not tested on a live RouterOS/CHR device. Add creates disabled rules; enable manually after review."}); err != nil {
			return o.fail(err, 1)
		}
		return 0
	}
	password := os.Getenv("NETKIT_ROUTER_PASSWORD")
	if *passwordStdin {
		var err error
		password, err = readPassword(ctx, os.Stdin)
		if err != nil {
			return o.fail(err, 1)
		}
	}

	client, err := routeros.New(*endpoint, *user, password, *ca)
	if err != nil {
		return o.fail(err, 2)
	}
	o.note("RouterOS 7 HTTPS REST with verified certificate; credentials never sent on redirects. Reads may expose device configuration: protect exported output. Writes experimental; default rules disabled.")
	switch action {
	case "list":
		result, err := client.List(ctx, *resource)
		if err != nil {
			return o.fail(err, 1)
		}
		if err = o.result(result); err != nil {
			return o.fail(err, 1)
		}
	case "add":
		result, err := client.AddRule(ctx, rule)
		if err != nil {
			return o.fail(err, 1)
		}
		if err = o.result(result); err != nil {
			return o.fail(err, 1)
		}
	case "remove":
		if err := client.RemoveRule(ctx, *id); err != nil {
			return o.fail(err, 1)
		}
		if err = o.result(map[string]string{"removed": *id}); err != nil {
			return o.fail(err, 1)
		}
	}
	return 0
}
func tor(ctx context.Context, args []string, o output) int {
	if len(args) == 0 {
		return o.fail(errors.New("tor requires start or check"), 2)
	}
	switch args[0] {
	case "start":
		f := flags("tor start", o)
		port := f.Int("port", 19050, "loopback SOCKS port")
		data := f.String("data-dir", "", "private Tor data directory (default user cache)")
		if err := parse(f, args[1:]); err != nil {
			return flagError(o, err)
		}
		if f.NArg() != 0 {
			return o.fail(errors.New("tor start takes flags only"), 2)
		}
		o.note("Runs installed Tor in foreground with isolated configuration. Only clients explicitly using its SOCKS endpoint are routed through Tor. Wait for Bootstrapped 100%.")
		if err := transport.TorStart(ctx, *port, *data, o.out, o.diagnostics); err != nil {
			return o.fail(err, 1)
		}
		return 0
	case "check":
		f := flags("tor check", o)
		socks := f.String("socks", "socks5h://127.0.0.1:19050", "SOCKS endpoint with remote DNS")
		timeout := f.Duration("timeout", 30*time.Second, "request timeout")
		if err := parse(f, args[1:]); err != nil {
			return flagError(o, err)
		}
		if f.NArg() != 0 {
			return o.fail(errors.New("tor check takes flags only"), 2)
		}
		o.note("Queries https://check.torproject.org/api/ip through the selected SOCKS endpoint. It reports this request's exit IP, not the host's global IP. It does not request a new circuit.")
		result, err := transport.TorCheck(ctx, *socks, "https://check.torproject.org/api/ip", *timeout)
		if err != nil {
			return o.fail(err, 1)
		}
		if err = o.result(result); err != nil {
			return o.fail(err, 1)
		}
		if !result.IsTor {
			fmt.Fprintln(o.diagnostics, "Endpoint did not report a Tor exit.")
			return 1
		}
		return 0
	default:
		return o.fail(errors.New("tor requires start or check"), 2)
	}
}

// readPassword consumes one bounded line; cancellation never waits for stdin EOF.
// The CLI exits after cancellation, releasing an outstanding OS read.
func readPassword(ctx context.Context, r io.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(r, 65537)).ReadString('\n')
		if len(line) > 65536 {
			done <- result{err: errors.New("password input exceeds 64 KiB")}
			return
		}
		if err != nil && err != io.EOF {
			done <- result{err: errors.New("cannot read password")}
			return
		}
		done <- result{value: strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-done:
		return value.value, value.err
	}
}

// Package app is the command-line adapter. Services never parse terminal input.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Alifarid0011/netkit/internal/diagnostic"
	linuxnet "github.com/Alifarid0011/netkit/internal/linux"
	"github.com/Alifarid0011/netkit/internal/transport"
)

var Version = "dev"

const help = `NETKIT  ·  Linux network workbench

Observe, understand, then change.

  netkit ip                              Interfaces and routes
  netkit ports                           Local listeners (ss)
  netkit doctor [flags] HOST[:PORT]|URL   DNS → TCP → TLS → HTTP
  netkit probe [flags] HOST:PORT          Repeated TCP latency checks
  netkit ping [flags] HOST                ICMP via system ping
  netkit proxy --to URL [--listen ADDR]   Foreground reverse proxy
  netkit capture [flags]                 Bounded packet capture (tcpdump)
  netkit pcap FILE                       Read a saved capture
  netkit firewall list|plan|apply|remove [flags]  Managed nftables rules
  netkit router list|add|remove [flags]   MikroTik RouterOS 7 HTTPS REST
  netkit tor start|check [flags]         Dedicated Tor / SOCKS-routed IP check
  netkit tui                            Live dashboard (q + Enter to quit)
  netkit version

  --explain  Explain method and limits.  --json  Versioned machine output.
  Put command-specific flags before positional arguments. --help for options.
  Optional Linux backends: ip, ss, ping, tcpdump, nft, tor.
  No network settings change merely by opening the dashboard.
`

type output struct {
	out, diagnostics io.Writer
	json, explain    bool
}

func (o output) result(v any) error {
	if o.json {
		return json.NewEncoder(o.out).Encode(struct {
			Schema int `json:"schema_version"`
			Data   any `json:"data"`
		}{1, v})
	}
	switch x := v.(type) {
	case string:
		fmt.Fprintln(o.out, safeText(x))
	case diagnostic.PortsReport:
		fmt.Fprintln(o.out, safeText(x.Output))
	default:
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(o.out, safeText(string(b)))
	}
	return nil
}
func (o output) note(s string) {
	if o.explain {
		fmt.Fprintln(o.diagnostics, "EXPLAIN: "+s)
	}
}
func (o output) fail(err error, code int) int {
	if o.json {
		b, _ := json.MarshalIndent(struct {
			Schema int    `json:"schema_version"`
			Error  string `json:"error"`
		}{1, err.Error()}, "", "  ")
		fmt.Fprintln(o.out, string(b))
	} else {
		fmt.Fprintln(o.diagnostics, "netkit: "+safeText(err.Error()))
	}
	return code
}
func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == 127 || (r < 32 && r != '\n' && r != '\t') || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}
func flags(name string, o output) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(o.diagnostics)
	return f
}
func parse(f *flag.FlagSet, args []string) error { return f.Parse(args) }
func Run(ctx context.Context, args []string, out, diagnostics io.Writer) int {
	o := output{out: out, diagnostics: diagnostics}
	var filtered []string
	for _, arg := range args {
		switch arg {
		case "--json":
			o.json = true
		case "--explain":
			o.explain = true
		default:
			filtered = append(filtered, arg)
		}
	}
	args = filtered
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, help)
		return 0
	}
	cmd := args[0]
	args = args[1:]
	if o.json && (cmd == "tui" || cmd == "proxy" || cmd == "capture" || cmd == "pcap" || cmd == "ping" || (cmd == "tor" && len(args) > 0 && args[0] == "start")) {
		return o.fail(errors.New("--json is unavailable for streaming commands"), 2)
	}
	switch cmd {
	case "version":
		if len(args) > 0 {
			return o.fail(errors.New("version takes no arguments"), 2)
		}
		if err := o.result(map[string]string{"version": Version, "platform": "linux", "schema": "1"}); err != nil {
			return o.fail(err, 1)
		}
		return 0
	case "ip", "ports":
		if len(args) > 0 {
			return o.fail(errors.New("command takes no arguments; use --explain or --json"), 2)
		}
		var v any
		var err error
		if cmd == "ip" {
			o.note("iproute2 queries addresses and routes in this process's network namespace; configured IPs are not necessarily public egress IPs.")
			v, err = diagnostic.IP(ctx)
		} else {
			o.note("ss lists local listening TCP/UDP sockets; listening does not prove remote reachability. Process names require permission.")
			v, err = diagnostic.Ports(ctx)
		}
		if err != nil {
			return o.fail(err, 1)
		}
		if err = o.result(v); err != nil {
			return o.fail(err, 1)
		}
		return 0
	case "doctor":
		f := flags(cmd, o)
		timeout := f.Duration("timeout", 3*time.Second, "per-stage timeout (0 < timeout <= 1m)")
		if err := parse(f, args); err != nil {
			return flagError(o, err)
		}
		if f.NArg() != 1 {
			return o.fail(errors.New("doctor requires one host:port or URL"), 2)
		}
		if *timeout <= 0 || *timeout > time.Minute {
			return o.fail(errors.New("timeout must be >0 and <=1m"), 2)
		}
		target := f.Arg(0)
		if !strings.Contains(target, "://") {
			if _, _, err := net.SplitHostPort(target); err != nil {
				target = "https://" + target
			}
		}
		o.note("Stages test DNS, each resolved address, verified TLS, and HTTP where applicable. A timeout cannot identify which firewall or route caused it. Bare hosts use HTTPS.")
		if err := validateDoctorTarget(target); err != nil {
			return o.fail(err, 2)
		}
		report, err := diagnostic.Doctor(ctx, target, *timeout)
		if err != nil {
			return o.fail(err, 1)
		}
		if o.json {
			if err = o.result(report); err != nil {
				return o.fail(err, 1)
			}
		} else {
			renderDoctor(out, report)
		}
		for _, s := range report.Stages {
			if !s.OK {
				return 1
			}
		}
		return 0
	case "probe":
		f := flags(cmd, o)
		count := f.Int("count", 5, "sample count (1..1000)")
		interval := f.Duration("interval", time.Second, "delay between samples")
		timeout := f.Duration("timeout", 3*time.Second, "TCP timeout")
		watch := f.Bool("watch", false, "repeat until interrupted")
		if err := parse(f, args); err != nil {
			return flagError(o, err)
		}
		if f.NArg() != 1 {
			return o.fail(errors.New("probe requires host:port"), 2)
		}
		if o.json && *watch {
			return o.fail(errors.New("--watch is streaming; omit --json"), 2)
		}
		if *count < 1 || *count > 1000 || *interval < 0 || *interval > time.Minute || *timeout <= 0 || *timeout > time.Minute {
			return o.fail(errors.New("count must be 1..1000, interval 0..1m and timeout >0..1m"), 2)
		}
		if err := validateAddress(f.Arg(0)); err != nil {
			return o.fail(err, 2)
		}
		o.note("Measures new TCP connections, not ICMP or throughput; failures may have many causes. Watch retains only the current batch.")
		for {
			samples, err := diagnostic.Probe(ctx, f.Arg(0), *count, *interval, *timeout)
			if err != nil {
				if ctx.Err() != nil && *watch {
					return 0
				}
				return o.fail(err, 1)
			}
			if o.json {
				if err = o.result(samples); err != nil {
					return o.fail(err, 1)
				}
			} else {
				for _, s := range samples {
					status := "OK"
					if !s.OK {
						status = "FAIL"
					}
					fmt.Fprintf(out, "%4d  %-4s  %8.2f ms  %s\n", s.Sequence, status, s.DurationMS, safeText(s.Error))
				}
			}
			if !*watch {
				for _, s := range samples {
					if !s.OK {
						return 1
					}
				}
				return 0
			}
			select {
			case <-ctx.Done():
				return 0
			case <-time.After(*interval):
			}
		}
	case "proxy":
		f := flags(cmd, o)
		listen := f.String("listen", "127.0.0.1:8080", "local listen address")
		to := f.String("to", "", "HTTP(S) upstream URL")
		if err := parse(f, args); err != nil {
			return flagError(o, err)
		}
		if f.NArg() != 0 {
			return o.fail(errors.New("proxy takes flags only"), 2)
		}
		o.note("Runs in foreground; Ctrl+C stops it. Only this listener is proxied; no system routes or firewall rules change.")
		if err := transport.ServeProxy(ctx, *listen, *to, diagnostics); err != nil {
			return o.fail(err, 1)
		}
		return 0
	case "capture":
		f := flags(cmd, o)
		iface := f.String("interface", "", "interface, e.g. eth0 or any")
		filter := f.String("filter", "", "tcpdump capture expression, e.g. tcp port 443")
		file := f.String("output", "", "new PCAP path (never overwrite)")
		duration := f.Duration("duration", 10*time.Second, "capture duration (bounded)")
		count := f.Int("count", 100, "packet limit")
		if err := parse(f, args); err != nil {
			return flagError(o, err)
		}
		if f.NArg() != 0 {
			return o.fail(errors.New("capture takes flags only"), 2)
		}
		o.note("Captures only traffic visible on the chosen interface; TLS payload remains encrypted. tcpdump prints capture-drop statistics. Recording requires capture privileges.")
		if err := linuxnet.Capture(ctx, linuxnet.CaptureOptions{Interface: *iface, Filter: *filter, Output: *file, Duration: *duration, Count: *count}, out, diagnostics); err != nil {
			return o.fail(err, 1)
		}
		return 0
	case "pcap":
		if len(args) != 1 {
			return o.fail(errors.New("pcap requires one saved capture path"), 2)
		}
		if err := linuxnet.InspectPCAP(ctx, args[0], out, diagnostics); err != nil {
			return o.fail(err, 1)
		}
		return 0
	case "firewall":
		return firewall(ctx, args, o)
	case "router":
		return router(ctx, args, o)
	case "tor":
		return tor(ctx, args, o)
	case "tui":
		if len(args) > 0 {
			return o.fail(errors.New("tui takes no arguments"), 2)
		}
		if err := dashboard(ctx, out, diagnostics); err != nil {
			return o.fail(err, 1)
		}
		return 0
	case "ping":
		f := flags(cmd, o)
		count := f.Int("count", 4, "ICMP request count (1..100)")
		if err := parse(f, args); err != nil {
			return flagError(o, err)
		}
		if f.NArg() != 1 || strings.HasPrefix(f.Arg(0), "-") || *count < 1 || *count > 100 {
			return o.fail(errors.New("ping requires HOST and count 1..100"), 2)
		}
		o.note("ICMP via Linux ping; some networks block ICMP while TCP still works.")
		c := exec.CommandContext(ctx, "ping", "-n", "-c", fmt.Sprint(*count), "-W", "2", "--", f.Arg(0))
		c.Stdout = out
		c.Stderr = diagnostics
		if err := c.Run(); err != nil {
			if ctx.Err() != nil {
				return 0
			}
			return o.fail(err, 1)
		}
		return 0
	default:
		return o.fail(fmt.Errorf("unknown command %q; run netkit help", cmd), 2)
	}
}
func flagError(o output, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return o.fail(err, 2)
}
func renderDoctor(out io.Writer, r diagnostic.Report) {
	fmt.Fprintf(out, "NETWORK DIAGNOSIS  %s\n\n", safeText(r.Target))
	for _, s := range r.Stages {
		status := "PASS"
		if !s.OK {
			status = "FAIL"
		}
		detail := s.Detail
		if s.Error != "" {
			detail = s.Error
		}
		fmt.Fprintf(out, "  %-4s  %-8s %-22s %8.2f ms  %s\n", status, safeText(s.Name), safeText(s.Address), s.DurationMS, safeText(detail))
	}
}

func validateAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\\t\r\n@?#") {
		return errors.New("target requires a valid host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("port must be 1..65535")
	}
	return nil
}
func validateDoctorTarget(value string) error {
	if !strings.Contains(value, "://") {
		return validateAddress(value)
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" || u.Fragment != "" {
		return errors.New("doctor requires an HTTP(S) URL without credentials or fragment")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return validateAddress(net.JoinHostPort(u.Hostname(), port))
}

package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Alifarid0011/netkit/internal/diagnostic"
)

func dashboard(ctx context.Context, out, diagnostics io.Writer) error {
	terminal, ok := out.(*os.File)
	if !ok {
		return errors.New("dashboard needs an interactive terminal; use netkit ip --json for scripts")
	}
	info, err := terminal.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 || os.Getenv("TERM") == "dumb" {
		return errors.New("dashboard needs an interactive terminal")
	}
	input := make(chan string, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			select {
			case input <- strings.TrimSpace(scanner.Text()):
			case <-done:
				return
			}
		}
		select {
		case input <- "q":
		case <-done:
		}
	}()
	fmt.Fprint(out, "\x1b[?1049h\x1b[?25l")
	defer fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")
	page := "overview"
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	render := func() {
		fmt.Fprint(out, "\x1b[H\x1b[2J")
		fmt.Fprintf(out, "\x1b[1;36m NETKIT\x1b[0m  LINUX NETWORK WORKBENCH     %s\n", time.Now().Format("15:04:05"))
		fmt.Fprintln(out, " ──────────────────────────────────────────────────────────────")
		fmt.Fprintln(out, " [i] interfaces & routes    [p] listeners    [h] learn    [q] quit")
		fmt.Fprintln(out, " Type a key then Enter. Refresh: 3s. Read-only; this namespace.")
		fmt.Fprintln(out, " ──────────────────────────────────────────────────────────────")
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		switch page {
		case "ports":
			ports, err := diagnostic.Ports(work)
			if err != nil {
				fmt.Fprintln(out, safeText(err.Error()))
				return
			}
			lines := strings.Split(safeText(ports.Output), "\n")
			if len(lines) > 18 {
				lines = append(lines[:18], "… more listeners: netkit ports")
			}
			fmt.Fprintln(out, strings.Join(lines, "\n"))
		case "help":
			fmt.Fprintln(out, " LISTENING ≠ REACHABLE\n A listener is a local socket. Routes, NAT and firewalls decide\n whether another machine can reach it.\n\n DIAGNOSE BY LAYER\n netkit doctor --explain example.com\n DNS → TCP → verified TLS → HTTP\n\n CAPTURE AT THE RIGHT PLACE\n netkit capture --interface eth0 --filter 'tcp port 443'\n Encrypted payloads remain encrypted.\n\n CHANGE WITH CONTEXT\n netkit firewall plan --action block --port 8080 --explain\n Review a plan before changing any device.")
		default:
			report, err := diagnostic.IP(work)
			if err != nil {
				fmt.Fprintln(out, safeText(err.Error()))
				return
			}
			var addresses []struct {
				IfName string `json:"ifname"`
				State  string `json:"operstate"`
				Info   []struct {
					Local  string `json:"local"`
					Prefix int    `json:"prefixlen"`
				} `json:"addr_info"`
			}
			if err := json.Unmarshal(report.Addresses, &addresses); err != nil {
				fmt.Fprintln(out, "Cannot decode interface data")
				return
			}
			for i, iface := range addresses {
				if i >= 12 {
					fmt.Fprintln(out, " … more: netkit ip")
					break
				}
				var ips []string
				for _, a := range iface.Info {
					ips = append(ips, fmt.Sprintf("%s/%d", a.Local, a.Prefix))
				}
				fmt.Fprintf(out, " %-14s %-9s %s\n", safeText(iface.IfName), safeText(iface.State), safeText(strings.Join(ips, ", ")))
			}
			fmt.Fprintln(out, "\n ROUTES")
			var routes []struct{ Dst, Gateway, Dev string }
			if err := json.Unmarshal(report.Routes, &routes); err != nil {
				fmt.Fprintln(out, "Cannot decode route data")
				return
			}
			for i, r := range routes {
				if i >= 6 {
					fmt.Fprintln(out, " … more: netkit ip")
					break
				}
				fmt.Fprintf(out, " %-20s via %-18s dev %s\n", safeText(r.Dst), safeText(r.Gateway), safeText(r.Dev))
			}
		}
	}
	render()
	for {
		select {
		case <-ctx.Done():
			return nil
		case line := <-input:
			switch line {
			case "q", "quit", "exit":
				return nil
			case "p":
				page = "ports"
			case "i":
				page = "overview"
			case "h", "?":
				page = "help"
			}
			render()
		case <-ticker.C:
			render()
		}
	}
}

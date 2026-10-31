// Package diagnostic provides bounded, read-only network observations.
package diagnostic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const maxAddresses = 16

type Stage struct {
	Name       string  `json:"name"`
	Address    string  `json:"address,omitempty"`
	DurationMS float64 `json:"duration_ms"`
	OK         bool    `json:"ok"`
	Error      string  `json:"error,omitempty"`
	Detail     string  `json:"detail,omitempty"`
}
type Report struct {
	Target    string   `json:"target"`
	Host      string   `json:"host"`
	Port      string   `json:"port"`
	Addresses []string `json:"addresses"`
	Truncated bool     `json:"truncated"`
	Stages    []Stage  `json:"stages"`
}
type Sample struct {
	Sequence   int     `json:"sequence"`
	Address    string  `json:"address"`
	DurationMS float64 `json:"duration_ms"`
	OK         bool    `json:"ok"`
	Error      string  `json:"error,omitempty"`
}
type IPReport struct {
	Method    string          `json:"method"`
	Addresses json.RawMessage `json:"addresses"`
	Routes    json.RawMessage `json:"routes"`
}
type PortsReport struct {
	Method string `json:"method"`
	Output string `json:"output"`
}

func validTimeout(timeout time.Duration) error {
	if timeout <= 0 || timeout > time.Minute {
		return errors.New("timeout must be greater than zero and at most one minute")
	}
	return nil
}
func addressParts(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\\t\r\n@?#") {
		return "", "", errors.New("target must contain a valid host and numeric port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", "", errors.New("port must be between 1 and 65535")
	}
	return host, port, nil
}
func parseTarget(target string) (string, string, *url.URL, error) {
	if len(target) > 4096 {
		return "", "", nil, errors.New("target exceeds 4096 bytes")
	}
	if !strings.Contains(target, "://") {
		h, p, e := addressParts(target)
		return h, p, nil, e
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", "", nil, errors.New("target must be an HTTP(S) URL without credentials or fragment")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	host, port, err := addressParts(net.JoinHostPort(u.Hostname(), port))
	return host, port, u, err
}

// Doctor resolves a target and checks at most 16 addresses. Targets are host:port
// or HTTP(S) URLs. Stage failures are observations; errors denote invalid input
// or cancellation. A timeout does not establish a firewall diagnosis.
func Doctor(ctx context.Context, target string, timeout time.Duration) (Report, error) {
	report := Report{Target: target, Addresses: []string{}, Stages: []Stage{}}
	if err := validTimeout(timeout); err != nil {
		return report, err
	}
	host, port, u, err := parseTarget(target)
	if err != nil {
		return report, err
	}
	report.Host = host
	report.Port = port
	if err := ctx.Err(); err != nil {
		return report, err
	}
	started := time.Now()
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	ips, lookupErr := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	cancel()
	stage := makeStage("dns", "", started, lookupErr)
	report.Stages = append(report.Stages, stage)
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if lookupErr != nil {
		return report, nil
	}
	if len(ips) > maxAddresses {
		ips = ips[:maxAddresses]
		report.Truncated = true
	}
	for _, ip := range ips {
		address := net.JoinHostPort(ip.String(), port)
		report.Addresses = append(report.Addresses, address)
		started = time.Now()
		dialCtx, stop := context.WithTimeout(ctx, timeout)
		conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
		stop()
		report.Stages = append(report.Stages, makeStage("tcp", address, started, dialErr))
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if dialErr != nil {
			continue
		}
		_ = conn.Close()
		if u == nil {
			continue
		}
		if u.Scheme == "https" {
			started = time.Now()
			tlsCtx, stop := context.WithTimeout(ctx, timeout)
			tlsConn, tlsErr := (&tls.Dialer{Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}).DialContext(tlsCtx, "tcp", address)
			stop()
			report.Stages = append(report.Stages, makeStage("tls", address, started, tlsErr))
			if tlsErr == nil {
				_ = tlsConn.Close()
			}
			if err := ctx.Err(); err != nil {
				return report, err
			}
			if tlsErr != nil {
				continue
			}
		}
		started = time.Now()
		requestCtx, stop := context.WithTimeout(ctx, timeout)
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, u.String(), nil)
		if requestErr != nil {
			stop()
			return report, fmt.Errorf("create HTTP request: %w", requestErr)
		}
		resp, httpErr := client.Do(req)
		stage = makeStage("http", address, started, httpErr)
		if resp != nil {
			stage.Detail = resp.Status
			stage.OK = resp.StatusCode < 400
			_ = resp.Body.Close()
		}
		stop()
		transport.CloseIdleConnections()
		report.Stages = append(report.Stages, stage)
		if err := ctx.Err(); err != nil {
			return report, err
		}
	}
	return report, nil
}
func makeStage(name, address string, started time.Time, err error) Stage {
	s := Stage{Name: name, Address: address, DurationMS: float64(time.Since(started)) / float64(time.Millisecond), OK: err == nil}
	if err != nil {
		s.Error = err.Error()
	}
	return s
}

// Probe measures TCP connection setup, not ICMP loss. Count is capped at 1000;
// interval and each connection timeout are capped at one minute.
func Probe(ctx context.Context, address string, count int, interval, timeout time.Duration) ([]Sample, error) {
	if _, _, err := addressParts(address); err != nil {
		return nil, err
	}
	if err := validTimeout(timeout); err != nil {
		return nil, err
	}
	if count < 1 || count > 1000 || interval < 0 || interval > time.Minute {
		return nil, errors.New("count must be 1..1000 and interval 0..1 minute")
	}
	samples := make([]Sample, 0, count)
	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return samples, err
		}
		if i > 0 && interval > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return samples, ctx.Err()
			case <-timer.C:
			}
		}
		started := time.Now()
		sampleCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := (&net.Dialer{}).DialContext(sampleCtx, "tcp", address)
		cancel()
		s := Sample{Sequence: i + 1, Address: address, DurationMS: float64(time.Since(started)) / float64(time.Millisecond), OK: err == nil}
		if err != nil {
			s.Error = err.Error()
		} else {
			_ = conn.Close()
		}
		samples = append(samples, s)
		if err := ctx.Err(); err != nil {
			return samples, err
		}
	}
	return samples, nil
}

// IP returns configured addresses and IPv4/IPv6 routes as iproute2 JSON,
// not public IP. Routes preserve backend order, with IPv6 appended to IPv4.
func IP(ctx context.Context) (IPReport, error) {
	r := IPReport{Method: "ip -j address; ip -j route; ip -6 -j route (routes tagged with family)"}
	addresses, err := command(ctx, "ip", "-j", "address")
	if err != nil {
		return r, err
	}
	if _, err := objectArray(addresses); err != nil {
		return r, fmt.Errorf("ip address: %w", err)
	}
	r.Addresses = addresses
	merged := make([]map[string]json.RawMessage, 0)
	for _, family := range []string{"ipv4", "ipv6"} {
		args := []string{"-j", "route"}
		if family == "ipv6" {
			args = []string{"-6", "-j", "route"}
		}
		data, err := command(ctx, "ip", args...)
		if err != nil {
			return r, err
		}
		routes, err := objectArray(data)
		if err != nil {
			return r, fmt.Errorf("ip %s route: %w", family, err)
		}
		for _, route := range routes {
			route["family"] = json.RawMessage(strconv.Quote(family))
			merged = append(merged, route)
		}
	}
	data, err := json.Marshal(merged)
	if err != nil {
		return r, fmt.Errorf("encode routes: %w", err)
	}
	r.Routes = data
	return r, nil
}

func objectArray(data []byte) ([]map[string]json.RawMessage, error) {
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal(data, &objects); err != nil {
		return nil, fmt.Errorf("expected JSON array of objects: %w", err)
	}
	if objects == nil {
		return nil, errors.New("expected JSON array of objects, got null")
	}
	for _, object := range objects {
		if object == nil {
			return nil, errors.New("expected JSON object, got null element")
		}
	}
	return objects, nil
}

// Ports preserves ss output because its process attribution varies by privilege
// and version. Local listeners do not establish remote reachability.
func Ports(ctx context.Context) (PortsReport, error) {
	r := PortsReport{Method: "ss -H -l -n -t -u -p (raw output; process attribution depends on permissions)"}
	output, err := command(ctx, "ss", "-H", "-l", "-n", "-t", "-u", "-p")
	r.Output = string(output)
	return r, err
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	// Bound output in memory while allowing the process to complete normally.
	out := &limitedBuffer{limit: 4 << 20}
	stderr := &limitedBuffer{limit: 4096}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.data, ctx.Err()
	}
	if err != nil {
		return out.data, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(stderr.data)))
	}
	if out.truncated {
		return out.data, fmt.Errorf("%s output exceeds 4 MiB", name)
	}
	return out.data, nil
}

type limitedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	b.data = append(b.data, p...)
	return n, nil
}

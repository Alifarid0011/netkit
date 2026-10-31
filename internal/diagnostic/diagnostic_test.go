package diagnostic

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDoctorHTTP(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer s.Close()
	report, err := Doctor(context.Background(), s.URL+"/health", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Stages) != 3 || report.Stages[0].Name != "dns" || report.Stages[1].Name != "tcp" || report.Stages[2].Name != "http" {
		t.Fatalf("stages: %+v", report.Stages)
	}
	if report.Stages[2].OK || report.Stages[2].Detail != "503 Service Unavailable" {
		t.Fatalf("HTTP: %+v", report.Stages[2])
	}
}
func TestDoctorTLSValidation(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer s.Close()
	report, err := Doctor(context.Background(), s.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Stages) != 3 || report.Stages[2].Name != "tls" || report.Stages[2].OK || report.Stages[2].Error == "" {
		t.Fatalf("stages: %+v", report.Stages)
	}
}
func TestDoctorClosedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	r, err := Doctor(context.Background(), address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Stages) != 2 || r.Stages[1].OK || r.Stages[1].Error == "" {
		t.Fatalf("stages: %+v", r.Stages)
	}
}
func TestInvalidInputs(t *testing.T) {
	for _, target := range []string{"", "ftp://example.com", "http://user:pass@example.com", "http://example.com:0", "http://example.com:65536", "a b:80", "localhost", "http://example.com/#fragment"} {
		t.Run(target, func(t *testing.T) {
			if _, err := Doctor(context.Background(), target, time.Second); err == nil {
				t.Fatal("wanted target error")
			}
		})
	}
	for _, tc := range []struct {
		count             int
		interval, timeout time.Duration
	}{{0, 0, time.Second}, {1001, 0, time.Second}, {1, -1, time.Second}, {1, 0, 0}, {1, 0, 2 * time.Minute}} {
		if _, err := Probe(context.Background(), "127.0.0.1:80", tc.count, tc.interval, tc.timeout); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
func TestProbeAndCancellation(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	samples, err := Probe(context.Background(), l.Addr().String(), 2, 0, time.Second)
	if err != nil || len(samples) != 2 || !samples[0].OK || samples[1].Sequence != 2 {
		t.Fatalf("%+v %v", samples, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Probe(ctx, l.Addr().String(), 2, time.Minute, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := Doctor(ctx, "127.0.0.1:80", time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestDoctorDoesNotFollowRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed redirect") }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer source.Close()
	report, err := Doctor(context.Background(), source.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	last := report.Stages[len(report.Stages)-1]
	if last.Detail != "302 Found" {
		t.Fatalf("stage: %+v", last)
	}
}

func TestDoctorHTTPTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	report, err := Doctor(context.Background(), s.URL, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	stage := report.Stages[len(report.Stages)-1]
	if stage.Name != "http" || stage.OK || stage.Error == "" {
		t.Fatalf("stage: %+v", stage)
	}
}

func TestInspectionTools(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	writeTool := func(name, script string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeTool("ip", `case "$*" in
'-j address') printf '[{"ifname":"lo"}]';;
'-j route') printf '[{"dst":"default"},{"dst":"192.0.2.0/24"}]';;
'-6 -j route') printf '[{"dst":"default","gateway":"fe80::1"}]';;
*) exit 9;;
esac
`)
	writeTool("ss", `[ "$*" = '-H -l -n -t -u -p' ] || exit 9
printf 'tcp LISTEN 127.0.0.1:80\n'
`)
	ip, err := IP(context.Background())
	if err != nil || string(ip.Addresses) != `[{"ifname":"lo"}]` || string(ip.Routes) != `[{"dst":"default","family":"ipv4"},{"dst":"192.0.2.0/24","family":"ipv4"},{"dst":"default","family":"ipv6","gateway":"fe80::1"}]` || !strings.Contains(ip.Method, "ip -6 -j route") {
		t.Fatalf("IP: %+v %v", ip, err)
	}
	ports, err := Ports(context.Background())
	if err != nil || ports.Output != "tcp LISTEN 127.0.0.1:80\n" || !strings.Contains(ports.Method, "raw output") {
		t.Fatalf("Ports: %+v %v", ports, err)
	}
	writeTool("ip", "printf 'not json'\n")
	if _, err := IP(context.Background()); err == nil {
		t.Fatal("accepted invalid ip JSON")
	}
	writeTool("ss", "printf 'fixture denied' >&2\nexit 1\n")
	if _, err := Ports(context.Background()); err == nil || !strings.Contains(err.Error(), "fixture denied") {
		t.Fatalf("tool error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := IP(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("IP cancel: %v", err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := Ports(context.Background()); err == nil {
		t.Fatal("expected missing backend error")
	}
}

func TestIPRejectsWrongJSONShapes(t *testing.T) {
	for _, shape := range []string{`null`, `{}`, `[null]`, `[1]`, `["route"]`} {
		for _, stage := range []string{"address", "route", "v6"} {
			t.Run(stage+shape, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("PATH", dir)
				output := func(s string) string {
					if s == stage {
						return shape
					}
					return "[]"
				}
				script := "#!/bin/sh\ncase \"$*\" in\n'-j address') printf '%s' '" + output("address") + "';;\n'-j route') printf '%s' '" + output("route") + "';;\n'-6 -j route') printf '%s' '" + output("v6") + "';;\nesac\n"
				if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				if _, err := IP(context.Background()); err == nil {
					t.Fatal("accepted wrong JSON shape")
				}
			})
		}
	}
}

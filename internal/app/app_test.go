package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHelpAndErrors(t *testing.T) {
	for _, tt := range []struct {
		args []string
		code int
		want string
	}{{nil, 0, "doctor"}, {[]string{"help"}, 0, "capture"}, {[]string{"nonsense"}, 2, "unknown command"}, {[]string{"probe"}, 2, "host:port"}, {[]string{"doctor", "--timeout=-1s", "example.com"}, 2, "timeout"}, {[]string{"proxy", "--json"}, 2, "streaming"}, {[]string{"tor", "nonsense"}, 2, "tor"}} {
		var out, err bytes.Buffer
		code := Run(context.Background(), tt.args, &out, &err)
		if code != tt.code || !strings.Contains(out.String()+err.String(), tt.want) {
			t.Errorf("%v code=%d out=%s err=%s", tt.args, code, &out, &err)
		}
	}
}
func TestJSONError(t *testing.T) {
	var out, err bytes.Buffer
	code := Run(context.Background(), []string{"probe", "--json"}, &out, &err)
	if code != 2 || !strings.Contains(out.String(), `"schema_version": 1`) || !strings.Contains(out.String(), `"error"`) {
		t.Fatalf("%d %s %s", code, &out, &err)
	}
}
func TestFirewallPlanNoMutation(t *testing.T) {
	var out, err bytes.Buffer
	code := Run(context.Background(), []string{"firewall", "plan", "--action=block", "--protocol=tcp", "--port=12345", "--json"}, &out, &err)
	if code != 0 || !strings.Contains(out.String(), `"data"`) {
		t.Fatalf("%d %s %s", code, &out, &err)
	}
}
func TestSanitizeTerminal(t *testing.T) {
	if got := safeText("hello\x1b[2J\rworld\a"); strings.ContainsAny(got, "\x1b\r\a") {
		t.Fatalf("unsafe %q", got)
	}
}

func TestRouterPreviewValidation(t *testing.T) {
	for _, args := range [][]string{{"router", "add", "--action=invalid"}, {"router", "remove", "--id=0"}, {"router", "add", "--url=https://user:secret@router.local"}} {
		var out, err bytes.Buffer
		if code := Run(context.Background(), args, &out, &err); code != 2 {
			t.Errorf("accepted %v: %d %s", args, code, &out)
		}
	}
}
func TestRouterPreviewNoCredentialsNeeded(t *testing.T) {
	var out, err bytes.Buffer
	if code := Run(context.Background(), []string{"router", "add", "--action=block", "--port=8080", "--json"}, &out, &err); code != 0 || !strings.Contains(out.String(), `"preview":true`) {
		t.Fatalf("%d %s %s", code, &out, &err)
	}
}
func TestDoctorHTTPAndFailureExit(t *testing.T) {
	for _, status := range []int{200, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		var out, err bytes.Buffer
		code := Run(context.Background(), []string{"doctor", server.URL, "--json", "--explain"}, &out, &err)
		server.Close()
		expected := 0
		if status == 503 {
			expected = 1
		}
		if code != expected || !strings.Contains(out.String(), `"stages"`) || !strings.Contains(err.String(), "EXPLAIN:") {
			t.Fatalf("%d %s %s", code, &out, &err)
		}
	}
}
func TestCancelledJSONProbeReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, err bytes.Buffer
	code := Run(ctx, []string{"probe", "--json", "127.0.0.1:1"}, &out, &err)
	if code == 0 || !strings.Contains(out.String(), `"error"`) {
		t.Fatalf("cancelled probe: %d %s %s", code, &out, &err)
	}
}
func TestFirewallRequiresExplicitConfirmation(t *testing.T) {
	for _, args := range [][]string{{"firewall", "apply", "--port=8080"}, {"firewall", "remove", "--id=anything"}} {
		var out, err bytes.Buffer
		if code := Run(context.Background(), args, &out, &err); code != 2 || !strings.Contains(err.String(), "--confirm") {
			t.Fatalf("%v: %d %s", args, code, &err)
		}
	}
}
func TestCLIValidationExitCodes(t *testing.T) {
	for _, args := range [][]string{{"probe", "--count=0", "localhost:80"}, {"doctor", "ftp://example.com"}, {"probe", "localhost:99999"}} {
		var out, err bytes.Buffer
		if code := Run(context.Background(), args, &out, &err); code != 2 {
			t.Fatalf("%v code=%d %s", args, code, &err)
		}
	}
}

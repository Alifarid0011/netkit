package routeros

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(s.URL, "operator", "secret-password", ca)
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func TestListTLSAuthAndAllowedResources(t *testing.T) {
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "operator" || p != "secret-password" {
			t.Error("missing auth")
		}
		if r.Method != "GET" || r.URL.Path != "/rest/system/resource" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"version":"7.20"}`)
	})
	got, err := c.List(context.Background(), "system/resource")
	if err != nil || got.(map[string]any)["version"] != "7.20" {
		t.Fatalf("%v %v", got, err)
	}
	untrusted, err := New(s.URL, "operator", "secret-password", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = untrusted.List(context.Background(), "system/resource"); err == nil {
		t.Fatal("accepted untrusted cert")
	}
}

func TestValidationBeforeNetwork(t *testing.T) {
	for _, u := range []string{"http://router", "https://user:password@router", "https://router/rest/../system", "https://router?token=x", "https://router#x", "https://router/elsewhere", "https://router/rest%2f"} {
		if _, err := New(u, "operator", "secret", ""); err == nil {
			t.Errorf("accepted URL %q", u)
		}
	}
	c, err := New("https://router/rest", "operator", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/interface", "../system/reset", "ip/firewall/filter/*1", "system/script", "interface?x=y", "interface/", "ip%2faddress"} {
		if _, err := c.List(context.Background(), p); err == nil {
			t.Errorf("accepted path %q", p)
		}
	}
	for _, id := range []string{"0", "*", "*1/../reset", "*1?x=y", "%2A1", "*xyz"} {
		if err := c.RemoveRule(context.Background(), id); err == nil {
			t.Errorf("accepted ID %q", id)
		}
	}
	for _, rule := range []Rule{{Action: "accept", Chain: "input"}, {Action: "allow", Chain: "output"}, {Action: "allow", Chain: "input", Source: "::/0"}, {Action: "allow", Chain: "input", Destination: "1.2.3.4"}, {Action: "allow", Chain: "input", Protocol: "icmp", Port: 80}, {Action: "block", Chain: "forward", Protocol: "tcp", Port: 65536}, {Action: "allow", Chain: "input", Protocol: "tcp;reboot"}} {
		if _, err := c.AddRule(context.Background(), rule); err == nil {
			t.Errorf("accepted rule %+v", rule)
		}
	}
}

func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	var hits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer sink.Close()
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", sink.URL+"/secret-password")
		w.WriteHeader(http.StatusFound)
	})
	_, err := c.List(context.Background(), "interface")
	if err == nil || hits.Load() != 0 {
		t.Fatalf("redirect followed: %v hits %d", err, hits.Load())
	}
	if strings.Contains(err.Error(), "secret-password") {
		t.Fatal("credential leaked")
	}
}

func TestAddRuleDisabledAndExplicitEnable(t *testing.T) {
	var bodies []map[string]string
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/rest/ip/firewall/filter" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{".id":"*A"}`)
	})
	for _, enable := range []bool{false, true} {
		_, err := c.AddRule(context.Background(), Rule{Action: "allow", Chain: "input", Source: "192.0.2.0/24", Destination: "198.51.100.1/32", Protocol: "tcp", Port: 443, Enable: enable})
		if err != nil {
			t.Fatal(err)
		}
	}
	if bodies[0]["disabled"] != "true" || bodies[1]["disabled"] != "false" || bodies[0]["comment"] != OwnerComment || bodies[0]["action"] != "accept" || bodies[0]["dst-port"] != "443" || bodies[0]["src-address"] != "192.0.2.0/24" {
		t.Fatalf("bodies: %#v", bodies)
	}
}

func TestRemoveOnlyOwnedStableID(t *testing.T) {
	for _, comment := range []string{OwnerComment, "operator rule", OwnerComment + " extra"} {
		t.Run(comment, func(t *testing.T) {
			var deletes int
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/rest/ip/firewall/filter/*A" {
					t.Errorf("path %q", r.URL.Path)
				}
				if r.Method == "GET" {
					json.NewEncoder(w).Encode(map[string]string{".id": "*A", "comment": comment})
					return
				}
				if r.Method != "DELETE" {
					t.Errorf("method %q", r.Method)
				}
				deletes++
				w.WriteHeader(http.StatusNoContent)
			})
			err := c.RemoveRule(context.Background(), "*A")
			if comment == OwnerComment {
				if err != nil || deletes != 1 {
					t.Fatalf("%v %d", err, deletes)
				}
			} else if err == nil || deletes != 0 {
				t.Fatalf("removed unowned: %v %d", err, deletes)
			}
		})
	}
}

func TestErrorsBoundedRedactedAndWriteUncertain(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{{"echo", "secret-password", 401}, {"large", strings.Repeat("x", (1<<20)+1), 200}, {"malformed", "{", 200}} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) })
			_, err := c.List(context.Background(), "interface")
			if err == nil || strings.Contains(err.Error(), "secret-password") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201); fmt.Fprint(w, "{") })
	_, err := c.AddRule(context.Background(), Rule{Action: "block", Chain: "forward"})
	if err == nil || !strings.Contains(err.Error(), "may have") {
		t.Fatalf("must report uncertain write: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.List(ctx, "interface"); err == nil {
		t.Fatal("expected cancellation")
	}
	if time.Since(start) > time.Second {
		t.Fatal("slow cancellation")
	}
}

func TestRemoveRefusesMismatchedIDAndReportsDeleteFailure(t *testing.T) {
	for _, id := range []string{"*B", "*A"} {
		t.Run(id, func(t *testing.T) {
			deletes := 0
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					json.NewEncoder(w).Encode(map[string]string{".id": id, "comment": OwnerComment})
					return
				}
				deletes++
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "secret-password")
			})
			err := c.RemoveRule(context.Background(), "*A")
			if err == nil || strings.Contains(err.Error(), "secret-password") {
				t.Fatalf("unsafe error: %v", err)
			}
			if id == "*B" && deletes != 0 {
				t.Fatal("deleted mismatched ID")
			}
			if id == "*A" && (deletes != 1 || !strings.Contains(err.Error(), "may have")) {
				t.Fatalf("delete status not preserved: %v", err)
			}
		})
	}
}

func TestPreviewValidationWithoutClient(t *testing.T) {
	for _, rule := range []Rule{{Action: "block", Chain: "input"}, {Action: "allow", Chain: "forward", Protocol: "udp", Port: 53, Source: "192.0.2.1/32"}} {
		if err := ValidateRule(rule); err != nil {
			t.Errorf("valid rule rejected: %v", err)
		}
	}
	for _, rule := range []Rule{{}, {Action: "allow", Chain: "input", Source: "::/0"}, {Action: "block", Chain: "forward", Protocol: "icmp", Port: 22}, {Action: "allow", Chain: "input", Destination: "bad"}} {
		if err := ValidateRule(rule); err == nil {
			t.Errorf("invalid preview rule accepted: %+v", rule)
		}
	}
	for _, id := range []string{"*1", "*ABcd"} {
		if err := ValidateID(id); err != nil {
			t.Errorf("valid ID rejected: %v", err)
		}
	}
	for _, id := range []string{"", "1", "*A/../reset", "*GG", "*" + strings.Repeat("1", 33)} {
		if err := ValidateID(id); err == nil {
			t.Errorf("invalid preview ID accepted: %q", id)
		}
	}
	var c *Client
	if _, err := c.AddRule(context.Background(), Rule{}); err == nil {
		t.Fatal("invalid rule used nil client")
	}
	if err := c.RemoveRule(context.Background(), "invalid"); err == nil {
		t.Fatal("invalid ID used nil client")
	}
}

package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProxyStreamingAndPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/base/hello" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("X-Test", "yes")
		io.WriteString(w, "hello")
	}))
	defer upstream.Close()
	handler, err := NewProxy(upstream.URL+"/base", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	resp, err := http.Get(server.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "hello" || resp.Header.Get("X-Test") != "yes" {
		t.Fatalf("%s", b)
	}
}
func TestProxyRejectTarget(t *testing.T) {
	for _, target := range []string{"ftp://host", "http://user:pass@host", "host", "http://host/#frag"} {
		if _, err := NewProxy(target, io.Discard); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}
func TestTorCheckRequiresSOCKS(t *testing.T) {
	for _, proxy := range []string{"http://127.0.0.1:9050", "socks5h://user:pass@localhost:9050", "socks5h://localhost"} {
		if _, err := TorCheck(context.Background(), proxy, "https://example.com", time.Second); err == nil {
			t.Errorf("accepted %s", proxy)
		}
	}
}
func TestTorCheckValidatesResponse(t *testing.T) {
	// Explicitly supplied dialer routes a fixture; production always uses SOCKS.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"IsTor":true,"IP":"203.0.113.1"}`) }))
	defer server.Close()
	result, err := checkTorWithClient(context.Background(), server.Client(), server.URL)
	if err != nil || !result.IsTor || result.IP != "203.0.113.1" {
		t.Fatalf("%+v %v", result, err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, strings.Repeat("x", 70000)) }))
	defer bad.Close()
	if _, err := checkTorWithClient(context.Background(), bad.Client(), bad.URL); err == nil {
		t.Fatal("expected invalid body error")
	}
}
func TestTorSOCKSURL(t *testing.T) {
	u, _ := url.Parse("socks5h://127.0.0.1:9050")
	if _, err := TorCheck(context.Background(), u.String(), "http://example.com", time.Second); err == nil {
		t.Fatal("accepted HTTP check")
	}
}

func TestTorCheckSOCKSRemoteDNS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			destination <- "accept failed"
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		var greeting [2]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			destination <- "greeting failed"
			return
		}
		methods := make([]byte, int(greeting[1]))
		io.ReadFull(conn, methods)
		conn.Write([]byte{5, 0})
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			destination <- "header failed"
			return
		}
		if header[3] != 3 {
			destination <- "not remote DNS"
			return
		}
		host := make([]byte, int(header[4]))
		io.ReadFull(conn, host)
		destination <- string(host)
		conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
	}()
	_, err = TorCheck(context.Background(), "socks5h://"+listener.Addr().String(), "https://must-not-resolve.invalid/api/ip", time.Second)
	if err == nil {
		t.Fatal("expected refused upstream")
	}
	select {
	case host := <-destination:
		if host != "must-not-resolve.invalid" {
			t.Fatal(host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS handshake stalled")
	}
}
func TestProxyStreamsBeforeUpstreamFinishes(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "second\n")
	}))
	defer upstream.Close()
	handler, err := NewProxy(upstream.URL, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(proxy.URL)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	close(release)
	if err != nil || line != "first\n" {
		t.Fatalf("stream %q %v", line, err)
	}
}
func TestProxyFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	handler, err := NewProxy("http://"+address, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "http://local/", nil))
	if w.Code != 502 {
		t.Fatalf("status %d", w.Code)
	}
}

// Package transport implements foreground proxying and explicitly Tor-routed checks.
package transport

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func NewProxy(target string, output io.Writer) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("upstream must be an http(s) URL without credentials or fragment")
	}
	logger := log.New(output, "proxy ", log.LstdFlags)
	p := httputil.NewSingleHostReverseProxy(u)
	p.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, ExpectContinueTimeout: time.Second}
	p.FlushInterval = -1
	p.ErrorLog = logger
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Printf("upstream unavailable: %T", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		p.ServeHTTP(w, r)
		logger.Printf("method=%s duration_ms=%.2f", r.Method, float64(time.Since(start).Microseconds())/1000)
	}), nil
}

// ServeProxy serves until ctx cancellation. Read/write deadlines are deliberately
// not imposed on streaming responses; request headers are bounded separately.
func ServeProxy(ctx context.Context, listen, target string, output io.Writer) error {
	handler, err := NewProxy(target, output)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Fprintf(output, "Proxy listening on %s\n", listener.Addr())
	select {
	case err := <-done:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdown)
		if err != nil {
			server.Close()
		}
		<-done
		return err
	}
}

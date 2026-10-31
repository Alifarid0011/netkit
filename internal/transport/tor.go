package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type TorResult struct {
	IsTor bool   `json:"IsTor"`
	IP    string `json:"IP"`
}

// TorCheck routes just this HTTPS request through SOCKS with remote DNS.
// It never changes system routes, proxy settings, or Tor identity.
func TorCheck(ctx context.Context, socks, endpoint string, timeout time.Duration) (TorResult, error) {
	p, err := url.Parse(socks)
	if err != nil || p.Scheme != "socks5h" || p.User != nil || p.Path != "" || p.RawQuery != "" || p.Fragment != "" {
		return TorResult{}, errors.New("SOCKS proxy must be socks5h://host:port without credentials")
	}
	if _, _, err := net.SplitHostPort(p.Host); err != nil {
		return TorResult{}, errors.New("SOCKS proxy requires host:port")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return TorResult{}, errors.New("Tor check requires an HTTPS endpoint without credentials")
	}
	if timeout <= 0 || timeout > 2*time.Minute {
		return TorResult{}, errors.New("timeout must be >0 and <=2m")
	}
	tr := &http.Transport{Proxy: http.ProxyURL(p), TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	return checkTorWithClient(ctx, client, endpoint)
}
func checkTorWithClient(ctx context.Context, client *http.Client, endpoint string) (TorResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return TorResult{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return TorResult{}, fmt.Errorf("Tor request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TorResult{}, fmt.Errorf("Tor check returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return TorResult{}, err
	}
	if len(b) > 65536 {
		return TorResult{}, errors.New("Tor check response too large")
	}
	var result TorResult
	if err := json.Unmarshal(b, &result); err != nil {
		return TorResult{}, errors.New("invalid Tor check JSON")
	}
	if net.ParseIP(result.IP) == nil {
		return TorResult{}, errors.New("Tor check returned invalid IP")
	}
	return result, nil
}
func TorStart(ctx context.Context, port int, dataDir string, out, diagnostics io.Writer) error {
	if port < 1024 || port > 65535 {
		return errors.New("Tor SOCKS port must be between 1024 and 65535")
	}
	if dataDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		dataDir = filepath.Join(base, "netkit", "tor")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("Tor data directory must be a private directory (0700)")
	}
	path, err := exec.LookPath("tor")
	if err != nil {
		return errors.New("tor is not installed; install your distribution's tor package")
	}
	cmd := exec.CommandContext(ctx, path, "-f", "/dev/null", "--SocksPort", "127.0.0.1:"+strconv.Itoa(port), "--DataDirectory", abs, "--ClientOnly", "1", "--Log", "notice stdout")
	cmd.Stdout = out
	cmd.Stderr = diagnostics
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return cmd.Process.Signal(syscall.SIGINT)
	}
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

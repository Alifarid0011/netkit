// Package routeros provides a bounded RouterOS v7 HTTPS REST client.
// It is experimental: tests use TLS HTTP fixtures, not a RouterOS/CHR lab.
// Rule writes are not transactions and have no automatic rollback or Safe Mode
// guarantee. The ownership check before removal is not atomic with deletion;
// callers must serialize changes with other operators. Rules append to existing
// order and do not override earlier policy. Capability/version detection and
// stale-plan enforcement must be supplied before production mutation use.
package routeros

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// OwnerComment is the exact reserved comment used to identify managed filters.
// It is an ownership convention, not authentication against other router users.
const OwnerComment = "netkit:managed-filter:v1"
const maxResponse = 1 << 20

// Rule describes a narrow IPv4 filter rule. Action is allow or block; Chain is
// input or forward. Source/Destination are optional IPv4 CIDRs. Protocol may be
// empty, tcp, udp or icmp; Port is an optional destination port for TCP/UDP.
// Enable must be explicit: the zero value creates a disabled rule.
type Rule struct {
	Action      string
	Chain       string
	Source      string
	Destination string
	Protocol    string
	Port        int
	Enable      bool
}

// Client keeps credentials private and never follows HTTP redirects.
type Client struct {
	base     string
	user     string
	password string
	http     *http.Client
}

// New accepts an HTTPS origin with optional /rest suffix and optional PEM CA
// bundle. It always verifies certificates and names, using TLS 1.2 or newer.
// Constructing a client does not contact the router or change configuration.
func New(baseURL, user, password, caFile string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/" && u.Path != "/rest" && u.Path != "/rest/") {
		return nil, errors.New("RouterOS URL must be an HTTPS origin with optional /rest path, without credentials, query or fragment")
	}
	if user == "" || password == "" || strings.ContainsAny(user, ":\r\n") {
		return nil, errors.New("RouterOS username and password are required; username cannot contain colon or newline")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("cannot read RouterOS CA file")
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("RouterOS CA file contains no certificates")
		}
	}
	transport := &http.Transport{
		// No environment proxy: credentials go directly to the selected router.
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		MaxResponseHeaderBytes: 64 << 10,
	}
	u.Path = "/rest"
	u.RawPath = ""
	return &Client{base: u.String(), user: user, password: password, http: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// List reads only the exact supported menu names, without arbitrary commands,
// query parameters or item paths. RouterOS strings and array order are retained.
func (c *Client) List(ctx context.Context, resource string) (any, error) {
	switch resource {
	case "system/resource", "system/identity", "interface", "ip/address", "ip/route", "ip/firewall/filter", "ip/firewall/nat":
	default:
		return nil, errors.New("unsupported RouterOS read resource")
	}
	return c.request(ctx, http.MethodGet, resource, nil)
}

// ValidateRule checks a filter plan locally without credentials or network access.
func ValidateRule(rule Rule) error {
	if rule.Action != "allow" && rule.Action != "block" {
		return errors.New("rule action must be allow or block")
	}
	if rule.Chain != "input" && rule.Chain != "forward" {
		return errors.New("rule chain must be input or forward")
	}
	if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
		return errors.New("unsupported rule protocol")
	}
	if rule.Port < 0 || rule.Port > 65535 || (rule.Port != 0 && rule.Protocol != "tcp" && rule.Protocol != "udp") {
		return errors.New("destination port must be 1-65535 with tcp or udp")
	}
	for _, value := range []string{rule.Source, rule.Destination} {
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.Addr().Is4() {
			return errors.New("rule addresses must be IPv4 CIDRs")
		}
	}
	return nil
}

// AddRule appends one managed filter. A failed response after dispatch may still
// mean the rule was created; inspect the router before retrying. No retry occurs.
func (c *Client) AddRule(ctx context.Context, rule Rule) (any, error) {
	if err := ValidateRule(rule); err != nil {
		return nil, err
	}
	body := map[string]string{"chain": rule.Chain, "action": "accept", "comment": OwnerComment, "disabled": strconv.FormatBool(!rule.Enable)}
	if rule.Action == "block" {
		body["action"] = "drop"
	}
	for key, value := range map[string]string{"src-address": rule.Source, "dst-address": rule.Destination} {
		if value == "" {
			continue
		}
		prefix, _ := netip.ParsePrefix(value) // Already checked by ValidateRule.
		body[key] = prefix.Masked().String()
	}
	if rule.Protocol != "" {
		body["protocol"] = rule.Protocol
	}
	if rule.Port != 0 {
		body["dst-port"] = strconv.Itoa(rule.Port)
	}
	return c.request(ctx, http.MethodPut, "ip/firewall/filter", body)
}

var stableID = regexp.MustCompile(`^\*[0-9A-Fa-f]+$`)

// ValidateID checks that a rule reference is a stable RouterOS hexadecimal .id.
// It makes no network request and does not establish ownership.
func ValidateID(id string) error {
	if len(id) > 33 || !stableID.MatchString(id) {
		return errors.New("rule ID must be a stable RouterOS hexadecimal .id such as *A")
	}
	return nil
}

// RemoveRule reads the stable RouterOS .id, verifies the exact ownership marker,
// then deletes that same ID. No positional numbers or unowned rules are accepted.
func (c *Client) RemoveRule(ctx context.Context, id string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	path := "ip/firewall/filter/" + id
	result, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	record, ok := result.(map[string]any)
	if !ok || record[".id"] != id || record["comment"] != OwnerComment {
		return errors.New("refusing to remove rule: ID or ownership marker does not match")
	}
	_, err = c.request(ctx, http.MethodDelete, path, nil)
	return err
}

func (c *Client) request(ctx context.Context, method, path string, body map[string]string) (any, error) {
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, errors.New("cannot encode RouterOS request")
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/"+path, input)
	if err != nil {
		return nil, errors.New("cannot construct RouterOS request")
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		// URL/transport error strings can contain attacker-controlled redirect URLs.
		if ctx.Err() != nil {
			return nil, writeError(method, ctx.Err())
		}
		return nil, writeError(method, errors.New("RouterOS HTTPS request failed (certificate, connection or timeout)"))
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, writeError(method, fmt.Errorf("RouterOS HTTP status %d", response.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return nil, writeError(method, errors.New("cannot read RouterOS response"))
	}
	if len(data) > maxResponse {
		return nil, writeError(method, errors.New("RouterOS response exceeds 1 MiB limit"))
	}
	if method == http.MethodDelete {
		return nil, nil
	}
	var result any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, writeError(method, errors.New("invalid RouterOS JSON response"))
	}
	return result, nil
}

func writeError(method string, err error) error {
	if method == http.MethodPut || method == http.MethodDelete {
		return fmt.Errorf("%w; write may have taken effect; inspect the router before retrying (no automatic rollback)", err)
	}
	return err
}

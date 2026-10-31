package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTemporaryFirewallCleansUpOnLookupFailure(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "nft")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec \"$NETKIT_APP_TEST_BINARY\" -test.run=^TestNftAppHelper$ -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("NETKIT_APP_TEST_BINARY", exe)
	t.Setenv("NETKIT_APP_NFT_HELPER", dir)
	var out, diag bytes.Buffer
	code := Run(context.Background(), []string{"firewall", "apply", "--port=8080", "--confirm", "--json"}, &out, &diag)
	if code == 0 {
		t.Fatal("expected observation failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "removed")); err != nil {
		t.Fatalf("temporary committed rule left behind: %s %s", &out, &diag)
	}
	if !strings.Contains(out.String(), "netkit-v1-") {
		t.Fatal("lost recovery ID")
	}
}
func TestNftAppHelper(t *testing.T) {
	dir := os.Getenv("NETKIT_APP_NFT_HELPER")
	if dir == "" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) > 0 {
		args = args[1:]
	}
	if len(args) > 0 && args[0] == "-f" {
		batch, _ := io.ReadAll(os.Stdin)
		if strings.HasPrefix(string(batch), "delete rule") {
			os.WriteFile(filepath.Join(dir, "removed"), []byte("yes"), 0600)
		} else {
			os.WriteFile(filepath.Join(dir, "batch"), batch, 0600)
		}
		os.Exit(0)
	}
	batch, err := os.ReadFile(filepath.Join(dir, "batch"))
	if os.IsNotExist(err) {
		fmt.Print(`{"nftables":[]}`)
		os.Exit(0)
	}
	if _, err := os.Stat(filepath.Join(dir, "failed")); os.IsNotExist(err) {
		os.WriteFile(filepath.Join(dir, "failed"), []byte("yes"), 0600)
		os.Exit(1)
	}
	id := regexp.MustCompile(`netkit-v1-[0-9a-f]{32}`).FindString(string(batch))
	state := map[string]any{"nftables": []any{map[string]any{"table": map[string]any{"family": "inet", "name": "netkit", "comment": "netkit-managed-v1"}}, map[string]any{"chain": map[string]any{"family": "inet", "table": "netkit", "name": "ingress", "comment": "netkit-ingress-v1", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, map[string]any{"rule": map[string]any{"family": "inet", "table": "netkit", "chain": "ingress", "comment": id, "handle": 7}}}}
	json.NewEncoder(os.Stdout).Encode(state)
	os.Exit(0)
}

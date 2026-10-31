package linux

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagedFirewallNamespace(t *testing.T) {
	if os.Getenv("NETKIT_NFT_NAMESPACE") != "1" {
		t.Skip("requires explicit isolated namespace helper")
	}
	ownNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ownNS == os.Getenv("NETKIT_NFT_PARENT_NS") || os.Getenv("NETKIT_NFT_PARENT_NS") == "" {
		t.Fatal("refusing firewall tests without a verified distinct network namespace")
	}
	// This test is launched exclusively inside unshare -Urn by TestFirewallIsolation.
	ctx := context.Background()
	if err := exec.Command("nft", "add", "table", "inet", "sentinel").Run(); err != nil {
		t.Fatal(err)
	}
	first, err := ManagedApply(ctx, Rule{Action: "allow", Protocol: "tcp", Source: "192.0.2.0/24", Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ManagedApply(ctx, Rule{Action: "block", Protocol: "udp", Source: "2001:db8::/32", Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.Handle == second.Handle {
		t.Fatalf("unstable identity: %+v %+v", first, second)
	}
	if err := ManagedRemove(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	state, err := FirewallList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(state, first.ID) || !strings.Contains(state, second.ID) || !strings.Contains(state, "table inet sentinel") {
		t.Fatalf("wrong removal: %s", state)
	}
	if err := ManagedRemove(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := ManagedRemove(ctx, first.ID); err == nil {
		t.Fatal("removed absent rule")
	}
	// Prove block behavior and explicitly verify an accept in our chain cannot
	// override another base chain's later drop. All sockets exist only in this ns.
	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	connect := func() error {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
		if conn != nil {
			conn.Close()
		}
		return err
	}
	if err := connect(); err != nil {
		t.Fatalf("baseline connection: %v", err)
	}
	blocked, err := ManagedApply(ctx, Rule{Action: "block", Protocol: "tcp", Source: "127.0.0.1/32", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if err := connect(); err == nil {
		t.Fatal("managed drop did not block connection")
	}
	if err := ManagedRemove(ctx, blocked.ID); err != nil {
		t.Fatal(err)
	}
	allowed, err := ManagedApply(ctx, Rule{Action: "allow", Protocol: "tcp", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if err := connect(); err != nil {
		t.Fatalf("removed block still affects new connection: %v", err)
	}
	batch := "add chain inet sentinel input { type filter hook input priority 10; policy accept; }\nadd rule inet sentinel input tcp dport " + strconv.Itoa(port) + " drop\n"
	if _, err := nftRun(ctx, batch, "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := connect(); err == nil {
		t.Fatal("managed accept incorrectly overrides external drop")
	}
	if err := ManagedRemove(ctx, allowed.ID); err != nil {
		t.Fatal(err)
	}

	// An external ownership change must prevent subsequent mutation.
	if err := exec.Command("nft", "delete", "table", "inet", "netkit").Run(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("nft", "add", "table", "inet", "netkit").Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := ManagedApply(ctx, first.Rule); err == nil {
		t.Fatal("accepted foreign netkit table")
	}
}

func TestFirewallIsolation(t *testing.T) {
	if os.Getenv("NETKIT_TEST_NFT") != "1" {
		t.Skip("set NETKIT_TEST_NFT=1 on a runner supporting isolated user/network namespaces")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-Urn", "--", exe, "-test.run=^TestManagedFirewallNamespace$", "-test.v")
	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), "NETKIT_NFT_NAMESPACE=1", "NETKIT_NFT_PARENT_NS="+parentNS)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("namespace integration: %v\n%s", err, output)
	}
}

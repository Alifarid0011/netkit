package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("NETKIT_HELPER_NFT") == "1" && filepath.Base(os.Args[0]) == "nft" {
		if len(os.Args) > 1 && os.Args[1] == "-f" {
			batch, err := io.ReadAll(os.Stdin)
			if err != nil {
				os.Exit(2)
			}
			if err := os.WriteFile(os.Getenv("NETKIT_HELPER_BATCH"), batch, 0600); err != nil {
				os.Exit(2)
			}
			fmt.Fprintln(os.Stderr, "simulated failure after kernel commit")
			os.Exit(1)
		}
		fmt.Print(`{"nftables":[]}`)
		os.Exit(0)
	}

	if os.Getenv("NETKIT_HELPER") == "1" && filepath.Base(os.Args[0]) == "tcpdump" {
		if os.Getenv("NETKIT_HELPER_WAIT") == "1" {
			signals := make(chan os.Signal, 1)
			signal.Notify(signals, os.Interrupt)
			fmt.Print("pcap header\n")
			<-signals
			fmt.Print("flushed\n")
		} else {
			_ = json.NewEncoder(os.Stdout).Encode(os.Args[1:])
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(t *testing.T) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(exe, filepath.Join(dir, "tcpdump")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("NETKIT_HELPER", "1")
}

func TestCaptureRejectsInvalidOptions(t *testing.T) {
	for _, opts := range []CaptureOptions{
		{}, {Interface: "-i any", Count: 1}, {Interface: "lo", Count: -1},
		{Interface: "lo", Duration: -time.Second}, {Interface: "lo", Count: 1, Filter: "tcp\x00udp"},
	} {
		if err := Capture(context.Background(), opts, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Errorf("accepted %+v", opts)
		}
	}
}

func TestCaptureFilterIsOneArgumentAfterSeparator(t *testing.T) {
	helper(t)
	var out bytes.Buffer
	filter := "-w /tmp/injection; $(touch forbidden)"
	if err := Capture(context.Background(), CaptureOptions{Interface: "lo", Count: 2, Filter: filter}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(out.Bytes(), &args); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args[len(args)-2:], []string{"--", filter}) {
		t.Fatalf("unsafe args: %q", args)
	}
}

func TestCaptureDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	err := Capture(context.Background(), CaptureOptions{Interface: "lo", Count: 1, Output: path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("overwrote existing output")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "keep" {
		t.Fatal("output changed")
	}
}

func TestCaptureDurationFlushesFile(t *testing.T) {
	helper(t)
	t.Setenv("NETKIT_HELPER_WAIT", "1")
	path := filepath.Join(t.TempDir(), "capture.pcap")
	var out bytes.Buffer
	if err := Capture(context.Background(), CaptureOptions{Interface: "lo", Duration: 250 * time.Millisecond, Output: path}, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "flushed") {
		t.Fatalf("child did not flush: %q", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
}

func TestCaptureCancellation(t *testing.T) {
	helper(t)
	t.Setenv("NETKIT_HELPER_WAIT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := Capture(ctx, CaptureOptions{Interface: "lo", Count: 10}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestCaptureMissingBackend(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := Capture(context.Background(), CaptureOptions{Interface: "lo", Count: 1}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "tcpdump") {
		t.Fatalf("got %v", err)
	}
}

func TestFirewallValidationAndPlan(t *testing.T) {
	valid := Rule{Action: "allow", Protocol: "tcp", Source: "192.0.2.0/24", Port: 22}
	for _, rule := range []Rule{
		{Action: "accept; flush ruleset", Protocol: "tcp", Port: 22},
		{Action: "allow", Protocol: "icmp", Port: 22},
		{Action: "allow", Protocol: "udp", Source: "all; flush ruleset", Port: 53},
		{Action: "block", Protocol: "tcp", Port: 0},
		{Action: "block", Protocol: "udp", Port: 65536},
	} {
		if _, err := FirewallPlan(rule); err == nil {
			t.Errorf("accepted %+v", rule)
		}
	}
	plan, err := FirewallPlan(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplySupported {
		t.Fatal("verified managed mutation unavailable")
	}
	joined := strings.Join(plan.Commands, "\n")
	if strings.Contains(joined, "flush") || !strings.Contains(joined, "inet netkit") || !strings.Contains(joined, "ip saddr 192.0.2.0/24 tcp dport 22 accept") {
		t.Fatalf("unexpected plan: %s", joined)
	}
}

func TestInspectRealPCAP(t *testing.T) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump backend not installed")
	}
	// Ethernet + IPv4 + UDP; payload absent, no network socket is opened.
	packet, err := hex.DecodeString("00112233445566778899aabb08004500001c0000000040110000c0000201c63364013039003500080000")
	if err != nil {
		t.Fatal(err)
	}
	var fixture bytes.Buffer
	for _, v := range []any{uint32(0xa1b2c3d4), uint16(2), uint16(4), int32(0), uint32(0), uint32(65535), uint32(1), uint32(1), uint32(0), uint32(len(packet)), uint32(len(packet))} {
		if err := binary.Write(&fixture, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	fixture.Write(packet)
	path := filepath.Join(t.TempDir(), "fixture.pcap")
	if err := os.WriteFile(path, fixture.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if err := InspectPCAP(context.Background(), path, &out, &diag); err != nil {
		t.Fatalf("%v: %s", err, diag.String())
	}
	if !strings.Contains(out.String(), "192.0.2.1.12345") || !strings.Contains(out.String(), "198.51.100.1.53") {
		t.Fatalf("unexpected metadata: %s", out.String())
	}
}

func TestInspectRejectsMalformedPCAP(t *testing.T) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump backend not installed")
	}
	path := filepath.Join(t.TempDir(), "truncated.pcap")
	if err := os.WriteFile(path, []byte("not a pcap"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InspectPCAP(context.Background(), path, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted malformed PCAP")
	}
}

func TestManagedApplyPreservesIDOnDispatchFailure(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(exe, filepath.Join(dir, "nft")); err != nil {
		t.Fatal(err)
	}
	batchPath := filepath.Join(dir, "committed-batch")
	t.Setenv("PATH", dir)
	t.Setenv("NETKIT_HELPER_NFT", "1")
	t.Setenv("NETKIT_HELPER_BATCH", batchPath)
	rule := Rule{Action: "allow", Protocol: "tcp", Source: "192.0.2.1/24", Port: 22}
	applied, err := ManagedApply(context.Background(), rule)
	if err == nil {
		t.Fatal("expected dispatch failure")
	}
	if applied.ID == "" || applied.Rule.Source != "192.0.2.0/24" {
		t.Fatalf("lost recovery information: %+v, %v", applied, err)
	}
	batch, readErr := os.ReadFile(batchPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(batch), `comment "`+applied.ID+`"`) {
		t.Fatalf("recovery ID differs from dispatched rule: %s", batch)
	}
	if !strings.Contains(err.Error(), "may have committed") {
		t.Fatalf("uncertain outcome was hidden: %v", err)
	}
}

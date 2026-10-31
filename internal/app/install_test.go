package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInstallerDoesNotFollowDirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	prefix := filepath.Join(dir, "prefix")
	referent := filepath.Join(dir, "other")
	for _, d := range []string{release, filepath.Join(prefix, "bin"), referent} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile("../../packaging/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(release, "install.sh")
	os.WriteFile(script, data, 0700)
	os.WriteFile(filepath.Join(release, "netkit"), []byte("binary-fixture"), 0700)
	target := filepath.Join(prefix, "bin", "netkit")
	os.Symlink(referent, target)
	if out, err := exec.Command("sh", script, "--prefix", prefix, "--force").CombinedOutput(); err != nil {
		t.Fatalf("%s %v", out, err)
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("installer left non-file: %v %v", info, err)
	}
	entries, _ := os.ReadDir(referent)
	if len(entries) != 0 {
		t.Fatal("wrote through target symlink")
	}
}
func TestInstallerPreservesExistingWithoutForce(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "prefix")
	os.MkdirAll(filepath.Join(prefix, "bin"), 0700)
	scriptData, _ := os.ReadFile("../../packaging/install.sh")
	script := filepath.Join(dir, "install.sh")
	os.WriteFile(script, scriptData, 0700)
	os.WriteFile(filepath.Join(dir, "netkit"), []byte("new"), 0700)
	target := filepath.Join(prefix, "bin", "netkit")
	os.WriteFile(target, []byte("old"), 0700)
	if _, err := exec.Command("sh", script, "--prefix", prefix).CombinedOutput(); err == nil {
		t.Fatal("expected refusal")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Fatal("overwrote existing")
	}
}

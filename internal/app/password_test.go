package app

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestPasswordReadsOneLine(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	go func() { io.WriteString(writer, "private-value\n") }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := readPassword(ctx, reader)
	if err != nil || got != "private-value" {
		t.Fatalf("password reading failed: %v", err)
	}
}
func TestPasswordCancellation(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readPassword(ctx, reader); err == nil {
		t.Fatal("ignored cancellation")
	}
}
func TestPasswordLimit(t *testing.T) {
	if _, err := readPassword(context.Background(), strings.NewReader(strings.Repeat("x", 65537))); err == nil {
		t.Fatal("accepted excessive password")
	}
}

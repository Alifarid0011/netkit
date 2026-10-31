// Package linux provides Linux system-tool adapters. Commands never pass through a shell.
package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CaptureOptions selects a local interface and an explicit stop condition.
// Output writes packet payloads to a new mode-0600 PCAP; empty Output prints
// tcpdump's decoded metadata without requesting payload dumps.
type CaptureOptions struct {
	Interface string        `json:"interface"`
	Filter    string        `json:"filter,omitempty"`
	Output    string        `json:"output,omitempty"`
	Duration  time.Duration `json:"duration_ns"`
	Count     int           `json:"count"`
}

var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:@-]{1,64}$`)

// Capture stops gracefully on cancellation so tcpdump can flush the PCAP and
// report capture/drop counters to diagnostics. Count-only captures also have a
// five-minute deadline. Kernel drop counters describe capture loss, not network loss.
func Capture(ctx context.Context, opts CaptureOptions, out, diagnostics io.Writer) error {
	if !interfaceName.MatchString(opts.Interface) || strings.HasPrefix(opts.Interface, "-") {
		return errors.New("capture requires an explicit valid interface")
	}
	if opts.Count < 0 || opts.Count > 10_000_000 {
		return errors.New("capture count must be between 0 and 10000000")
	}
	if opts.Duration < 0 || opts.Duration > 24*time.Hour {
		return errors.New("capture duration must be between 0 and 24 hours")
	}
	if opts.Duration == 0 && opts.Count == 0 {
		return errors.New("capture requires a positive duration or packet count")
	}
	if len(opts.Filter) > 4096 || strings.ContainsAny(opts.Filter, "\x00\r\n") {
		return errors.New("capture filter is invalid or exceeds 4096 bytes")
	}
	if strings.ContainsRune(opts.Output, 0) {
		return errors.New("capture output path contains a NUL")
	}
	if out == nil {
		out = io.Discard
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	path, err := exec.LookPath("tcpdump")
	if err != nil {
		return fmt.Errorf("tcpdump backend unavailable: %w", err)
	}
	args := []string{"-i", opts.Interface, "-n", "-U"}
	var file *os.File
	if opts.Output != "" {
		file, err = os.OpenFile(opts.Output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("create exclusive PCAP: %w", err)
		}
		defer file.Close()
		args = append(args, "-w", "-")
	} else {
		args = append(args, "-l", "-tttt")
	}
	if opts.Count > 0 {
		args = append(args, "-c", strconv.Itoa(opts.Count))
	}
	if opts.Filter != "" {
		args = append(args, "--", opts.Filter)
	}
	duration := opts.Duration
	if duration == 0 {
		duration = 5 * time.Minute
	}
	captureCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	cmd := gracefulCommand(captureCtx, path, args...)
	cmd.Stderr = diagnostics
	if file != nil {
		cmd.Stdout = file
	} else {
		cmd.Stdout = out
	}
	err = cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// A deadline chosen by this operation is normal bounded completion only
	// after the child started; backend startup failures still surface.
	if captureCtx.Err() != nil && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("tcpdump capture (check interface and capture privileges): %w", err)
	}
	if file != nil {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync PCAP: %w", err)
		}
		_, err = fmt.Fprintf(out, "PCAP saved to %s; capture/drop statistics are on stderr.\n", opts.Output)
	}
	return err
}

// InspectPCAP delegates offline decoding to tcpdump. It requires no capture
// privileges and never prints hex/ASCII payload dumps.
func InspectPCAP(ctx context.Context, path string, out, diagnostics io.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open PCAP: %w", err)
	}
	defer file.Close()
	if out == nil {
		out = io.Discard
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := gracefulCommand(bounded, "tcpdump", "-n", "-tttt", "-r", "-")
	cmd.Stdin = file
	cmd.Stdout = out
	cmd.Stderr = diagnostics
	if err := cmd.Run(); err != nil {
		if bounded.Err() != nil {
			return bounded.Err()
		}
		return fmt.Errorf("tcpdump offline decode: %w", err)
	}
	return nil
}

func gracefulCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 2 * time.Second
	return cmd
}

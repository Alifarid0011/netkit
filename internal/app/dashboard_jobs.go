package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Alifarid0011/netkit/internal/diagnostic"
	"io"
	"strings"
	"sync"
)

type dashboardBuffer struct {
	mu        sync.Mutex
	data      []byte
	limit     int
	truncated bool
}

func newDashboardBuffer(limit int) *dashboardBuffer { return &dashboardBuffer{limit: limit} }
func (b *dashboardBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if n >= b.limit {
		b.data = append(b.data[:0], p[n-b.limit:]...)
		b.truncated = true
	} else {
		extra := len(b.data) + n - b.limit
		if extra > 0 {
			b.data = append(b.data[:0], b.data[extra:]...)
			b.truncated = true
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
func (b *dashboardBuffer) snapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	prefix := ""
	if b.truncated {
		prefix = "[Earlier output discarded: live history is bounded]\n"
	}
	return prefix + safeText(strings.ToValidUTF8(string(b.data), "�"))
}

type dashboardJob struct {
	ID       uint64
	Tool     int
	cancel   context.CancelFunc
	finished chan struct{}
	once     sync.Once
	buffer   *dashboardBuffer
	code     int
}
type dashboardExecute func(context.Context, dashboardTool, []string, io.Writer) int

func (j *dashboardJob) start(ctx context.Context, run dashboardExecute, tool dashboardTool, values []string) {
	j.once.Do(func() { go func() { defer close(j.finished); j.code = run(ctx, tool, values, j.buffer) }() })
}
func (j *dashboardJob) stopAndWait(ctx context.Context) {
	j.cancel()
	j.once.Do(func() { close(j.finished) })
	select {
	case <-j.finished:
	case <-ctx.Done():
	}
}
func executeDashboardTool(ctx context.Context, tool dashboardTool, values []string, out io.Writer) int {
	args, err := tool.arguments(values)
	if err != nil {
		return (output{out: out, diagnostics: out}).fail(err, 2)
	}
	if tool.ID == "doctor" {
		var data bytes.Buffer
		code := Run(ctx, append(args, "--json"), &data, out)
		var result struct {
			Data  diagnostic.Report `json:"data"`
			Error string            `json:"error"`
		}
		if err := json.Unmarshal(data.Bytes(), &result); err != nil {
			fmt.Fprintln(out, "Cannot decode diagnosis result")
			return 1
		}
		if result.Error != "" {
			fmt.Fprintln(out, safeText(result.Error))
			return code
		}
		fmt.Fprintln(out, "DIAGNOSIS · "+safeText(result.Data.Target))
		for _, s := range result.Data.Stages {
			state := "PASS"
			if !s.OK {
				state = "FAIL"
			}
			fmt.Fprintf(out, "\n%-5s %-4s %.2f ms\n", strings.ToUpper(s.Name), state, s.DurationMS)
			if s.Address != "" {
				fmt.Fprintln(out, "  "+safeText(s.Address))
			}
			if s.Error != "" {
				fmt.Fprintln(out, "  "+safeText(s.Error))
			} else if s.Detail != "" {
				fmt.Fprintln(out, "  "+safeText(s.Detail))
			}
		}
		return code
	}
	if len(args) > 0 && args[0] == "router" {
		var secret *string
		for i, f := range tool.Fields {
			if f.Secret && values[i] != "" {
				value := values[i]
				secret = &value
			}
		}
		return routerWithPassword(ctx, args[1:], output{out: out, diagnostics: out, explain: false}, secret)
	}
	return Run(ctx, args, out, out)
}

package app

import (
	"context"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"io"
	"strings"
	"testing"
	"time"
)

func key(m *dashboardModel, k string) {
	var msg tea.KeyMsg
	switch k {
	case "down":
		msg.Type = tea.KeyDown
	case "up":
		msg.Type = tea.KeyUp
	case "tab":
		msg.Type = tea.KeyTab
	case "enter":
		msg.Type = tea.KeyEnter
	case "esc":
		msg.Type = tea.KeyEsc
	case "ctrl+c":
		msg.Type = tea.KeyCtrlC
	case "ctrl+q":
		msg.Type = tea.KeyCtrlQ
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}
	m.Update(msg)
}
func selectTool(m *dashboardModel, id string) {
	for i, t := range m.tools {
		if t.ID == id {
			m.selected = i
			m.focus = focusMenu
			m.resetFocus()
			return
		}
	}
	panic("tool missing")
}
func TestDashboardImmediateKeysAndFieldTyping(t *testing.T) {
	m := newDashboardModel(context.Background())
	key(m, "down")
	if m.selected != 1 {
		t.Fatal("arrow required Enter")
	}
	selectTool(m, "doctor")
	key(m, "enter")
	if m.focus != focusForm {
		t.Fatal("not focused")
	}
	key(m, "q")
	if m.quitting || !strings.Contains(m.screens[m.selected].Inputs[0].Value(), "q") {
		t.Fatal("typing q quit instead of editing")
	}
	key(m, "tab")
	if m.focus != focusOutput {
		t.Fatal("Tab did not change pane")
	}
}
func TestDashboardMutationRequiresConfirmation(t *testing.T) {
	m := newDashboardModel(context.Background())
	selectTool(m, "firewall-apply")
	m.focus = focusForm
	m.fieldIndex = len(m.tools[m.selected].Fields)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.confirming || cmd != nil || m.job != nil {
		t.Fatal("mutation ran before confirmation")
	}
	key(m, "esc")
	if m.confirming || m.job != nil {
		t.Fatal("cancelled confirmation executed")
	}
}
func TestDashboardStalePulseIgnored(t *testing.T) {
	m := newDashboardModel(context.Background())
	m.job = &dashboardJob{ID: 2, finished: make(chan struct{}), cancel: func() {}}
	m.screens[0].Output = "current"
	m.Update(dashboardPulse{ID: 1})
	if m.screens[0].Output != "current" {
		t.Fatal("stale output applied")
	}
}
func TestDashboardResizeAndScroll(t *testing.T) {
	m := newDashboardModel(context.Background())
	m.Update(tea.WindowSizeMsg{Width: 82, Height: 24})
	m.screens[0].Output = strings.Repeat("a long line of output\n", 100)
	m.focus = focusOutput
	m.updateViewport()
	m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	if m.screens[0].Scroll == 0 {
		t.Fatal("results do not scroll")
	}
	view := m.View()
	if !strings.Contains(view, "NETKIT") {
		t.Fatal("missing UI")
	}
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 10})
	if !strings.Contains(m.View(), "70") {
		t.Fatal("small terminal not explained")
	}
}
func TestDashboardSecretNotRendered(t *testing.T) {
	m := newDashboardModel(context.Background())
	selectTool(m, "router-add")
	for i, f := range m.tools[m.selected].Fields {
		if f.Secret {
			m.screens[m.selected].Inputs[i].SetValue("must-not-render")
		}
	}
	m.confirming = true
	if strings.Contains(m.View(), "must-not-render") {
		t.Fatal("secret leaked")
	}
}
func TestDashboardCancelAndQuitWaitForCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newDashboardModel(ctx)
	started := make(chan struct{})
	release := make(chan struct{})
	m.execute = func(ctx context.Context, _ dashboardTool, _ []string, _ io.Writer) int {
		close(started)
		<-ctx.Done()
		<-release
		return 0
	}
	selectTool(m, "doctor")
	m.focus = focusForm
	m.fieldIndex = len(m.tools[m.selected].Fields)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("no task")
	}
	cmd()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	key(m, "ctrl+q")
	if !m.quitting || m.job == nil {
		t.Fatal("quit skipped cleanup")
	}
	select {
	case <-m.job.finished:
		t.Fatal("cleanup not waited")
	default:
	}
	close(release)
	select {
	case <-m.job.finished:
	case <-time.After(time.Second):
		t.Fatal("cleanup failed")
	}
	_, quit := m.Update(dashboardPulse{ID: m.job.ID})
	if quit == nil {
		t.Fatal("did not quit after cleanup")
	}
}
func TestDashboardOutputBound(t *testing.T) {
	b := newDashboardBuffer(1024)
	b.Write([]byte(strings.Repeat("x", 5000)))
	if len(b.snapshot()) > 1200 {
		t.Fatal("unbounded live output")
	}
}
func TestDashboardFitsTerminal(t *testing.T) {
	for _, size := range [][2]int{{70, 18}, {82, 24}, {120, 40}} {
		m := newDashboardModel(context.Background())
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		for i, tool := range m.tools {
			m.selected = i
			m.fieldIndex = len(tool.Fields)
			view := m.View()
			if lipgloss.Width(view) > size[0] || lipgloss.Height(view) > size[1] {
				t.Errorf("%s at %v renders %dx%d", tool.ID, size, lipgloss.Width(view), lipgloss.Height(view))
			}
		}
	}
}
func TestDashboardLongFieldsAndConfirmationFit(t *testing.T) {
	m := newDashboardModel(context.Background())
	m.Update(tea.WindowSizeMsg{Width: 70, Height: 18})
	selectTool(m, "router-add")
	for i, f := range m.tools[m.selected].Fields {
		if !f.Secret {
			m.screens[m.selected].Inputs[i].SetValue(strings.Repeat("long-value", 40))
		}
	}
	if lipgloss.Width(m.View()) > 70 || lipgloss.Height(m.View()) > 18 {
		t.Fatal("long values overflow terminal")
	}
	m.confirming = true
	view := m.View()
	if lipgloss.Width(view) > 70 || lipgloss.Height(view) > 18 || !strings.Contains(view, "y = apply") {
		t.Fatalf("confirmation overflow %dx%d", lipgloss.Width(view), lipgloss.Height(view))
	}
}
func TestDashboardResizeWhileEditingMiddle(t *testing.T) {
	m := newDashboardModel(context.Background())
	m.Update(tea.WindowSizeMsg{Width: 130, Height: 30})
	selectTool(m, "doctor")
	m.focus = focusForm
	input := &m.screens[m.selected].Inputs[0]
	input.SetValue(strings.Repeat("x", 200))
	input.CursorEnd()
	input.SetCursor(input.Position() - 10)
	position := input.Position()
	m.Update(tea.WindowSizeMsg{Width: 70, Height: 18})
	if lipgloss.Width(m.View()) > 70 || lipgloss.Height(m.View()) > 18 {
		t.Fatal("resized input kept wide viewport")
	}
	if input.Position() != position {
		t.Fatal("resize moved editing cursor")
	}
}

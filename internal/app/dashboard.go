package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"
)

type dashboardFocus int

const (
	focusMenu dashboardFocus = iota
	focusForm
	focusOutput
)

type dashboardScreen struct {
	Inputs         []textinput.Model
	Output, Status string
	Code           int
	Scroll         int
	Follow         bool
}
type dashboardPulse struct{ ID uint64 }
type dashboardModel struct {
	helpScroll                          int
	stopping                            bool
	quitError                           string
	confirmScroll                       int
	ctx                                 context.Context
	tools                               []dashboardTool
	screens                             []dashboardScreen
	selected, fieldIndex, width, height int
	focus                               dashboardFocus
	confirming, help, quitting          bool
	notice                              string
	frame                               int
	sequence                            uint64
	job                                 *dashboardJob
	execute                             dashboardExecute
}

func newDashboardModel(ctx context.Context) *dashboardModel {
	m := &dashboardModel{ctx: ctx, tools: dashboardTools(), width: 100, height: 30, execute: executeDashboardTool}
	for _, tool := range m.tools {
		screen := dashboardScreen{Follow: false, Status: "Ready"}
		for _, f := range tool.Fields {
			input := textinput.New()
			input.Width = max(10, m.panelWidth()-22)
			input.SetValue(f.Default)
			input.Placeholder = f.Hint
			input.CharLimit = 4096
			input.Prompt = ""
			if f.Secret {
				input.EchoMode = textinput.EchoPassword
				input.EchoCharacter = '•'
				input.CharLimit = 512
			}
			screen.Inputs = append(screen.Inputs, input)
		}
		m.screens = append(m.screens, screen)
	}
	return m
}
func (m *dashboardModel) Init() tea.Cmd { return nil }
func (m *dashboardModel) values() []string {
	values := make([]string, len(m.screens[m.selected].Inputs))
	for i, input := range m.screens[m.selected].Inputs {
		values[i] = input.Value()
	}
	return values
}
func (m *dashboardModel) resetFocus() {
	for s := range m.screens {
		for i := range m.screens[s].Inputs {
			m.screens[s].Inputs[i].Blur()
		}
	}
	if m.focus == focusForm && m.fieldIndex < len(m.screens[m.selected].Inputs) {
		m.screens[m.selected].Inputs[m.fieldIndex].Focus()
	}
}
func pulse(id uint64) tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return dashboardPulse{ID: id} })
}
func (m *dashboardModel) start() tea.Cmd {
	if m.job != nil {
		m.notice = "An operation is already running. Esc stops it first."
		return nil
	}
	tool := m.tools[m.selected]
	values := m.values()
	if _, err := tool.arguments(values); err != nil {
		m.notice = err.Error()
		return nil
	}
	if tool.Mutation && !m.confirming {
		m.confirming = true
		m.confirmScroll = 0
		m.resetFocus()
		return nil
	}
	m.confirming = false
	m.stopping = false
	m.notice = ""
	m.sequence++
	ctx, cancel := context.WithCancel(m.ctx)
	job := &dashboardJob{ID: m.sequence, Tool: m.selected, cancel: cancel, finished: make(chan struct{}), buffer: newDashboardBuffer(64 * 1024)}
	m.job = job
	screen := &m.screens[m.selected]
	screen.Output = ""
	screen.Status = "Running"
	screen.Scroll = 0
	screen.Follow = true
	run := m.execute
	return func() tea.Msg { job.start(ctx, run, tool, values); return dashboardPulse{ID: job.ID} }
}
func (m *dashboardModel) requestQuit() tea.Cmd {
	if m.job != nil {
		m.quitting = true
		m.stopping = true
		m.job.cancel()
		m.notice = "Stopping operation and waiting for cleanup…"
		return nil
	}
	return tea.Quit
}
func (m *dashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		for si := range m.screens {
			for i := range m.screens[si].Inputs {
				input := &m.screens[si].Inputs[i]
				position := input.Position()
				input.Width = max(10, m.panelWidth()-22)
				input.CursorStart()
				input.CursorEnd()
				input.SetCursor(position)
			}
		}
		m.updateViewport()
		return m, nil
	case dashboardPulse:
		if m.job == nil || msg.ID != m.job.ID {
			return m, nil
		}
		m.frame++
		screen := &m.screens[m.job.Tool]
		screen.Output = m.job.buffer.snapshot()
		select {
		case <-m.job.finished:
			screen.Output = m.job.buffer.snapshot()
			screen.Code = m.job.code
			screen.Status = "Completed"
			if screen.Code != 0 {
				screen.Status = fmt.Sprintf("Finished with exit %d", screen.Code)
			}
			m.job.cancel()
			m.notice = ""
			if m.stopping {
				screen.Status = fmt.Sprintf("Stopped · exit %d", screen.Code)
				m.notice = "Operation stopped; output was kept."
				m.stopping = false
			}
			if m.quitting && screen.Code != 0 {
				m.quitError = fmt.Sprintf("operation ended with exit %d:\n%s", screen.Code, screen.Output)
			}
			m.job = nil
			m.updateViewport()
			if m.quitting {
				return m, tea.Quit
			}
			return m, nil
		default:
			m.updateViewport()
			return m, pulse(msg.ID)
		}
	case tea.KeyMsg:
		key := msg.String()
		if key == "ctrl+q" {
			return m, m.requestQuit()
		}
		if key == "ctrl+c" {
			if m.job != nil {
				m.job.cancel()
				m.stopping = true
				m.notice = "Stopping operation…"
				return m, nil
			}
			return m, m.requestQuit()
		}
		if m.quitting {
			return m, nil
		}
		if m.help {
			switch key {
			case "esc", "?", "f1":
				m.help = false
			case "up", "pgup":
				m.helpScroll = max(0, m.helpScroll-3)
			case "down", "pgdown":
				m.helpScroll = min(max(0, len(m.helpLines())-max(3, m.height-6)), m.helpScroll+3)
			}
			return m, nil
		}
		if m.confirming {
			switch key {
			case "y", "Y":
				return m, m.start()
			case "up", "pgup":
				m.confirmScroll = max(0, m.confirmScroll-3)
			case "down", "pgdown":
				m.confirmScroll = min(max(0, len(m.confirmationLines())-m.confirmHeight()), m.confirmScroll+3)
			case "esc", "n", "N":
				m.confirming = false
				m.notice = "Change cancelled"
				m.resetFocus()
			}
			return m, nil
		}
		if key == "esc" {
			if m.job != nil {
				m.job.cancel()
				m.stopping = true
				m.notice = "Stopping operation…"
			} else {
				m.focus = focusMenu
				m.resetFocus()
			}
			return m, nil
		}
		if key == "f1" || (key == "?" && m.focus != focusForm) {
			m.help = true
			m.helpScroll = 0
			return m, nil
		}
		if key == "tab" || key == "shift+tab" {
			step := 1
			if key == "shift+tab" {
				step = 2
			}
			m.focus = dashboardFocus((int(m.focus) + step) % 3)
			m.resetFocus()
			return m, nil
		}
		if key == "ctrl+r" {
			return m, m.start()
		}
		if key == "pgup" || key == "pgdown" {
			step := m.outputHeight()
			if key == "pgup" {
				step = -step
			}
			m.screens[m.selected].Scroll += step
			m.screens[m.selected].Follow = false
			m.updateViewport()
			return m, nil
		}
		switch m.focus {
		case focusMenu:
			switch key {
			case "q":
				return m, m.requestQuit()
			case "up", "k":
				m.selected = (m.selected + len(m.tools) - 1) % len(m.tools)
				m.fieldIndex = 0
				m.notice = ""
			case "down", "j":
				m.selected = (m.selected + 1) % len(m.tools)
				m.fieldIndex = 0
				m.notice = ""
			case "enter", "right":
				if len(m.tools[m.selected].Fields) == 0 {
					return m, m.start()
				}
				m.focus = focusForm
				m.fieldIndex = 0
				m.resetFocus()
			}
			return m, nil
		case focusForm:
			// An active job uses an immutable snapshot; freeze its form until it stops.
			if m.job != nil && m.job.Tool == m.selected {
				m.notice = "This form is running. Esc stops it; Tab opens results."
				return m, nil
			}
			count := len(m.tools[m.selected].Fields)
			switch key {
			case "up":
				m.fieldIndex = (m.fieldIndex + count) % (count + 1)
				m.resetFocus()
				return m, nil
			case "down":
				m.fieldIndex = (m.fieldIndex + 1) % (count + 1)
				m.resetFocus()
				return m, nil
			case "enter":
				if m.fieldIndex == count {
					return m, m.start()
				}
				m.fieldIndex++
				m.resetFocus()
				return m, nil
			}
			if m.fieldIndex < count {
				input, cmd := m.screens[m.selected].Inputs[m.fieldIndex].Update(msg)
				m.screens[m.selected].Inputs[m.fieldIndex] = input
				return m, cmd
			}
			return m, nil
		case focusOutput:
			screen := &m.screens[m.selected]
			switch key {
			case "up", "k":
				screen.Scroll--
				screen.Follow = false
			case "down", "j":
				screen.Scroll++
				screen.Follow = false
			case "home", "g":
				screen.Scroll = 0
				screen.Follow = false
			case "end", "G":
				screen.Follow = true
			case "enter":
				return m, m.start()
			case "q":
				return m, m.requestQuit()
			}
			m.updateViewport()
			return m, nil
		}
	}
	// Cursor blink messages belong only to the focused input.
	if m.focus == focusForm && m.fieldIndex < len(m.screens[m.selected].Inputs) {
		input, cmd := m.screens[m.selected].Inputs[m.fieldIndex].Update(msg)
		m.screens[m.selected].Inputs[m.fieldIndex] = input
		return m, cmd
	}
	return m, nil
}

var uiAccent = lipgloss.AdaptiveColor{Light: "#08665B", Dark: "#5DD4BD"}
var uiMuted = lipgloss.AdaptiveColor{Light: "#596273", Dark: "#94A3B8"}
var uiText = lipgloss.AdaptiveColor{Light: "#182332", Dark: "#E5EDF5"}
var uiSelected = lipgloss.AdaptiveColor{Light: "#DBF2EC", Dark: "#17443E"}

func uiClip(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(safeText(s), width, "…")
}
func (m *dashboardModel) panelWidth() int { return max(38, m.width-29) }
func (m *dashboardModel) visibleFields() int {
	return min(len(m.tools[m.selected].Fields), max(1, (m.height-14)/2))
}
func (m *dashboardModel) outputHeight() int { return max(3, m.height-m.visibleFields()-14) }
func (m *dashboardModel) outputLines() []string {
	value := m.screens[m.selected].Output
	if value == "" {
		if m.job != nil && m.job.Tool == m.selected {
			value = "Starting operation…\nOutput will appear here. Esc stops it."
		} else if m.screens[m.selected].Status != "Ready" {
			value = "Operation finished without output."
		} else {
			value = m.tools[m.selected].Explain + "\n\nNo operation has run. Fill the form and choose Run."
		}
	}
	return strings.Split(ansi.Wrap(safeText(value), max(20, m.panelWidth()-4), ""), "\n")
}
func (m *dashboardModel) updateViewport() {
	screen := &m.screens[m.selected]
	maxScroll := max(0, len(m.outputLines())-m.outputHeight())
	if screen.Follow {
		screen.Scroll = maxScroll
	} else {
		screen.Scroll = max(0, min(screen.Scroll, maxScroll))
	}
}
func (m *dashboardModel) View() string {
	if m.width < 70 || m.height < 18 {
		return "NETKIT — terminal is too small\nResize to at least 70 columns × 18 rows.\nCtrl+Q quits; Esc stops a running task.\n"
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(uiAccent).Render("NETKIT") + lipgloss.NewStyle().Foreground(uiMuted).Render("  network workbench · "+Version)
	status := "READY"
	if m.job != nil {
		status = string("|/-\\"[m.frame%4]) + " RUNNING · " + m.tools[m.job.Tool].Title
	}
	if m.quitting {
		status = "STOPPING · waiting for cleanup"
	}
	header := title + "\n" + lipgloss.NewStyle().Foreground(uiMuted).Render(uiClip(status, m.width))
	if m.help {
		lines := m.helpLines()
		height := max(3, m.height-6)
		start := min(m.helpScroll, max(0, len(lines)-height))
		return header + "\n\n" + strings.Join(lines[start:min(len(lines), start+height)], "\n") + "\n↑↓ scroll · Esc / F1 closes help"
	}
	if m.confirming {
		return header + "\n\n" + m.confirmView()
	}
	tool := m.tools[m.selected]
	screen := &m.screens[m.selected]
	panelWidth := m.panelWidth()
	inner := panelWidth - 4
	// Keep the selected menu item in view rather than truncating the menu.
	menuHeight := max(5, m.height-9)
	menuStart := max(0, m.selected-menuHeight+1)
	if menuStart+menuHeight > len(m.tools) {
		menuStart = max(0, len(m.tools)-menuHeight)
	}
	var menu []string
	menu = append(menu, lipgloss.NewStyle().Bold(true).Render("TOOLS"))
	for i := menuStart; i < min(len(m.tools), menuStart+menuHeight); i++ {
		label := "  " + m.tools[i].Title
		if i == m.selected {
			label = "> " + m.tools[i].Title
			label = lipgloss.NewStyle().Background(uiSelected).Foreground(uiAccent).Bold(true).Render(uiClip(label, 22))
		} else {
			label = uiClip(label, 22)
		}
		menu = append(menu, label)
	}
	menu = append(menu, lipgloss.NewStyle().Foreground(uiMuted).Render("↑↓ select · Enter open"))
	left := m.border(focusMenu).Width(24).Render(strings.Join(menu, "\n"))
	var form []string
	form = append(form, lipgloss.NewStyle().Bold(true).Foreground(uiText).Render(uiClip(tool.Title, inner)))
	form = append(form, lipgloss.NewStyle().Foreground(uiMuted).Render(uiClip(tool.Summary, inner)))
	visible := m.visibleFields()
	start := max(0, m.fieldIndex-visible+1)
	if start+visible > len(tool.Fields) {
		start = max(0, len(tool.Fields)-visible)
	}
	for i := start; i < min(len(tool.Fields), start+visible); i++ {
		input := screen.Inputs[i]
		input.Width = max(10, inner-18)
		label := fmt.Sprintf("%-16s", uiClip(tool.Fields[i].Label, 15))
		if m.focus == focusForm && i == m.fieldIndex {
			label = lipgloss.NewStyle().Foreground(uiAccent).Bold(true).Render(label)
		}
		form = append(form, label+input.View())
	}
	if len(tool.Fields) > visible {
		form = append(form, lipgloss.NewStyle().Foreground(uiMuted).Render(fmt.Sprintf("Fields %d–%d of %d · ↑↓ moves", start+1, start+visible, len(tool.Fields))))
	}
	button := "[ Enter: Run ]"
	if tool.Mutation {
		button = "[ Enter: Review change ]"
	}
	if m.job != nil && m.job.Tool == m.selected {
		button = "[ Running · Esc to stop ]"
	}
	buttonStyle := lipgloss.NewStyle().Foreground(uiAccent).Bold(true)
	if m.focus == focusForm && m.fieldIndex == len(tool.Fields) {
		buttonStyle = buttonStyle.Background(uiSelected)
	}
	form = append(form, buttonStyle.Render(button))
	hint := "Ctrl+R runs · Tab switches pane"
	if m.focus == focusForm && m.fieldIndex < len(tool.Fields) {
		hint = tool.Fields[m.fieldIndex].Hint
	}
	form = append(form, lipgloss.NewStyle().Foreground(uiMuted).Render(uiClip(hint, inner)))
	formView := m.border(focusForm).Width(panelWidth).Render(strings.Join(form, "\n"))
	lines := m.outputLines()
	scroll := min(screen.Scroll, max(0, len(lines)-m.outputHeight()))
	visibleLines := lines[scroll:min(len(lines), scroll+m.outputHeight())]
	outputTitle := fmt.Sprintf("RESULTS · %s · %d/%d", screen.Status, scroll+1, len(lines))
	outputBody := lipgloss.NewStyle().Foreground(uiMuted).Render(uiClip(outputTitle, inner)) + "\n" + strings.Join(visibleLines, "\n")
	results := m.border(focusOutput).Width(panelWidth).Render(outputBody)
	right := formView + "\n" + results
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	footer := "Tab pane · ↑↓ navigate · Enter run · Esc stop/back · Ctrl+Q quit · F1 help"
	if m.notice != "" {
		footer = m.notice
	}
	return header + "\n" + body + "\n" + lipgloss.NewStyle().Foreground(uiMuted).Render(uiClip(footer, m.width))
}
func (m *dashboardModel) border(f dashboardFocus) lipgloss.Style {
	color := uiMuted
	if m.focus == f {
		color = uiAccent
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(color).Padding(0, 1)
}
func (m *dashboardModel) helpLines() []string {
	return strings.Split(ansi.Wrap(m.tools[m.selected].Title+"\n"+m.tools[m.selected].Explain+"\n\n"+m.helpView(), max(20, m.width-2), ""), "\n")
}
func (m *dashboardModel) helpView() string {
	return "KEYBOARD\n\n↑/↓ or j/k     Select a tool in the menu\nEnter           Open a form; advance fields; run the selected button\nTab / Shift+Tab Move between menu, form and results\n↑/↓ in form    Select a field or Run button\n←/→ Home End    Edit the focused text field\nCtrl+U          Delete text before the cursor\nCtrl+R          Run current form\nPgUp / PgDn     Scroll results from any pane\ng / G           Top / follow output when results are focused\nEsc             Stop active operation, otherwise return to menu\nCtrl+C          Stop active operation; quit when idle\nCtrl+Q          Quit after active operation cleanup\nF1 / ?          Help (type ? normally inside a form)\n\nChanges require y/N confirmation. No automatic sudo.\nOne active operation at a time; forms/results stay in this session."
}
func (m *dashboardModel) confirmHeight() int { return max(3, m.height-9) }
func (m *dashboardModel) confirmationLines() []string {
	tool := m.tools[m.selected]
	width := max(20, m.width-8)
	var lines []string
	lines = append(lines, tool.Title, "", ansi.Wrap(tool.Explain, width, ""), "")
	for i, f := range tool.Fields {
		if !f.Secret && m.screens[m.selected].Inputs[i].Value() != "" {
			lines = append(lines, ansi.Wrap(safeText(f.Label+": "+m.screens[m.selected].Inputs[i].Value()), width, ""))
		}
	}
	return strings.Split(strings.Join(lines, "\n"), "\n")
}
func (m *dashboardModel) confirmView() string {
	lines := m.confirmationLines()
	start := min(m.confirmScroll, max(0, len(lines)-m.confirmHeight()))
	end := min(len(lines), start+m.confirmHeight())
	body := "REVIEW NETWORK CHANGE\n" + strings.Join(lines[start:end], "\n") + fmt.Sprintf("\n↑↓ / PgUp PgDn review · %d/%d\n", end, len(lines)) + "Apply? y = apply   n / Esc = cancel"
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(uiAccent).Padding(0, 2).Width(m.width - 2).Render(body)
}

func dashboardTerminal(out io.Writer) bool {
	terminal, ok := out.(*os.File)
	return ok && term.IsTerminal(terminal.Fd()) && term.IsTerminal(os.Stdin.Fd()) && os.Getenv("TERM") != "dumb"
}
func dashboard(ctx context.Context, out, diagnostics io.Writer) (err error) {
	if !dashboardTerminal(out) {
		return errors.New("dashboard needs an interactive terminal; use netkit help for scriptable commands")
	}
	m := newDashboardModel(ctx)
	defer func() {
		if m.job != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			m.job.stopAndWait(cleanup)
			select {
			case <-m.job.finished:
				if m.job.code != 0 {
					err = fmt.Errorf("operation ended with exit %d:\n%s", m.job.code, m.job.buffer.snapshot())
				}
			default:
				err = errors.New("operation cleanup did not finish within 12 seconds")
			}
		}
	}()
	_, err = tea.NewProgram(m, tea.WithInput(os.Stdin), tea.WithOutput(out), tea.WithAltScreen(), tea.WithContext(ctx)).Run()
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil
	}
	if err == nil && m.quitError != "" {
		return errors.New(m.quitError)
	}
	return err
}

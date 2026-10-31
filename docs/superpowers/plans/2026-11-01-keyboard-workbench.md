# Keyboard Workbench Implementation Plan

> For agentic workers: execute inline; request one independent code review before publishing.

**Goal:** Make Netkit's terminal interface usable for actual network operations with immediate keyboard input.
**Architecture:** Bubble Tea model owns UI state; immutable job inputs call existing command/services asynchronously. Bounded synchronized output and job IDs keep rendering responsive and prevent stale updates.
**Tech Stack:** Go, Bubble Tea v1.3.10, Bubbles textinput, Lip Gloss. Linux backends unchanged.
**Spec:** docs/superpowers/specs/2026-11-01-keyboard-workbench.md

## Global Constraints
No shell execution from user input. No implicit network mutations/elevation. Mask and never preview credentials. Preserve per-tool output while navigating. Cancellation must retain firewall cleanup. Existing CLI and JSON unchanged.

## Review Focus
Typing q in a field must not quit; stale job messages must not overwrite a newer run; quit must wait for cleanup; long output and tiny/resized terminals must stay bounded; password values must not enter rendered previews or logs.

## Tasks
1. Tests first: tool definitions produce valid CLI arguments, router credentials remain out of arguments, mutation classification and validation. Implement internal/app/dashboard_tools.go.
2. Tests first: arrows/Tab/immediate selection, form editing/Enter/run, confirmation/Esc, scroll bounds, stale results, cancellation/quit. Replace dashboard.go and add dashboard_test.go; async execution lives in dashboard_jobs.go.
3. Verify real PTY single-key navigation, running local doctor/probe, stop and quit, resize and restored terminal mode. Run full race/vet and isolated firewall tests. Fix concrete failures and request a fresh review.
4. Update README, changelog, roadmap, third-party license notices and packaging. Publish v0.2.0 with CI and installed binary verified.

## Progress
Implementation authorized by user's request to make the existing terminal product keyboard-operated. Work is isolated in netkit-keyboard. No other service implementation changes planned.

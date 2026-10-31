# Keyboard-operated network workbench

User request: the current dashboard is impractical and must let users do real tasks comfortably with the keyboard. This refines the already approved terminal workbench rather than adding new network capabilities.

Replace the line-buffered dashboard with Bubble Tea's immediate keyboard handling. Left menu selects tools using arrows or j/k, Tab/Shift+Tab moves focus between menu, form and results; Enter opens/advances a form or runs its selected action. Text inputs have cursor editing and masked secrets. Esc cancels a running task, otherwise returns to the menu; Ctrl+C cancels a task first, quits when idle; Ctrl+Q quits after cleanup. PgUp/PgDn scroll results and ?/F1 opens help. Resize is handled; narrow terminals receive a usable compact layout or a clear minimum-size message.

Expose existing IP/routes, listeners, doctor, TCP/ICMP probes, capture/PCAP decode, proxy, firewall list/plan/temporary apply/remove, RouterOS read/disabled add/owned remove and Tor start/check. Forms build typed arguments or call existing typed services, never shell commands. Mutations require a visible confirmation dialog. No automatic sudo or privileged changes while navigating. Existing command-line behavior remains available.

One operation runs at a time, asynchronously, with bounded live output and cancellation. Navigation and scrolling stay responsive. Keep separate in-memory forms/results per tool and ignore stale completion/poll messages. Stop/quit waits for existing cleanup so temporary firewall changes and foreground proxy shutdown retain their semantics. No command history or password persistence; no secret value in command previews.

Use maintained Bubble Tea, Bubbles text input and Lip Gloss rather than maintaining raw-terminal escape parsing. This intentionally replaces the previous zero-Go-dependency approach for the terminal UI; document licenses and ship notices. Human view remains English like the existing CLI. Publish v0.2.0 after state-machine tests, race/vet, actual PTY keyboard/resize checks, isolated firewall integration, installed app smoke tests and CI.

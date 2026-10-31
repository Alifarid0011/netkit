# Contributing

Small, reproducible improvements are welcome. Include the Linux distribution, backend versions, exact command and a redacted result when reporting a bug. Never attach passwords, unredacted router exports or real traffic captures to public issues.

Before a pull request, run `go test -race ./...`, `go vet ./...`, and gofmt. Add regression tests for behavioural changes. Use local fixtures; privileged tests must be explicitly opted into and confined to an isolated network namespace or dedicated RouterOS/CHR lab. Never flush a developer's live firewall for a test.

Keep command adapters thin, JSON schemas stable, network operations cancellable, concurrency bounded and backend arguments separate from shell text. Prefer the standard library. Explain operational limits in user-facing documentation. Experimental features must stay labeled until device/integration evidence exists.

Report potentially exploitable defects privately to alifarid0011@gmail.com before publishing details. Do not include credentials in the first message.

# secagent

AI-powered security analysis agent that combines [OSV-SCALIBR](https://github.com/google/osv-scalibr) (software composition analysis, secret detection) with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) to scan, explain, triage, and remediate security findings.

SCALIBR produces structured security data — packages, vulnerabilities, secrets. Claude reasons about it, explains it, and takes action.

## Requirements

- Go 1.24.6+
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) installed and authenticated
- Local clones of [osv-scalibr](https://github.com/google/osv-scalibr) and [claude-agent-sdk-go](https://github.com/severity1/claude-agent-sdk-go) as sibling directories (see [Setup](#setup))

## Setup

```bash
# Clone dependencies as siblings
cd ~/projects
git clone https://github.com/google/osv-scalibr
git clone https://github.com/severity1/claude-agent-sdk-go
git clone https://github.com/haasonsaas/secagent

# Build
cd secagent
go build -o secagent .
```

The `go.mod` uses `replace` directives pointing to `../osv-scalibr` and `../claude-agent-sdk-go`. Adjust if your directory layout differs.

## Commands

### `secagent explain`

Scans a target for packages and known vulnerabilities (CVEs), then asks Claude to produce a structured security analysis: severity breakdown, exploitability assessment, and a prioritized remediation plan.

```bash
secagent explain -target ./my-project
```

**How it works:** Runs SCALIBR with SCA extractors (`os`, `python`, `javascript`, `java`, `go`, `ruby`, `rust`) plus the `vulnmatch` enricher (OSV database). Formats findings as markdown and sends them to Claude in a one-shot query.

**Example output includes:**
- Executive summary for non-technical stakeholders
- Critical/High/Medium/Low severity breakdown with CVSS scores
- Per-vulnerability exploit analysis and fix versions
- Phased remediation roadmap

### `secagent remediate`

Scans for vulnerabilities, then gives Claude filesystem write access to actually fix them — upgrading dependency versions in manifest files and running tests.

```bash
secagent remediate -target ./my-project
```

**How it works:** Same scan as `explain`, but Claude gets `Read`, `Write`, `Edit`, `Bash`, `Glob`, and `Grep` tools scoped to the target directory. Runs with `acceptEdits` permission mode and up to 20 agent turns. Claude reads your `package.json` / `go.mod` / `requirements.txt` / `pom.xml`, applies version bumps, and runs your test suite.

### `secagent triage-secrets`

Scans for hardcoded secrets (API keys, tokens, credentials), then has Claude read the surrounding source code to classify each as a true positive, false positive, or needs investigation.

```bash
secagent triage-secrets -target ./my-project
```

**How it works:** Runs SCALIBR's Veles secret detection engine (detectors for Anthropic, AWS, GCP, GitHub, Slack, Stripe, and 30+ other providers). For each finding, Claude gets read-only filesystem tools (`Read`, `Glob`, `Grep`) to examine context — test directories, variable names, comments, `.gitignore` presence — and produces a structured triage report.

**Example classification signals Claude uses:**
- File path contains `test`, `fixture`, `mock`, `example`
- Variable named `FAKE_KEY`, `TEST_TOKEN`, etc.
- Comment says "placeholder" or "revoked"
- Key format matches real provider pattern vs. obvious dummy

### `secagent audit-image`

Scans a container image and produces a layer-by-layer security audit with base image recommendations.

```bash
secagent audit-image -image alpine:latest
secagent audit-image -image gcr.io/my-project/api:v1.2
secagent audit-image -image ./image.tar
```

**How it works:** Loads the image via SCALIBR's `lsimage` package (supports remote registries, local Docker daemon, and tarballs). Runs SCA extractors per layer, groups packages by their origin layer and Dockerfile command, then sends the layer-attributed inventory to Claude for analysis.

**Claude's audit covers:**
- Which layers contribute the most packages and vulnerabilities
- Base image identification and secure alternatives (distroless, alpine, scratch)
- Unnecessary packages increasing attack surface
- Dockerfile optimization suggestions (multi-stage builds, removing package managers)
- Deployment-blocking critical findings

### `secagent interactive`

Starts an interactive REPL where you can ask Claude security questions. Claude has access to SCALIBR scanning tools (via MCP) plus filesystem tools, so it can scan on demand and investigate findings.

```bash
secagent interactive -target ./my-project
```

**Available MCP tools in the session:**
- `scan_path` — Run an SCA scan on any path
- `scan_secrets` — Run a secrets scan on any path
- `scan_image` — Scan a container image

**Example session:**
```
secagent> scan my project for vulnerabilities and explain the worst ones
secagent> are any of the high-severity ones actually exploitable given how we use them?
secagent> check if there are any hardcoded secrets in the config directory
secagent> exit
```

### `secagent serve`

Starts a long-running session that exposes SCALIBR scanning capabilities as MCP tools for external Claude Code sessions to call.

```bash
secagent serve
```

## Architecture

```
secagent/
├── main.go                         # CLI dispatch (os.Args + flag, no cobra)
├── internal/
│   ├── scanner/
│   │   ├── scanner.go              # SCALIBR wrapper: Scan()
│   │   ├── image.go                # Container image scanning: ScanImage()
│   │   └── result.go               # Result type with convenience accessors
│   ├── formatter/
│   │   └── formatter.go            # Convert SCALIBR results → markdown for Claude
│   ├── agent/
│   │   ├── agent.go                # Claude SDK helpers: QueryOneShot, StreamToStdout
│   │   └── prompts.go              # System prompts for each use case
│   └── mcptools/
│       └── tools.go                # MCP tool definitions for interactive/serve
├── cmd/
│   ├── explain.go                  # secagent explain
│   ├── remediate.go                # secagent remediate
│   ├── triage.go                   # secagent triage-secrets
│   ├── audit.go                    # secagent audit-image
│   ├── interactive.go              # secagent interactive
│   └── serve.go                    # secagent serve
```

**Data flow:**

1. **Scan** — `scanner.Scan()` or `scanner.ScanImage()` calls SCALIBR with mode-appropriate plugins
2. **Format** — `formatter.FormatForClaude()` converts the structured `ScanResult` into markdown tables (truncated at 50K chars)
3. **Analyze** — `agent.QueryOneShot()` or `claudecode.WithClient()` sends the report to Claude with a role-specific system prompt
4. **Act** — For `remediate` and `triage-secrets`, Claude uses filesystem tools to read code, apply fixes, or investigate context

## SCALIBR Plugin Sets

| Mode | Plugins | What they find |
|------|---------|----------------|
| `ModeSCA` | `os`, `python`, `javascript`, `java`, `go`, `ruby`, `rust` | OS packages (dpkg, apk, rpm), language packages from manifests and lockfiles |
| `ModeSecrets` | `secrets` | API keys, tokens, credentials via Veles detectors (30+ providers) |
| `ModeFull` | All of the above | Combined SCA + secrets |

When `WithOSVMatch` is enabled, the `vulnmatch` enricher is added, which matches discovered packages against the [OSV vulnerability database](https://osv.dev/).

## Claude SDK Integration

| Command | SDK API | Tools | Turns |
|---------|---------|-------|-------|
| `explain` | `Query()` (one-shot) | None | 1 |
| `audit-image` | `Query()` (one-shot) | None | 1 |
| `triage-secrets` | `WithClient()` (streaming) | `Read`, `Glob`, `Grep` | 10 |
| `remediate` | `WithClient()` (streaming) | `Read`, `Write`, `Edit`, `Bash`, `Glob`, `Grep` | 20 |
| `interactive` | `WithClient()` (streaming) | Filesystem + MCP (`scan_path`, `scan_secrets`, `scan_image`) | 20 |
| `serve` | `WithClient()` (blocking) | MCP tools only | — |

## License

MIT

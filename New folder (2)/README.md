# Enterprise DevSecOps Pre-Commit Guardian

Production-grade security gatekeeper that prevents insecure code from entering Git repositories.

## Features

- **Git Pre-Commit Hook** + **Standalone CLI**
- **Incremental scanning** — only staged/changed code on subsequent commits
- **7 detection categories** — secrets, PII, client data, vulnerabilities, dependencies, code smells, misconfigurations
- **Online LLM validation** — Gemini 2.5 Flash (primary) + Groq (fallback) with snippet-only transmission
- **JSON-based tracking** — no database required
- **Rich reporting** — console, JSON, and Markdown
- **Extensible architecture** — pluggable scanners and LLM providers

## Quick Start

```bash
# Install
pip install -e .

# Configure
cp .env.example .env          # Add GEMINI_API_KEY and/or GROQ_API_KEY
devsecops config --init

# Install hook
devsecops install-hook

# Scan manually
devsecops scan
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `devsecops scan` | Run security scan |
| `devsecops report` | View last report |
| `devsecops status` | Show configuration status |
| `devsecops history` | View scan history |
| `devsecops config` | Manage configuration |
| `devsecops install-hook` | Install Git pre-commit hook |
| `devsecops resolve` | Mark finding as resolved |

## Scanning Rules

| Scenario | Scope |
|----------|-------|
| First commit | All tracked files → baseline stored |
| Subsequent commits | Staged files only via `git diff --cached` |

## Detection Categories

| Category | Severity | Blocks Commit |
|----------|----------|---------------|
| Secrets & Credentials | CRITICAL | Yes |
| PII | CRITICAL | Yes |
| Client Confidential | HIGH | Yes |
| Security Vulnerabilities | HIGH/CRITICAL | Yes |
| Dependency CVEs | HIGH/CRITICAL | Yes |
| Code Smells | MEDIUM | Configurable |
| Misconfigurations | HIGH | Yes |

## Architecture

```
Developer Commit → Git Hook → Diff Analysis → Scanners → LLM Validation → Report → Pass/Fail
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full diagram.

## Project Structure

```
├── src/devsecops/
│   ├── cli/           # Typer CLI
│   ├── core/          # Config, git, models, storage
│   ├── scanners/      # Secret, PII, vuln, dep, smell, misconfig
│   ├── llm/           # Gemini + Groq providers
│   ├── reporting/     # Console, JSON, Markdown
│   └── hooks/         # Git hook installer
├── tests/             # Unit + integration tests
├── docs/              # Installation, usage, architecture, security
├── samples/reports/   # Sample scan reports
├── Dockerfile
└── .github/workflows/ # CI pipeline
```

## Configuration

`.devsecops/config.yaml`:

```yaml
enable_llm: true
llm_provider: gemini
block_medium: false
scanners:
  secrets: true
  pii: true
  vulnerabilities: true
external_tools:
  gitleaks: true
  semgrep: true
  osv_scanner: true
```

## Docker

```bash
docker build -t devsecops-guardian .
docker run --rm -v $(pwd):/repo -w /repo devsecops-guardian scan --no-llm
```

## Testing

```bash
pip install -e ".[dev]"
DEVSECOPS_ENABLE_LLM=false pytest tests/ -v
```

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)

## License

MIT

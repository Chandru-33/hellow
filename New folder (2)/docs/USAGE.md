# Usage Guide

## CLI Commands

### `devsecops scan`

Run a security scan on staged files (or all tracked files on first commit).

```bash
devsecops scan                  # Scan current repo
devsecops scan /path/to/repo    # Scan specific repo
devsecops scan --no-llm         # Skip LLM validation
devsecops scan --hook           # Pre-commit hook mode (exit 1 on block)
```

### `devsecops report`

View the last scan report.

```bash
devsecops report                # Console summary
devsecops report -f json        # JSON output
devsecops report -f markdown    # Markdown output
```

### `devsecops status`

Show configuration and provider status.

```bash
devsecops status
```

### `devsecops history`

View scan history.

```bash
devsecops history
devsecops history --limit 20
```

### `devsecops config`

Manage configuration.

```bash
devsecops config --init         # Create default config
devsecops config --show         # Display current config
```

### `devsecops install-hook`

Install the Git pre-commit hook.

```bash
devsecops install-hook
devsecops install-hook --pre-commit
```

### `devsecops resolve`

Mark a finding as resolved (won't re-flag until code reappears).

```bash
devsecops resolve <fingerprint>
```

## Scanning Behavior

### First Commit

When no baseline exists (`git init` → `git add .` → `git commit`):

- Scans **all tracked files**
- Creates baseline snapshot in `.devsecops/baseline.json`

### Subsequent Commits

- Scans **only staged files** via `git diff --cached`
- Analyzes only added/modified lines
- Unchanged code is never scanned

## Commit Blocking Rules

| Severity | Default Behavior |
|----------|-----------------|
| CRITICAL | Block commit |
| HIGH | Block commit |
| MEDIUM | Allow (configurable) |
| LOW | Allow commit |

Configure in `.devsecops/config.yaml`:

```yaml
severity_block_rules:
  CRITICAL: true
  HIGH: true
  MEDIUM: false   # Set true to block
  LOW: false
```

Or via environment:

```env
DEVSECOPS_BLOCK_MEDIUM=true
```

## Client Confidential Patterns

Edit `client_patterns.yaml` or `.devsecops/client_patterns.yaml`:

```yaml
restricted_clients:
  - ClientABC
  - ClientXYZ

internal_urls:
  - internal.company.com

internal_hostnames:
  - prod-db-internal
```

## Workflow Example

```bash
# 1. Initialize
devsecops config --init
devsecops install-hook

# 2. Develop
echo 'password = "secret123"' >> app.py
git add app.py

# 3. Commit (hook runs automatically)
git commit -m "Add feature"
# → COMMIT BLOCKED: Secret detected

# 4. Fix and retry
# Remove secret, use os.environ["PASSWORD"]
git add app.py
git commit -m "Add feature with env var"
# → ✓ No blocking issues detected
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: DevSecOps Scan
  run: |
    pip install devsecops-guardian
    devsecops scan --no-llm
```

## Report Locations

- JSON: `.devsecops/reports/scan_YYYYMMDD_HHMMSS.json`
- Markdown: `.devsecops/reports/scan_YYYYMMDD_HHMMSS.md`
- Latest: `.devsecops/last_report.json`

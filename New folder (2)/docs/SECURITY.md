# Security Documentation

## Threat Model

DevSecOps Guardian operates as a **preventive control** at the Git commit boundary. It protects against:

- Accidental secret/credential commits
- PII and client data leakage
- Known vulnerability patterns in new code
- Vulnerable dependency introduction
- Security misconfigurations in IaC/config files

## What This Tool Does NOT Replace

- Runtime application security testing (DAST)
- Production secret rotation
- Code review and security architecture review
- Penetration testing
- Full SCA across entire dependency trees in CI

## Data Handling

### Local Processing

- All regex, entropy, and pattern scanning runs locally
- Git diff analysis is entirely local
- External tools (Gitleaks, Semgrep, OSV) process local files only

### LLM Data Transmission

When LLM validation is enabled:

- **Only** code snippets (±20 lines around findings) are sent to Gemini/Groq
- Full files, repositories, and unchanged code are **never** transmitted
- API keys are loaded from `.env` and never committed

### Stored Data

JSON files in `.devsecops/` may contain:
- Finding snippets (truncated)
- File paths and line numbers
- Scan metadata

**Recommendation:** Add `.devsecops/last_report.json` and `.devsecops/reports/` to `.gitignore` if reports contain sensitive context.

## API Key Security

```env
# .env (never commit)
GEMINI_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
```

- Keys are read via `python-dotenv` at runtime
- Keys are never logged, printed, or included in reports
- The secret scanner detects hardcoded API keys in source code

## Commit Blocking Policy

| Category | Severity | Blocks |
|----------|----------|--------|
| Secrets | CRITICAL | Yes |
| PII | CRITICAL | Yes |
| Client Confidential | HIGH | Yes |
| Vulnerabilities | HIGH/CRITICAL | Yes |
| Dependencies | HIGH/CRITICAL | Yes |
| Misconfigurations | HIGH | Yes |
| Code Smells | MEDIUM | Configurable |

## False Positive Management

1. **LLM Validation** — Gemini/Groq confirms or rejects scanner findings
2. **Resolution Tracking** — `devsecops resolve <fingerprint>` suppresses known false positives
3. **Re-flagging** — If identical insecure code reappears, it is flagged again

## Hook Security

The pre-commit hook:
- Runs before commit finalization
- Cannot be bypassed without `--no-verify` (document this in team policy)
- Exits with code 1 to block commits

## Dependency Security

The project itself should be scanned regularly:

```bash
pip install osv-scanner
osv-scanner -L pyproject.toml
```

## Reporting Security

Reports include:
- File paths and line numbers
- Code snippets (potentially sensitive)
- Recommended fixes

Store reports securely. Do not share reports containing real secrets or PII.

## Compliance Considerations

- Supports shift-left security in SDLC
- Provides audit trail via `scan_history.json`
- Fingerprint-based issue tracking for remediation workflows
- Configurable severity blocking for policy alignment

## Incident Response

If a secret is committed despite the hook:

1. **Rotate** the exposed credential immediately
2. **Remove** from Git history (`git filter-repo` or BFG)
3. **Review** why the hook did not catch it (bypass, config, pattern gap)
4. **Update** scanner rules or client patterns as needed

## Security Contact

Report vulnerabilities in this tool through your organization's standard security channel.

# Installation Guide

## Prerequisites

- Python 3.12 or higher
- Git 2.x
- (Optional) External security tools for enhanced scanning:
  - [Gitleaks](https://github.com/gitleaks/gitleaks)
  - [Semgrep](https://semgrep.dev/)
  - [OSV Scanner](https://google.github.io/osv-scanner/)
  - [Trufflehog](https://github.com/trufflesecurity/trufflehog) (optional)

## Quick Install

```bash
pip install devsecops-guardian
```

Or install from source:

```bash
git clone <repository-url>
cd devsecops-guardian
pip install -e ".[dev]"
```

## Environment Setup

1. Copy the environment template:

```bash
cp .env.example .env
```

2. Add your API keys:

```env
GEMINI_API_KEY=your_gemini_api_key
GROQ_API_KEY=your_groq_api_key
```

LLM validation requires at least one API key. Gemini 2.5 Flash is the primary provider; Groq is the fallback.

## Initialize Configuration

```bash
devsecops config --init
```

This creates:

- `.devsecops/config.yaml` — scanner and blocking rules
- `.devsecops/client_patterns.yaml` — restricted client patterns

## Install Git Hook

```bash
devsecops install-hook
```

For pre-commit framework integration:

```bash
devsecops install-hook --pre-commit
pre-commit install
```

## Docker Install

```bash
docker build -t devsecops-guardian .
docker run --rm -v $(pwd):/repo -w /repo devsecops-guardian scan --no-llm
```

## Optional External Tools

### Gitleaks

```bash
# macOS
brew install gitleaks

# Linux
curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar xz
sudo mv gitleaks /usr/local/bin/
```

### Semgrep

```bash
pip install semgrep
```

### OSV Scanner

```bash
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

## Verify Installation

```bash
devsecops --version
devsecops status
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Hook not running | Ensure `.git/hooks/pre-commit` is executable (`chmod +x`) |
| LLM validation skipped | Check `.env` for valid API keys |
| Slow scans | Disable unused scanners in `.devsecops/config.yaml` |
| False positives | Mark resolved: `devsecops resolve <fingerprint>` |

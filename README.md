# Lynx

A fast, local-first CLI that scans repositories and filesystems for leaked credentials, API keys, and high-entropy secrets.

Lynx uses regex detection rules, Shannon entropy filtering, optional baselines for known findings, and CI-friendly exit codes. All scanning is local — **no telemetry**.

**Authorized use only:** scan repositories and filesystems you own or have explicit permission to audit.

## Install

```bash
go install github.com/direo/lynx/cmd/lynx@latest
```

Or build from source:

```bash
git clone https://github.com/direo/lynx.git
cd lynx
make build
./bin/lynx version
```

## Quick start

```bash
# Scan current directory (working tree)
lynx scan .

# Scan git history for secrets that may have been removed
lynx scan . --history

# Limit history depth on large repos
lynx scan . --history --max-commits 200

# JSON for CI
lynx scan ./src -o json > findings.json

# SARIF for GitHub code scanning
lynx scan . -o sarif > results.sarif

# Custom rules + baseline
lynx scan . -r my-rules.yaml -b .lynx-baseline.json

# Create a baseline from current findings
lynx baseline create .

# Baseline from history findings
lynx baseline create . --history
```

## Commands

| Command | Description |
|---------|-------------|
| `lynx scan [path]` | Scan a directory or repo (default: `.`) |
| `lynx rules list` | List built-in detection rules |
| `lynx rules validate [file]` | Validate a custom rules YAML file |
| `lynx baseline create [path]` | Generate a baseline from current findings |
| `lynx version` | Print version |

### Scan flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--rules` | `-r` | built-in | Path to custom rules YAML |
| `--exclude` | `-e` | — | Extra glob / directory names to exclude |
| `--output` | `-o` | `table` | Output format: `table`, `json`, `sarif` |
| `--baseline` | `-b` | none | Baseline file to suppress known findings |
| `--entropy-threshold` | | `0` | Raise entropy floor for rules that set `entropy` (`0` = use each rule's value) |
| `--verify` | | false | Attempt live verification of findings |
| `--max-file-size` | | `1MB` | Skip files larger than this |
| `--no-git-ignore` | | false | Do not respect `.gitignore` |
| `--history` | | false | Scan git history (unique blob paths from `HEAD`) instead of the working tree |
| `--max-commits` | | `0` | With `--history`, limit to N most recent commits (`0` = all) |
| `--fail-on-find` | | true | Exit 1 when secrets found |
| `--no-fail-on-find` | | false | Always exit 0 when scan succeeds |
| `--quiet` | | false | Suppress progress on stderr |

`--history` requires `git` on `PATH` and a repository at the scan path. It deduplicates by blob OID + path and reports the first-seen commit for each finding. Default directory excludes (e.g. `node_modules`) still apply by path; `.gitignore` does not apply to historical blobs.

Exit codes: `0` clean, `1` findings (when fail-on-find), `2` error.

## Built-in rules

Lynx ships with rules for AWS keys, GitHub PATs, Slack webhooks, Stripe keys, generic API keys, PEM private keys, JWTs, database URLs, and npm tokens.

```bash
lynx rules list
```

## Custom rules

```yaml
rules:
  - id: my-org-token
    description: My org API token
    regex: 'ORG_[A-Za-z0-9]{32}'
    severity: high
    entropy: 3.5          # optional; enables entropy filtering for this rule
    keywords:             # optional; match must be near one of these
      - ORG_
```

Validate before use:

```bash
lynx rules validate my-rules.yaml
lynx scan . -r my-rules.yaml
```

## Baselines

Ignore known/accepted findings (fingerprints only — still treat the file carefully):

```bash
lynx baseline create . -o .lynx-baseline.json
lynx scan . -b .lynx-baseline.json
```

Add `.lynx-baseline.json` to `.gitignore` if fingerprints should stay private.

## Live verification

`--verify` is **opt-in**. Today it can check GitHub personal access tokens via the GitHub API. It may send candidate secrets to that API — only use this on repositories you are authorized to audit.

## CI examples

### GitHub Actions

```yaml
name: Secret scan
on: [push, pull_request]
jobs:
  lynx:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.1"
      - run: go install github.com/direo/lynx/cmd/lynx@latest
      - run: lynx scan . -o sarif > lynx.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: lynx.sarif
```

### GitLab CI

```yaml
lynx:
  image: golang:1.26
  script:
    - go install github.com/direo/lynx/cmd/lynx@latest
    - lynx scan . -o json | tee lynx-findings.json
  artifacts:
    when: always
    paths:
      - lynx-findings.json
```

## Security notes

- Findings printed to stdout may contain secret material (JSON includes full matches) — pipe carefully.
- No telemetry; scanning is entirely local unless `--verify` is set.
- Test fixtures under `testdata/` use documented fake credentials only.

## License

MIT

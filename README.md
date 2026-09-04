# inkshade

**ink + shade** — a Go CLI that masks personally identifiable information (PII) and credentials (API keys / tokens) in text streams.

Candidates are extracted via regex, then validated with Luhn / libphonenumber / net/netip (and Shannon entropy for two short-prefix credential rules) before masking, resulting in fewer false positives than naive regex matching.

## Install

### Homebrew

```bash
brew install toritori0318/inkshade/inkshade
```

### go install

```bash
go install github.com/toritori0318/inkshade@latest
```

### Build from source

```bash
git clone https://github.com/toritori0318/inkshade.git
cd inkshade
go build -o inkshade .
```

## Quick Start

```bash
# pipe (default: mask mode, PII rules only)
echo "contact tanaka@example.com 090-1234-5678" | inkshade
# → contact [EMAIL] [PHONE]

# file input
inkshade access.log > masked.log

# detect mode — check if sensitive data exists
inkshade --mode detect input.txt
# → detected   or   clean

# diagnose mode — show what matched and where
inkshade --mode diagnose --format ndjson app.log

# CI mode — exit 1 if any finding
inkshade --mode detect --fail-on-detect secrets.txt

# credentials only
echo "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789" | inkshade --preset secrets
# → token=[GITHUB_TOKEN]

# PII + credentials
echo "mail tanaka@example.com key AKIAIOSFODNN7EXAMPLE" | inkshade --preset all
# → mail [EMAIL] key [AWS_ACCESS_KEY]
```

## Modes

| Mode | Description |
|------|-------------|
| `mask` (default) | Replace findings with labels and output masked text |
| `detect` | Output `detected` or `clean` per line (or ndjson with `--format ndjson`) |
| `diagnose` | Show rule ID, match position, matched text for each finding |

### detect output

Text:

```
detected
clean
```

With `--format ndjson`:

```json
{"line":1,"has_findings":true,"count":1,"rules":["aws_access_key"]}
```

### diagnose output

> **Note:** Diagnose mode outputs matched PII and credential values in plain text. Avoid using it in CI logs or other environments where output may be persisted or shared.

```
line=1    rule=email          span=8-26   match="tanaka@example.com"  replace="[EMAIL]"
line=1    rule=phone          span=27-40  match="090-1234-5678"       replace="[PHONE]"
```

With `--format ndjson`:

```json
{"line":1,"rule_id":"email","name":"Email Address","start":8,"end":26,"text":"tanaka@example.com","replace":"[EMAIL]"}
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `mask` | `mask` / `detect` / `diagnose` |
| `--format` | `text` | Output format: `text` / `ndjson` / `sarif` |
| `--config` | — | YAML config file path |
| `--preset` | — | Rule preset: `jp-strict`, `secrets`, `all` |
| `--disable` | — | Comma-separated rule IDs to disable |
| `--replace` | — | Custom replacements: `email=[E],phone=[TEL]` |
| `--mask-style` | `label` | Mask style: `label`, `partial`, or `pseudo` |
| `--dry-run` | `false` | Show unified-diff-style preview (mask mode only) |
| `--git-staged` | `false` | Scan git staged files |
| `--fail-on-detect` | `false` | Exit 1 if sensitive data detected |
| `--output` | stdout | Output file path |
| `--version` | — | Show version and exit |

With no `--preset`, only the default PII rules run. `--preset secrets` enables credential rules only. `--preset all` enables every PII and credential rule.

## Supported PII Types

| Rule ID | Type | Label | Validation |
|---------|------|-------|------------|
| `email` | Email address | `[EMAIL]` | Regex |
| `credit_card` | Credit card number | `[CREDIT_CARD]` | Regex + Luhn check |
| `phone` | Phone number (JP) | `[PHONE]` | Regex + [libphonenumber](https://github.com/nyaruka/phonenumbers) |
| `ip_addr` | IPv4 address | `[IP_ADDR]` | Regex + [net/netip](https://pkg.go.dev/net/netip) |
| `postal` | Postal code (JP) | `[POSTAL]` | Regex |

### JP-Strict Preset

Enable with `--preset jp-strict` to add Japan-specific rules:

| Rule ID | Type | Label | Validation |
|---------|------|-------|------------|
| `my_number` | My Number (Individual Number) | `[MY_NUMBER]` | 12-digit + MOD 11 check digit |
| `bank_account` | Bank account number | `[BANK_ACCOUNT]` | 7-digit + contextual keyword detection |

## Secrets Preset

Enable with `--preset secrets` (credentials only) or `--preset all` (PII + credentials).

| Rule ID | Type | Prefix | Label |
|---------|------|--------|-------|
| `klaviyo_pk` | Klaviyo Private API Key | `pk_` | `[KLAVIYO_PK]` |
| `stripe_sk` | Stripe Secret Key | `sk_live_` / `sk_test_` | `[STRIPE_SK]` |
| `shopify_token` | Shopify Access Token | `shpat_` / `shpca_` / `shpss_` / `shpua_` / `shppa_` | `[SHOPIFY_TOKEN]` |
| `github_token` | GitHub Token | `ghp_` / `gho_` / `ghs_` / `ghr_` / `ghu_` / `github_pat_` | `[GITHUB_TOKEN]` |
| `google_api_key` | Google API Key | `AIza` | `[GOOGLE_API_KEY]` |
| `google_oauth` | Google OAuth Token | `ya29.` | `[GOOGLE_OAUTH]` |
| `meta_token` | Meta Access Token | `EAA` | `[META_TOKEN]` |
| `slack_token` | Slack Token | `xoxb-` / `xoxp-` | `[SLACK_TOKEN]` |
| `aws_access_key` | AWS Access Key ID | `AKIA` | `[AWS_ACCESS_KEY]` |
| `anthropic_key` | Anthropic API Key | `sk-ant-` | `[ANTHROPIC_KEY]` |

```bash
echo "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789" | inkshade --preset secrets
# → token=[GITHUB_TOKEN]

echo "ghp_abcdefghijklmnopqrstuvwxyz0123456789" | inkshade --preset secrets --mask-style partial
# → ghp_***MASKED***
```

Credential patterns are derived from our own pre-commit hook and masking module; they are not copied from third-party secret scanners.

## Mask Styles

### Label (default)

```bash
echo "tanaka@example.com 4111111111111111" | inkshade
# → [EMAIL] [CREDIT_CARD]
```

### Partial

Preserves structure while masking sensitive digits. Credential rules keep their public prefix:

```bash
echo "tanaka@example.com 4111111111111111 090-1234-5678" | inkshade --mask-style partial
# → t*****@e******.com ************1111 ***-****-5678

echo "ghp_abcdefghijklmnopqrstuvwxyz0123456789" | inkshade --preset secrets --mask-style partial
# → ghp_***MASKED***
```

### Pseudonymize

Replace PII with deterministic fake values. The same input always produces the same output, useful for preserving referential integrity across documents. Unregistered rule IDs (including credentials) fall back to `[PSEUDO_<hash8>]`.

```bash
echo "tanaka@example.com 4111111111111111 090-1234-5678" | inkshade --mask-style pseudo
# → user_75ceba6f@masked.example ****-****-****-9bbe ***-****-522d
```

## Dry Run

Preview changes without modifying output:

```bash
echo "tanaka@example.com 090-1234-5678" | inkshade --dry-run
# @@ line 1 @@
# -tanaka@example.com 090-1234-5678
# +[EMAIL] [PHONE]
```

## Git Staged Scanning

Scan files in the git staging area:

```bash
inkshade --git-staged --mode detect --fail-on-detect
```

## YAML Configuration

```yaml
# inkshade.yaml
mode: mask
mask_style: partial
# preset: secrets  # or jp-strict / all

rules:
  email:
    enabled: true
    replace: "[EMAIL]"
  ip_addr:
    enabled: false

allowlist:
  literals:
    - "test@example.com"
    - "127.0.0.1"
  patterns:
    - '.*@example\.com'
    - '192\.168\.\d+\.\d+'
```

```bash
inkshade --config inkshade.yaml input.txt

# CLI flags override YAML settings when explicitly specified
inkshade --config inkshade.yaml --mode mask input.txt
```

## Fullwidth Support

Input is normalized via [NFKC](https://unicode.org/reports/tr15/) before matching, so fullwidth digits and common hyphen variants are handled transparently.

## How It Works

```
Input → NFKC normalize → Regex candidate extraction (all rules)
                        → Validator (Luhn / phonenumbers / netip / context / entropy)
                        → Allowlist filtering
                        → Overlap resolution (longest match wins)
                        → Mode-specific output (mask / detect / diagnose)
```

## CI Integration

### GitHub Actions

```yaml
- name: Check for PII and credential leaks
  run: |
    go install github.com/toritori0318/inkshade@latest
    cat .env config.yaml | inkshade --preset all --mode detect --fail-on-detect --format ndjson
```

### GitHub Code Scanning (SARIF)

```yaml
- name: Scan for PII and credentials
  run: |
    go install github.com/toritori0318/inkshade@latest
    inkshade --format sarif app.log > results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
#!/bin/sh
inkshade --git-staged --mode detect --fail-on-detect
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success (no sensitive data found, or mask completed) |
| `1` | Sensitive data detected (with `--fail-on-detect`) |
| `2` | Scan error (I/O failure, malformed input) |

## Known Limitations

- **Multi-line PEM private keys are not detected.** inkshade processes input line by line; multi-line credentials such as `-----BEGIN PRIVATE KEY-----` blocks are out of scope.
- **Two tokens of the same rule separated by a single delimiter** (e.g. `pk_xxx,pk_yyy`) mask only the first token, because Go's RE2 engine has no lookaround and the consumed boundary character hides the second token's start. Tokens separated by two or more characters (e.g. `, `) are both masked. Adjacent tokens of *different* rules are both masked.
- **Output is NFKC-normalized.** The whole line is normalized before masking, so unmasked parts of a line containing full-width characters may differ byte-wise from the input.
- **`klaviyo_pk` and `meta_token` additionally require a minimum Shannon entropy** in the token body, because their prefixes (`pk_`, `EAA`) are short and collide easily with ordinary text. Degenerate tokens such as `pk_aaaa…` are not masked.
- **Version numbers** like `1.2.3.4` are valid IPv4 addresses and will be masked as `[IP_ADDR]`.
- **Names and addresses** require NLP/dictionary-based detection and are out of scope for regex-based masking.

## Development

### Prerequisites

- Go 1.25+

### Build

```bash
go build -o inkshade .

# with version stamp
go build -ldflags "-X main.version=0.1.0" -o inkshade .
```

### Run Tests

```bash
# all tests
go test ./...

# verbose output
go test -v ./...

# with coverage report
go test -cover ./...

# coverage by function
go test -coverprofile=cover.out ./... && go tool cover -func=cover.out

# HTML coverage report
go test -coverprofile=cover.out ./... && go tool cover -html=cover.out
```

### Benchmarks

```bash
go test -bench=. -benchmem ./...
```

### Lint

```bash
go vet ./...
```

## License

MIT

inkshade is the successor to [snipii](https://github.com/toritori0318/snipii) (same author, MIT). snipii is archived.

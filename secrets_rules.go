package main

import (
	"math"
	"regexp"
	"strings"
)

// Credential rules are derived from the author's own pre-commit hook and
// log-masking module. They are NOT copied from third-party scanners:
// TruffleHog is AGPL-3.0 (incompatible with this MIT tool) and gitleaks' MIT
// rules would require attribution we do not want to carry. Only the
// entropy-cutoff idea (which carries no license obligation) is borrowed.
//
// RE2 has no lookaround, so token boundaries are consumed character
// classes; group 1 (the token itself) is the finding span (Rule.Group).
var secretsRules = []Rule{
	{
		ID: "klaviyo_pk", Name: "Klaviyo Private API Key", Priority: 100, Group: 1,
		// Stripe publishable keys (pk_live_/pk_test_) do not match: the
		// body class excludes "_", so "live"/"test" is too short.
		Pattern:  regexp.MustCompile(`(?:^|[^0-9A-Za-z_])(pk_[0-9A-Za-z]{30,})(?:[^0-9A-Za-z_]|$)`),
		Replace:  "[KLAVIYO_PK]",
		Validate: secretBodyEntropy("klaviyo_pk", minBodyEntropy),
	},
	{
		ID: "stripe_sk", Name: "Stripe Secret Key", Priority: 101, Group: 1,
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z_])(sk_(?:live|test)_[0-9A-Za-z]{24,})(?:[^0-9A-Za-z_]|$)`),
		Replace: "[STRIPE_SK]",
	},
	{
		ID: "shopify_token", Name: "Shopify Access Token", Priority: 102, Group: 1,
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z_])(shp(?:at|ca|ss|ua|pa)_[0-9a-fA-F]{16,})(?:[^0-9A-Za-z_]|$)`),
		Replace: "[SHOPIFY_TOKEN]",
	},
	{
		ID: "github_token", Name: "GitHub Token", Priority: 103, Group: 1,
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z_])(gh[posru]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{82,})(?:[^0-9A-Za-z_]|$)`),
		Replace: "[GITHUB_TOKEN]",
	},
	{
		ID: "google_api_key", Name: "Google API Key", Priority: 104, Group: 1,
		// Fixed 35-char body: avoids matching inside longer base64url runs.
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z_-])(AIza[0-9A-Za-z_-]{35})(?:[^0-9A-Za-z_-]|$)`),
		Replace: "[GOOGLE_API_KEY]",
	},
	{
		ID: "google_oauth", Name: "Google OAuth Token", Priority: 105, Group: 1,
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z_-])(ya29\.[0-9A-Za-z_-]{20,})(?:[^0-9A-Za-z_-]|$)`),
		Replace: "[GOOGLE_OAUTH]",
	},
	{
		ID: "meta_token", Name: "Meta Access Token", Priority: 106, Group: 1,
		// "EAA" is a common trigram inside base64 blobs, so this rule carries
		// the highest false-positive risk of the ten; entropy cuts padding.
		Pattern:  regexp.MustCompile(`(?:^|[^0-9A-Za-z_])(EAA[0-9A-Za-z]{30,})(?:[^0-9A-Za-z_]|$)`),
		Replace:  "[META_TOKEN]",
		Validate: secretBodyEntropy("meta_token", minBodyEntropy),
	},
	{
		ID: "slack_token", Name: "Slack Token", Priority: 107, Group: 1,
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z_-])(xox[bp]-[0-9A-Za-z-]{10,})(?:[^0-9A-Za-z_-]|$)`),
		Replace: "[SLACK_TOKEN]",
	},
	{
		ID: "aws_access_key", Name: "AWS Access Key ID", Priority: 108, Group: 1,
		// Boundary is [^0-9A-Za-z]: "_" counts as a boundary here (per source).
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z])(AKIA[0-9A-Z]{16})(?:[^0-9A-Za-z]|$)`),
		Replace: "[AWS_ACCESS_KEY]",
	},
	{
		ID: "anthropic_key", Name: "Anthropic API Key", Priority: 109, Group: 1,
		Pattern: regexp.MustCompile(`(?:^|[^0-9A-Za-z_-])(sk-ant-[0-9A-Za-z_-]{20,})(?:[^0-9A-Za-z_-]|$)`),
		Replace: "[ANTHROPIC_KEY]",
	},
}

func secretsRuleIDList() []string {
	ids := make([]string, 0, len(secretsRules))
	seen := map[string]bool{}
	for _, r := range secretsRules {
		if !seen[r.ID] {
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func allRulesWithSecrets() []Rule {
	return append(allRulesWithJP(), secretsRules...)
}

// secretsPrefixes maps rule ID -> known public prefixes, longest first.
// Used by the partial mask style to keep the prefix and hide the body.
var secretsPrefixes = map[string][]string{
	"klaviyo_pk":     {"pk_"},
	"stripe_sk":      {"sk_live_", "sk_test_"},
	"shopify_token":  {"shpat_", "shpca_", "shpss_", "shpua_", "shppa_"},
	"github_token":   {"github_pat_", "ghp_", "gho_", "ghs_", "ghr_", "ghu_"},
	"google_api_key": {"AIza"},
	"google_oauth":   {"ya29."},
	"meta_token":     {"EAA"},
	"slack_token":    {"xoxb-", "xoxp-"},
	"aws_access_key": {"AKIA"},
	"anthropic_key":  {"sk-ant-"},
}

const secretsMaskPlaceholder = "***MASKED***"

// minBodyEntropy rejects degenerate bodies (padding like "aaaa..."). It is set
// low on purpose: every real key sits far above it, so this must never become
// a tuning knob that silently narrows what we detect.
const minBodyEntropy = 3.0

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// secretBodyEntropy reads secretsPrefixes at match time, not at init time, so
// package-level initialization order does not matter.
func secretBodyEntropy(ruleID string, min float64) func(string) bool {
	return func(s string) bool {
		body := s
		for _, p := range secretsPrefixes[ruleID] {
			if strings.HasPrefix(s, p) {
				body = s[len(p):]
				break
			}
		}
		return shannonEntropy(body) >= min
	}
}

func partialMaskSecretToken(prefixes []string) func(string) string {
	return func(s string) string {
		for _, p := range prefixes {
			if len(s) > len(p) && s[:len(p)] == p {
				return p + secretsMaskPlaceholder
			}
		}
		return partialMaskGeneric(s, 0)
	}
}

func init() {
	secretIDs := secretsRuleIDList()
	presets["secrets"] = secretIDs
	// "all" is derived, not hand-written, so it can never drift from the
	// rule definitions: hand-written lists silently drift when rules are added.
	all := append([]string{}, presets["jp-strict"]...)
	presets["all"] = append(all, secretIDs...)

	for id, prefixes := range secretsPrefixes {
		partialMaskFuncs[id] = partialMaskSecretToken(prefixes)
	}
}

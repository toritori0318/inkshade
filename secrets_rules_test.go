package main

import (
	"math"
	"strings"
	"testing"
)

func newSecretsEngine(t *testing.T, preset string) *Engine {
	t.Helper()
	cfg := DefaultConfig()
	cfg.EnabledPreset = preset
	return NewEngine(cfg)
}

// stripeLiveMin and stripeTestMin are concatenated so the file never contains
// a contiguous Stripe-shaped token. GitHub push protection treats those
// literals as live keys even when they are synthetic.
func stripeLiveMin() string { return "sk_live_" + "abcdefghijklmnopqrstuvwx" }
func stripeTestMin() string { return "sk_test_" + "abcdefghijklmnopqrstuvwx" }

// Synthetic tokens whose body is exactly the minimum length. Not real keys.
var minimalSecrets = map[string]string{
	"klaviyo_pk":     "pk_abcdefghijklmnopqrstuvwxyz0123",        // pk_ + 30
	"stripe_sk":      stripeLiveMin(),                            // sk_live_ + 24
	"shopify_token":  "shpat_0123456789abcdef",                   // shpat_ + 16 hex
	"github_token":   "ghp_abcdefghijklmnopqrstuvwxyz0123456789", // ghp_ + 36
	"google_api_key": "AIzaabcdefghijklmnopqrstuvwxyz012345678",  // AIza + 35 (fixed)
	"google_oauth":   "ya29.abcdefghijklmnopqrst",                // ya29. + 20
	"meta_token":     "EAAabcdefghijklmnopqrstuvwxyz0123",        // EAA + 30
	"slack_token":    "xoxb-1234567890",                          // xoxb- + 10
	"aws_access_key": "AKIAIOSFODNN7EXAMPLE",                     // AKIA + 16 (fixed, AWS docs example)
	"anthropic_key":  "sk-ant-api03-abcdefghijklmn",              // sk-ant- + 20
}

func TestKlaviyoPkFindingSpanIsTokenBodyOnly(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	token := minimalSecrets["klaviyo_pk"]
	input := "key " + token + " end"
	findings := e.Detect(input)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].RuleID != "klaviyo_pk" {
		t.Errorf("RuleID = %q, want klaviyo_pk", findings[0].RuleID)
	}
	if findings[0].Text != token {
		t.Errorf("Text = %q, want %q (span must exclude boundary characters)", findings[0].Text, token)
	}
}

func TestMaskPreservesBoundaryCharacters(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	input := "key " + minimalSecrets["klaviyo_pk"] + " end"
	result := e.Process(input)
	want := "key [KLAVIYO_PK] end"
	if result.Output != want {
		t.Errorf("Output = %q, want %q", result.Output, want)
	}
}

func TestTokensShorterThanMinimumAreNotDetected(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	githubPat81 := "github_pat_" + "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz012"
	tests := []struct {
		name  string
		token string
	}{
		{"klaviyo_pk body 29", "pk_abcdefghijklmnopqrstuvwxyz012"},
		{"stripe_sk body 23", "sk_live_abcdefghijklmnopqrstuvw"},
		{"shopify_token body 15", "shpat_0123456789abcde"},
		{"github_token ghp body 35", "ghp_abcdefghijklmnopqrstuvwxyz012345678"},
		{"github_token pat body 81", githubPat81},
		{"google_api_key body 34", "AIzaabcdefghijklmnopqrstuvwxyz01234567"},
		{"google_oauth body 19", "ya29.abcdefghijklmnopqrs"},
		{"meta_token body 29", "EAAabcdefghijklmnopqrstuvwxyz012"},
		{"slack_token body 9", "xoxb-123456789"},
		{"aws_access_key body 15", "AKIAIOSFODNN7EXAMPL"},
		{"anthropic_key body 19", "sk-ant-api03-abcdefghijklm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := e.Detect("a " + tt.token + " b")
			if len(findings) != 0 {
				t.Errorf("want 0 findings for %q, got %v", tt.token, findings)
			}
		})
	}
}

func TestAdjacentIdentifierCharactersAreNotDetected(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	ids := []string{
		"klaviyo_pk", "stripe_sk", "shopify_token", "github_token",
		"google_api_key", "google_oauth", "meta_token", "slack_token",
		"aws_access_key", "anthropic_key",
	}
	for _, id := range ids {
		token := minimalSecrets[id]
		t.Run(id+"/prefix", func(t *testing.T) {
			findings := e.Detect("x" + token)
			if len(findings) != 0 {
				t.Errorf("want 0 findings for prefix-joined %q, got %v", token, findings)
			}
		})
	}
	// Suffix joins only reject a match when the extra character is an
	// identifier but cannot be absorbed into the body (fixed length, or a
	// body class that excludes it). Unbounded [0-9A-Za-z] bodies swallow "x".
	suffixCases := []struct {
		id     string
		suffix string
	}{
		{"shopify_token", "x"},  // x is not hex
		{"google_api_key", "x"}, // fixed 35-char body
		{"aws_access_key", "a"}, // [^0-9A-Za-z] boundary; lowercase is an identifier
	}
	for _, tt := range suffixCases {
		token := minimalSecrets[tt.id]
		t.Run(tt.id+"/suffix", func(t *testing.T) {
			findings := e.Detect(token + tt.suffix)
			if len(findings) != 0 {
				t.Errorf("want 0 findings for suffix-joined %q, got %v", token+tt.suffix, findings)
			}
		})
	}
}

var prefixVariants = []struct {
	ruleID string
	token  string
}{
	{"klaviyo_pk", "pk_abcdefghijklmnopqrstuvwxyz0123"},
	{"stripe_sk", stripeLiveMin()},
	{"stripe_sk", stripeTestMin()},
	{"shopify_token", "shpat_0123456789abcdef"},
	{"shopify_token", "shpca_0123456789abcdef"},
	{"shopify_token", "shpss_0123456789abcdef"},
	{"shopify_token", "shpua_0123456789abcdef"},
	{"shopify_token", "shppa_0123456789abcdef"},
	{"github_token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
	{"github_token", "gho_abcdefghijklmnopqrstuvwxyz0123456789"},
	{"github_token", "ghs_abcdefghijklmnopqrstuvwxyz0123456789"},
	{"github_token", "ghr_abcdefghijklmnopqrstuvwxyz0123456789"},
	{"github_token", "ghu_abcdefghijklmnopqrstuvwxyz0123456789"},
	{"github_token", "github_pat_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123"},
	{"google_api_key", "AIzaabcdefghijklmnopqrstuvwxyz012345678"},
	{"google_oauth", "ya29.abcdefghijklmnopqrst"},
	{"meta_token", "EAAabcdefghijklmnopqrstuvwxyz0123"},
	{"slack_token", "xoxb-1234567890"},
	{"slack_token", "xoxp-1234567890"},
	{"aws_access_key", "AKIAIOSFODNN7EXAMPLE"},
	{"anthropic_key", "sk-ant-api03-abcdefghijklmn"},
}

func TestMinimalLengthTokensAreDetected(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	for _, tt := range prefixVariants {
		t.Run(tt.ruleID+"/"+tt.token[:min(12, len(tt.token))], func(t *testing.T) {
			findings := e.Detect("a " + tt.token + " b")
			if len(findings) != 1 {
				t.Fatalf("want 1 finding for %q, got %d: %v", tt.token, len(findings), findings)
			}
			if findings[0].RuleID != tt.ruleID {
				t.Errorf("RuleID = %q, want %q", findings[0].RuleID, tt.ruleID)
			}
			if findings[0].Text != tt.token {
				t.Errorf("Text = %q, want %q", findings[0].Text, tt.token)
			}
		})
	}
}

func TestFixedLengthRulesRejectOversizedBodies(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	oversizedAIza := "AIzaabcdefghijklmnopqrstuvwxyz0123456789" // AIza + 36
	oversizedAKIA := "AKIAIOSFODNN7EXAMPLEX"                    // AKIA + 17
	longerKlaviyo := "pk_abcdefghijklmnopqrstuvwxyz01234"       // pk_ + 31

	if findings := e.Detect("a " + oversizedAIza + " b"); len(findings) != 0 {
		t.Errorf("AIza+36: want 0 findings, got %v", findings)
	}
	if findings := e.Detect("a " + oversizedAKIA + " b"); len(findings) != 0 {
		t.Errorf("AKIA+17: want 0 findings, got %v", findings)
	}
	findings := e.Detect("a " + longerKlaviyo + " b")
	if len(findings) != 1 {
		t.Fatalf("pk_+31: want 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].RuleID != "klaviyo_pk" {
		t.Errorf("RuleID = %q, want klaviyo_pk", findings[0].RuleID)
	}
}

func TestAWSBoundaryTreatsUnderscoreAsBoundary(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	aws := minimalSecrets["aws_access_key"]
	klaviyo := minimalSecrets["klaviyo_pk"]

	awsFindings := e.Detect("_" + aws + "_")
	if len(awsFindings) != 1 {
		t.Fatalf("AKIA surrounded by _: want 1 finding, got %d: %v", len(awsFindings), awsFindings)
	}
	if awsFindings[0].RuleID != "aws_access_key" {
		t.Errorf("RuleID = %q, want aws_access_key", awsFindings[0].RuleID)
	}

	klaviyoFindings := e.Detect("_" + klaviyo)
	if len(klaviyoFindings) != 0 {
		t.Errorf("pk_ after _: want 0 findings (underscore is an identifier), got %v", klaviyoFindings)
	}
}

func TestDefaultPresetDetectsSecrets(t *testing.T) {
	e := NewEngine(DefaultConfig())
	for id, token := range minimalSecrets {
		findings := e.Detect("a " + token + " b")
		found := false
		for _, f := range findings {
			if f.RuleID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default preset: %s %q should be detected, got %v", id, token, findings)
		}
	}
}

func TestDefaultPresetDoesNotEnableJPExtra(t *testing.T) {
	e := NewEngine(DefaultConfig())
	findings := e.Detect("my number 123456789018 口座 1234567")
	for _, f := range findings {
		if f.RuleID == "my_number" || f.RuleID == "bank_account" {
			t.Errorf("default preset should not enable jp-strict extras, got %v", findings)
		}
	}
}

func TestJPStrictPresetDoesNotDetectSecrets(t *testing.T) {
	e := newSecretsEngine(t, "jp-strict")
	for id, token := range minimalSecrets {
		findings := e.Detect("a " + token + " b")
		for _, f := range findings {
			if f.RuleID == id {
				t.Errorf("jp-strict: %s %q should not be detected", id, token)
			}
		}
	}
}

func TestAllPresetDetectsEmailAndSecrets(t *testing.T) {
	e := newSecretsEngine(t, "all")
	input := "tanaka@example.com " + minimalSecrets["aws_access_key"]
	findings := e.Detect(input)
	got := map[string]bool{}
	for _, f := range findings {
		got[f.RuleID] = true
	}
	if !got["email"] {
		t.Error("want email finding")
	}
	if !got["aws_access_key"] {
		t.Error("want aws_access_key finding")
	}
}

func TestTokenAtLineBoundariesIsDetected(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	token := minimalSecrets["stripe_sk"]
	tests := []struct {
		name  string
		input string
	}{
		{"start", token + " x"},
		{"end", "x " + token},
		{"whole line", token},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := e.Detect(tt.input)
			if len(findings) != 1 {
				t.Fatalf("want 1 finding, got %d: %v", len(findings), findings)
			}
			if findings[0].Text != token {
				t.Errorf("Text = %q, want %q", findings[0].Text, token)
			}
		})
	}
}

func TestAdjacentTokensOfDifferentRulesAreBothMasked(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	input := minimalSecrets["stripe_sk"] + "," + minimalSecrets["aws_access_key"]
	result := e.Process(input)
	want := "[STRIPE_SK],[AWS_ACCESS_KEY]"
	if result.Output != want {
		t.Errorf("Output = %q, want %q", result.Output, want)
	}
}

func TestAdjacentTokensOfSameRuleDropTheSecond(t *testing.T) {
	// Not a desired behavior: RE2 has no lookaround, so a consumed
	// one-character delimiter hides the next token of the same rule.
	// Two or more delimiter characters (e.g. ", ") let both match.
	e := newSecretsEngine(t, "secrets")
	a := minimalSecrets["klaviyo_pk"]
	b := "pk_abcdefghijklmnopqrstuvwxyz0124"
	oneDelim := e.Detect(a + "," + b)
	if len(oneDelim) != 1 {
		t.Fatalf("single delimiter: want 1 finding (first token only), got %d: %v", len(oneDelim), oneDelim)
	}
	if oneDelim[0].Text != a {
		t.Errorf("single delimiter: Text = %q, want first token %q", oneDelim[0].Text, a)
	}

	twoDelim := e.Detect(a + ", " + b)
	if len(twoDelim) != 2 {
		t.Fatalf("two-character delimiter: want 2 findings, got %d: %v", len(twoDelim), twoDelim)
	}
}

func TestPartialStyleKeepsKnownPrefixes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnabledPreset = "secrets"
	cfg.MaskStyle = MaskStylePartial
	e := NewEngine(cfg)
	tests := []struct {
		token string
		want  string
	}{
		{minimalSecrets["github_token"], "ghp_***MASKED***"},
		{stripeTestMin(), "sk_test_***MASKED***"},
		{minimalSecrets["google_oauth"], "ya29.***MASKED***"},
	}
	for _, tt := range tests {
		result := e.Process(tt.token)
		if result.Output != tt.want {
			t.Errorf("Process(%q) = %q, want %q", tt.token, result.Output, tt.want)
		}
	}
}

func TestMaskingIsIdempotent(t *testing.T) {
	styles := []MaskStyle{MaskStyleLabel, MaskStylePartial}
	token := minimalSecrets["stripe_sk"]
	for _, style := range styles {
		cfg := DefaultConfig()
		cfg.EnabledPreset = "secrets"
		cfg.MaskStyle = style
		e := NewEngine(cfg)
		first := e.Process(token)
		second := e.Process(first.Output)
		if len(second.Findings) != 0 {
			t.Errorf("style %s: remasking produced findings %v", style, second.Findings)
		}
		if second.Output != first.Output {
			t.Errorf("style %s: remask Output = %q, want %q", style, second.Output, first.Output)
		}
	}
	cfg := DefaultConfig()
	cfg.EnabledPreset = "secrets"
	cfg.MaskStyle = MaskStylePartial
	e := NewEngine(cfg)
	first := e.Process(minimalSecrets["klaviyo_pk"])
	second := e.Process(first.Output)
	if len(second.Findings) != 0 || second.Output != first.Output {
		t.Errorf("partial klaviyo remask: findings=%v output=%q first=%q", second.Findings, second.Output, first.Output)
	}
}

func TestSecretsSurviveNFKCNormalization(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	token := minimalSecrets["stripe_sk"]
	input := "全角ＡＢＣ　" + token
	result := e.Process(input)
	want := "全角ABC [STRIPE_SK]"
	if result.Output != want {
		t.Errorf("Output = %q, want %q", result.Output, want)
	}
}

func TestAllowlistExcludesSecretToken(t *testing.T) {
	token := minimalSecrets["github_token"]
	cfg := DefaultConfig()
	cfg.EnabledPreset = "secrets"
	cfg.Allowlist.Literals = []string{token}
	e := NewEngine(cfg)
	findings := e.Detect("a " + token + " b")
	if len(findings) != 0 {
		t.Errorf("allowlisted token still detected: %v", findings)
	}
}

func TestSecretsTablesAreInternallyConsistent(t *testing.T) {
	secretIDs := map[string]bool{}
	priorities := map[int]string{}
	for _, r := range secretsRules {
		secretIDs[r.ID] = true
		if r.Group != 1 {
			t.Errorf("rule %s: Group = %d, want 1", r.ID, r.Group)
		}
		if r.Priority < 100 {
			t.Errorf("rule %s: Priority = %d, want >= 100", r.ID, r.Priority)
		}
		if other, ok := priorities[r.Priority]; ok {
			t.Errorf("priority %d used by both %s and %s", r.Priority, other, r.ID)
		}
		priorities[r.Priority] = r.ID
	}

	if len(presets["secrets"]) != len(secretIDs) {
		t.Errorf("presets[secrets] len = %d, want %d", len(presets["secrets"]), len(secretIDs))
	}
	for _, id := range presets["secrets"] {
		if !secretIDs[id] {
			t.Errorf("presets[secrets] has %q which is not a secrets rule", id)
		}
	}
	for id := range secretIDs {
		found := false
		for _, p := range presets["secrets"] {
			if p == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("secrets rule %q missing from presets[secrets]", id)
		}
	}

	jpStrict := map[string]bool{}
	for _, id := range presets["jp-strict"] {
		jpStrict[id] = true
	}
	allSet := map[string]bool{}
	for _, id := range presets["all"] {
		allSet[id] = true
	}
	for id := range jpStrict {
		if !allSet[id] {
			t.Errorf("presets[all] missing jp-strict id %q", id)
		}
	}
	for id := range secretIDs {
		if !allSet[id] {
			t.Errorf("presets[all] missing secrets id %q", id)
		}
	}

	if len(secretsPrefixes) != len(secretIDs) {
		t.Errorf("secretsPrefixes keys = %d, want %d", len(secretsPrefixes), len(secretIDs))
	}
	for id := range secretIDs {
		if _, ok := secretsPrefixes[id]; !ok {
			t.Errorf("secretsPrefixes missing %q", id)
		}
	}
	for id := range secretsPrefixes {
		if !secretIDs[id] {
			t.Errorf("secretsPrefixes has extra key %q", id)
		}
	}

	tokenByPrefix := map[string]string{}
	for _, v := range prefixVariants {
		for _, p := range secretsPrefixes[v.ruleID] {
			if len(v.token) > len(p) && v.token[:len(p)] == p {
				tokenByPrefix[v.ruleID+"\x00"+p] = v.token
			}
		}
	}
	for id, prefixes := range secretsPrefixes {
		var rule Rule
		for _, r := range secretsRules {
			if r.ID == id {
				rule = r
				break
			}
		}
		for _, p := range prefixes {
			token := tokenByPrefix[id+"\x00"+p]
			if token == "" {
				t.Errorf("no variant token for %s prefix %q", id, p)
				continue
			}
			locs := rule.Pattern.FindAllStringSubmatchIndex(token, -1)
			if len(locs) == 0 {
				t.Errorf("%s prefix %q: pattern did not match %q", id, p, token)
				continue
			}
			start, end := locs[0][2], locs[0][3]
			if start < 0 || token[start:end] != token {
				t.Errorf("%s prefix %q: group 1 = %q, want full token %q", id, p, token[start:end], token)
			}
		}
	}
}

func TestDisableDropsOneSecretRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnabledPreset = "secrets"
	cfg.Disabled = map[string]bool{"github_token": true}
	e := NewEngine(cfg)
	ghp := e.Detect("a " + minimalSecrets["github_token"] + " b")
	if len(ghp) != 0 {
		t.Errorf("disabled github_token still detected: %v", ghp)
	}
	stripe := e.Detect("a " + minimalSecrets["stripe_sk"] + " b")
	if len(stripe) != 1 || stripe[0].RuleID != "stripe_sk" {
		t.Errorf("stripe_sk should still be active, got %v", stripe)
	}
}

func TestStripePublishableKeyIsNotKlaviyo(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	token := "pk_live_" + "abcdefghijklmnopqrstuvwxyz0123"
	findings := e.Detect("a " + token + " b")
	for _, f := range findings {
		if f.RuleID == "klaviyo_pk" {
			t.Errorf("pk_live_ matched klaviyo_pk: %v", findings)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"ab", 1.0},
		{"abcd", 2.0},
	}
	for _, tt := range tests {
		got := shannonEntropy(tt.in)
		if math.Abs(got-tt.want) >= 1e-9 {
			t.Errorf("shannonEntropy(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestEntropyCutoffRejectsDegenerateBodies(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	if findings := e.Detect("pk_" + strings.Repeat("a", 30)); len(findings) != 0 {
		t.Errorf("degenerate klaviyo: want 0 findings, got %v", findings)
	}
	if findings := e.Detect("EAA" + strings.Repeat("ab", 15)); len(findings) != 0 {
		t.Errorf("degenerate meta: want 0 findings, got %v", findings)
	}
	if findings := e.Detect(minimalSecrets["klaviyo_pk"]); len(findings) != 1 {
		t.Errorf("real klaviyo: want 1 finding, got %v", findings)
	}
	if findings := e.Detect(minimalSecrets["meta_token"]); len(findings) != 1 {
		t.Errorf("real meta: want 1 finding, got %v", findings)
	}
}

func TestEntropyCutoffIsNotAppliedToOtherRules(t *testing.T) {
	e := newSecretsEngine(t, "secrets")
	token := "AKIA" + strings.Repeat("A", 16)
	findings := e.Detect(token)
	if len(findings) != 1 {
		t.Fatalf("degenerate AKIA: want 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].RuleID != "aws_access_key" {
		t.Errorf("RuleID = %q, want aws_access_key", findings[0].RuleID)
	}
}

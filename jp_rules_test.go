package main

import "testing"

func TestMyNumberCheckDigit(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123456789018", true},
		{"123456789012", false},
		{"000000000000", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := validMyNumber(tt.input)
			if got != tt.want {
				t.Errorf("validMyNumber(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectMyNumber(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnabledPreset = "jp-strict"
	e := NewEngine(cfg)

	findings := e.Detect("my number 123456789018 registered")
	found := false
	for _, f := range findings {
		if f.RuleID == "my_number" {
			found = true
		}
	}
	if !found {
		t.Errorf("valid my_number should be detected, findings: %v", findings)
	}
}

func TestDetectMyNumberRejectsInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnabledPreset = "jp-strict"
	e := NewEngine(cfg)

	findings := e.Detect("number 123456789012 here")
	for _, f := range findings {
		if f.RuleID == "my_number" {
			t.Errorf("invalid check digit should not be detected as my_number: %v", f)
		}
	}
}

func TestDetectBankAccount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnabledPreset = "jp-strict"
	e := NewEngine(cfg)

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"with account keyword", "口座番号 1234567 here", true},
		{"with bank keyword", "銀行 普通 1234567", true},
		{"no keyword", "value 1234567 here", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := e.Detect(tt.input)
			found := false
			for _, f := range findings {
				if f.RuleID == "bank_account" {
					found = true
				}
			}
			if found != tt.want {
				t.Errorf("bank_account detected=%v, want %v, findings: %v", found, tt.want, findings)
			}
		})
	}
}

func TestPresetJPStrict(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnabledPreset = "jp-strict"
	e := NewEngine(cfg)

	input := "tanaka@example.com my number 123456789018 口座 1234567"
	findings := e.Detect(input)

	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.RuleID] = true
	}
	for _, want := range []string{"email", "my_number", "bank_account"} {
		if !rules[want] {
			t.Errorf("preset jp-strict should detect %s, found rules: %v", want, rules)
		}
	}
}

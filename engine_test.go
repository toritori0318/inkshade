package main

import "testing"

func TestDetectEmail(t *testing.T) {
	e := NewEngine(DefaultConfig())
	findings := e.Detect("contact tanaka@example.com here")
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "email" {
		t.Errorf("rule = %q, want email", f.RuleID)
	}
	if f.Text != "tanaka@example.com" {
		t.Errorf("text = %q, want tanaka@example.com", f.Text)
	}
}

func TestDetectCreditCardWithLuhn(t *testing.T) {
	e := NewEngine(DefaultConfig())
	findings := e.Detect("card 4111111111111111")
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "credit_card" {
		t.Errorf("rule = %q, want credit_card", findings[0].RuleID)
	}
}

func TestDetectRejectsInvalidLuhn(t *testing.T) {
	e := NewEngine(DefaultConfig())
	findings := e.Detect("order 1234567890123456")
	for _, f := range findings {
		if f.RuleID == "credit_card" {
			t.Errorf("false positive: %q detected as credit_card", f.Text)
		}
	}
}

func TestDetectPhone(t *testing.T) {
	e := NewEngine(DefaultConfig())
	findings := e.Detect("call 090-1234-5678 now")
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "phone" {
		t.Errorf("rule = %q, want phone", findings[0].RuleID)
	}
}

func TestDetectMultiple(t *testing.T) {
	e := NewEngine(DefaultConfig())
	findings := e.Detect("user tanaka@example.com 090-1234-5678")
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %v", len(findings), findings)
	}
}

func TestMaskFromFindings(t *testing.T) {
	e := NewEngine(DefaultConfig())
	input := "contact tanaka@example.com here"
	findings := e.Detect(input)
	got := e.Apply(input, findings)
	want := "contact [EMAIL] here"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDisableRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Disabled = map[string]bool{"email": true}
	e := NewEngine(cfg)
	findings := e.Detect("tanaka@example.com 090-1234-5678")
	for _, f := range findings {
		if f.RuleID == "email" {
			t.Error("email rule should be disabled")
		}
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding (phone only), got %d", len(findings))
	}
}

func TestCustomReplacement(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Replacements = map[string]string{"email": "***@***.***"}
	e := NewEngine(cfg)
	input := "contact tanaka@example.com here"
	findings := e.Detect(input)
	got := e.Apply(input, findings)
	want := "contact ***@***.*** here"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProcessMaskMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeMask
	e := NewEngine(cfg)
	result := e.Process("user tanaka@example.com 090-1234-5678")
	if result.Output != "user [EMAIL] [PHONE]" {
		t.Errorf("got %q", result.Output)
	}
	if !result.HasPII {
		t.Error("HasPII should be true")
	}
}

func TestProcessDetectMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeDetect
	e := NewEngine(cfg)
	result := e.Process("tanaka@example.com")
	if !result.HasPII {
		t.Error("HasPII should be true")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(result.Findings))
	}
}

func TestProcessNoPII(t *testing.T) {
	e := NewEngine(DefaultConfig())
	result := e.Process("this text has no PII at all")
	if result.HasPII {
		t.Error("HasPII should be false")
	}
}

func TestFullwidthNormalization(t *testing.T) {
	e := NewEngine(DefaultConfig())
	findings := e.Detect("phone ０９０−１２３４−５６７８ here")
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "phone" {
		t.Errorf("rule = %q, want phone", findings[0].RuleID)
	}
}

func TestBackwardCompatMask(t *testing.T) {
	e := NewEngine(DefaultConfig())
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"email", "contact tanaka@example.com here", "contact [EMAIL] here"},
		{"phone", "call 090-1234-5678 now", "call [PHONE] now"},
		{"credit card", "card 4111-1111-1111-1111", "card [CREDIT_CARD]"},
		{"ip", "from 192.168.1.100 access", "from [IP_ADDR] access"},
		{"postal prefix", "〒150-0002 area", "〒[POSTAL] area"},
		{"no pii", "this text has no PII at all", "this text has no PII at all"},
		{"mixed", "user tanaka@example.com 090-1234-5678", "user [EMAIL] [PHONE]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.Process(tt.input)
			if result.Output != tt.want {
				t.Errorf("got %q, want %q", result.Output, tt.want)
			}
		})
	}
}

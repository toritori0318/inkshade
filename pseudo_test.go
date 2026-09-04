package main

import (
	"strings"
	"testing"
)

func TestPseudonymizeEmailDeterministic(t *testing.T) {
	a := pseudonymize("email", "tanaka@example.com")
	b := pseudonymize("email", "tanaka@example.com")
	if a != b {
		t.Errorf("same input should produce same output: %q vs %q", a, b)
	}
}

func TestPseudonymizeEmailUnique(t *testing.T) {
	a := pseudonymize("email", "tanaka@example.com")
	b := pseudonymize("email", "suzuki@example.com")
	if a == b {
		t.Errorf("different inputs should produce different outputs: both %q", a)
	}
}

func TestPseudonymizeEmailFormat(t *testing.T) {
	result := pseudonymize("email", "tanaka@example.com")
	if !strings.Contains(result, "@") {
		t.Errorf("pseudonymized email should contain @: %q", result)
	}
}

func TestPseudonymizeCreditCard(t *testing.T) {
	a := pseudonymize("credit_card", "4111111111111111")
	b := pseudonymize("credit_card", "4111111111111111")
	if a != b {
		t.Errorf("same input should produce same output: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "****-****-") {
		t.Errorf("should have masked prefix: %q", a)
	}
}

func TestPseudonymizePhone(t *testing.T) {
	a := pseudonymize("phone", "090-1234-5678")
	b := pseudonymize("phone", "090-1234-5678")
	if a != b {
		t.Errorf("same input should produce same output: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "***-") {
		t.Errorf("should have masked prefix: %q", a)
	}
}

func TestProcessPseudoMaskStyle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaskStyle = MaskStylePseudo
	e := NewEngine(cfg)
	result := e.Process("contact tanaka@example.com and 090-1234-5678")

	if strings.Contains(result.Output, "tanaka@example.com") {
		t.Error("original email should be replaced")
	}
	if strings.Contains(result.Output, "090-1234-5678") {
		t.Error("original phone should be replaced")
	}
	if !strings.Contains(result.Output, "@masked.example") {
		t.Errorf("should contain pseudonymized email: %q", result.Output)
	}
	if strings.Contains(result.Output, "[PHONE]") || strings.Contains(result.Output, "[CREDIT_CARD]") {
		t.Errorf("should not contain label masks in pseudo mode: %q", result.Output)
	}

	result2 := e.Process("contact tanaka@example.com and 090-1234-5678")
	if result.Output != result2.Output {
		t.Errorf("pseudonymize should be deterministic: %q vs %q", result.Output, result2.Output)
	}
}

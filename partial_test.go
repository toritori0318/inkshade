package main

import (
	"strings"
	"testing"
)

func TestPartialMaskEmail(t *testing.T) {
	got := partialMaskEmail("tanaka@example.com")
	want := "t*****@e******.com"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPartialMaskEmailShort(t *testing.T) {
	got := partialMaskEmail("a@b.co")
	want := "a@b.co"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPartialMaskCreditCard(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"4111111111111111", "************1111"},
		{"4111-1111-1111-1111", "****-****-****-1111"},
		{"4111 1111 1111 1111", "**** **** **** 1111"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := partialMaskCreditCard(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPartialMaskPhone(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"090-1234-5678", "***-****-5678"},
		{"09012345678", "*******5678"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := partialMaskPhone(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPartialMaskGeneric(t *testing.T) {
	got := partialMaskGeneric("192.168.1.100", 0)
	want := "*************"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProcessPartialMaskStyle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaskStyle = MaskStylePartial
	e := NewEngine(cfg)
	result := e.Process("tanaka@example.com 4111111111111111 090-1234-5678")
	want := "t*****@e******.com ************1111 ***-****-5678"
	if result.Output != want {
		t.Errorf("got %q, want %q", result.Output, want)
	}
}

func TestDryRunDiff(t *testing.T) {
	original := "tanaka@example.com 090-1234-5678"
	masked := "[EMAIL] [PHONE]"
	diff := formatDryRunDiff(original, masked, 1)
	if diff == "" {
		t.Error("diff should not be empty")
	}
	if !strings.Contains(diff, "-tanaka@example.com") {
		t.Errorf("diff should contain original line, got: %s", diff)
	}
	if !strings.Contains(diff, "+[EMAIL]") {
		t.Errorf("diff should contain masked line, got: %s", diff)
	}
}

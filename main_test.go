package main

import (
	"strings"
	"testing"
)

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

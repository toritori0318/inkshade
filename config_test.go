package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
mode: detect
rules:
  email:
    enabled: true
    replace: "***@***.***"
  ip_addr:
    enabled: false
  phone:
    replace: "[TEL]"
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeDetect {
		t.Errorf("mode = %q, want detect", cfg.Mode)
	}
	if cfg.Replacements["email"] != "***@***.***" {
		t.Errorf("email replacement = %q", cfg.Replacements["email"])
	}
	if cfg.Replacements["phone"] != "[TEL]" {
		t.Errorf("phone replacement = %q", cfg.Replacements["phone"])
	}
	if !cfg.Disabled["ip_addr"] {
		t.Error("ip_addr should be disabled")
	}
}

func TestLoadConfigAllowlistLiteral(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
allowlist:
  literals:
    - "test@example.com"
    - "192.168.1.1"
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(cfg)
	findings := e.Detect("contact test@example.com for info")
	if len(findings) != 0 {
		t.Errorf("allowlisted email should not be detected, got %v", findings)
	}

	findings = e.Detect("contact other@example.com for info")
	if len(findings) != 1 {
		t.Errorf("non-allowlisted email should be detected, got %d findings", len(findings))
	}
}

func TestLoadConfigAllowlistPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
allowlist:
  patterns:
    - '.*@example\.com'
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(cfg)
	findings := e.Detect("test@example.com and admin@example.com")
	if len(findings) != 0 {
		t.Errorf("allowlisted pattern should exclude all example.com emails, got %v", findings)
	}

	findings = e.Detect("secret@corp.io")
	if len(findings) != 1 {
		t.Errorf("non-matching email should be detected, got %d findings", len(findings))
	}
}

func TestAllowlistInEngine(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Allowlist = Allowlist{
		Literals: []string{"test@example.com"},
	}
	e := NewEngine(cfg)
	findings := e.Detect("contact test@example.com here")
	if len(findings) != 0 {
		t.Errorf("allowlisted email should not be detected, got %v", findings)
	}
	findings = e.Detect("contact other@corp.io here")
	if len(findings) != 1 {
		t.Errorf("non-allowlisted email should be detected, got %d", len(findings))
	}
}

func TestLoadConfigMissing(t *testing.T) {
	_, err := LoadConfig("/nonexistent/inkshade.yaml")
	if err == nil {
		t.Error("expected error for missing config file")
	}
}

func TestLoadConfigMaskStyle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
mask_style: partial
preset: jp-strict
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaskStyle != MaskStylePartial {
		t.Errorf("mask_style = %q, want partial", cfg.MaskStyle)
	}
	if cfg.EnabledPreset != "jp-strict" {
		t.Errorf("preset = %q, want jp-strict", cfg.EnabledPreset)
	}
}

func TestLoadConfigInvalidAllowlistPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
allowlist:
  patterns:
    - '[invalid'
`), 0644)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid allowlist regex")
	}
}

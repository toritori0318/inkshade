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

func TestCustomRuleReplacesMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
custom_rules:
  - id: widget_token
    name: Widget Token
    pattern: 'WIDGET-[0-9A-Za-z]{8}'
    replace: "[WIDGET_TOKEN]"
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	result := NewEngine(cfg).Process("id WIDGET-abcdefgh end")
	if result.Output != "id [WIDGET_TOKEN] end" {
		t.Errorf("Output = %q", result.Output)
	}
}

func TestCustomRuleGroupReplacesOnlyTheGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
custom_rules:
  - id: widget_token
    name: Widget Token
    pattern: 'widget_token=([0-9A-Za-z]{8,})'
    group: 1
    replace: "[WIDGET_TOKEN]"
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	result := NewEngine(cfg).Process("widget_token=abcdefgh&x=1")
	if result.Output != "widget_token=[WIDGET_TOKEN]&x=1" {
		t.Errorf("Output = %q", result.Output)
	}
}

func TestCustomRuleInvalidPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
custom_rules:
  - id: widget_token
    name: Widget Token
    pattern: '[invalid'
    replace: "[WIDGET_TOKEN]"
`), 0644)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid custom rule pattern")
	}
}

func TestCustomRuleRejectsEmptyReplace(t *testing.T) {
	cases := []string{
		"replace: \"\"",
		"# replace omitted",
	}
	for _, replaceLine := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "inkshade.yaml")
		os.WriteFile(path, []byte(`
custom_rules:
  - id: widget_token
    name: Widget Token
    pattern: 'WIDGET-[0-9A-Za-z]{8}'
    `+replaceLine+`
`), 0644)

		_, err := LoadConfig(path)
		if err == nil {
			t.Errorf("expected error when replace is %q", replaceLine)
		}
	}
}

func TestCustomRuleRejectsBuiltInID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
custom_rules:
  - id: email
    name: Email
    pattern: 'widget_token=[0-9A-Za-z]+'
    replace: "[WIDGET_TOKEN]"
`), 0644)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error when custom rule id matches a built-in rule")
	}
}

func TestCustomRuleRejectsGroupOutOfRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
custom_rules:
  - id: widget_token
    name: Widget Token
    pattern: '(abc)'
    group: 2
    replace: "[WIDGET_TOKEN]"
`), 0644)

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error when group is out of range")
	}
}

func TestDisableDropsCustomRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
custom_rules:
  - id: widget_token
    name: Widget Token
    pattern: 'widget_token=([0-9A-Za-z]{8,})'
    group: 1
    replace: "[WIDGET_TOKEN]"
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Disabled["widget_token"] = true
	result := NewEngine(cfg).Process("widget_token=abcdefgh")
	if result.Output != "widget_token=abcdefgh" {
		t.Errorf("Output = %q", result.Output)
	}
}

func TestCustomRuleStaysOnUnderSecretsPreset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inkshade.yaml")
	os.WriteFile(path, []byte(`
preset: secrets
custom_rules:
  - id: widget_token
    name: Widget Token
    pattern: 'widget_token=([0-9A-Za-z]{8,})'
    group: 1
    replace: "[WIDGET_TOKEN]"
`), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	result := NewEngine(cfg).Process("tanaka@example.com widget_token=abcdefgh")
	want := "tanaka@example.com widget_token=[WIDGET_TOKEN]"
	if result.Output != want {
		t.Errorf("Output = %q, want %q", result.Output, want)
	}
}

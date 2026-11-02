package main

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Allowlist struct {
	Literals []string `yaml:"literals"`
	Patterns []string `yaml:"patterns"`

	compiledPatterns []*regexp.Regexp
}

func (a *Allowlist) compile() error {
	for _, p := range a.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("invalid allowlist pattern %q: %w", p, err)
		}
		a.compiledPatterns = append(a.compiledPatterns, re)
	}
	return nil
}

func (a *Allowlist) IsAllowed(s string) bool {
	for _, lit := range a.Literals {
		if s == lit {
			return true
		}
	}
	for _, re := range a.compiledPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

type yamlRuleConfig struct {
	Enabled *bool  `yaml:"enabled"`
	Replace string `yaml:"replace"`
}

type yamlCustomRule struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Group   int    `yaml:"group"`
	Replace string `yaml:"replace"`
}

type yamlConfig struct {
	Mode        string                    `yaml:"mode"`
	MaskStyle   string                    `yaml:"mask_style"`
	Preset      string                    `yaml:"preset"`
	Rules       map[string]yamlRuleConfig `yaml:"rules"`
	CustomRules []yamlCustomRule          `yaml:"custom_rules"`
	Allowlist   Allowlist                 `yaml:"allowlist"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var yc yamlConfig
	if err := yaml.Unmarshal(data, &yc); err != nil {
		return Config{}, err
	}

	cfg := DefaultConfig()

	if yc.Mode != "" {
		cfg.Mode = Mode(yc.Mode)
	}

	if yc.MaskStyle != "" {
		cfg.MaskStyle = MaskStyle(yc.MaskStyle)
	}

	if yc.Preset != "" {
		cfg.EnabledPreset = yc.Preset
	}

	for id, rc := range yc.Rules {
		if rc.Enabled != nil && !*rc.Enabled {
			cfg.Disabled[id] = true
		}
		if rc.Replace != "" {
			cfg.Replacements[id] = rc.Replace
		}
	}

	cfg.Allowlist = yc.Allowlist
	if err := cfg.Allowlist.compile(); err != nil {
		return Config{}, err
	}

	custom, err := compileCustomRules(yc.CustomRules)
	if err != nil {
		return Config{}, err
	}
	cfg.CustomRules = custom

	return cfg, nil
}

func compileCustomRules(list []yamlCustomRule) ([]Rule, error) {
	builtin := map[string]bool{}
	for _, r := range allRulesWithSecrets() {
		builtin[r.ID] = true
	}
	seen := map[string]bool{}
	out := make([]Rule, 0, len(list))
	for i, rc := range list {
		if rc.ID == "" {
			return nil, fmt.Errorf("custom rule %d: id is required", i)
		}
		if builtin[rc.ID] {
			return nil, fmt.Errorf("custom rule %q: id matches a built-in rule", rc.ID)
		}
		if seen[rc.ID] {
			return nil, fmt.Errorf("custom rule %q: duplicate id", rc.ID)
		}
		if rc.Pattern == "" {
			return nil, fmt.Errorf("custom rule %q: pattern is required", rc.ID)
		}
		re, err := regexp.Compile(rc.Pattern)
		if err != nil {
			return nil, fmt.Errorf("custom rule %q: invalid pattern: %w", rc.ID, err)
		}
		if rc.Group < 0 || rc.Group > re.NumSubexp() {
			return nil, fmt.Errorf("custom rule %q: group %d is out of range", rc.ID, rc.Group)
		}
		if rc.Replace == "" {
			return nil, fmt.Errorf("custom rule %q: replace is required", rc.ID)
		}
		name := rc.Name
		if name == "" {
			name = rc.ID
		}
		seen[rc.ID] = true
		out = append(out, Rule{
			ID:       rc.ID,
			Name:     name,
			Pattern:  re,
			Replace:  rc.Replace,
			Priority: 1000 + i,
			Group:    rc.Group,
		})
	}
	return out, nil
}

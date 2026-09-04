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

type yamlConfig struct {
	Mode      string                    `yaml:"mode"`
	MaskStyle string                    `yaml:"mask_style"`
	Preset    string                    `yaml:"preset"`
	Rules     map[string]yamlRuleConfig `yaml:"rules"`
	Allowlist Allowlist                 `yaml:"allowlist"`
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

	return cfg, nil
}

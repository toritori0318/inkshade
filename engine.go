package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/nyaruka/phonenumbers"
	"golang.org/x/text/unicode/norm"
)

type Mode string

const (
	ModeMask     Mode = "mask"
	ModeDetect   Mode = "detect"
	ModeDiagnose Mode = "diagnose"
)

type Config struct {
	Mode          Mode
	MaskStyle     MaskStyle
	Disabled      map[string]bool
	Replacements  map[string]string
	Allowlist     Allowlist
	EnabledPreset string
}

func DefaultConfig() Config {
	return Config{
		Mode:         ModeMask,
		MaskStyle:    MaskStyleLabel,
		Disabled:     map[string]bool{},
		Replacements: map[string]string{},
	}
}

type Rule struct {
	ID       string
	Name     string
	Pattern  *regexp.Regexp
	Replace  string
	Validate func(string) bool
	Priority int
}

type Finding struct {
	RuleID  string `json:"rule_id"`
	Name    string `json:"name"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Text    string `json:"text"`
	Replace string `json:"replace"`
}

type Result struct {
	Input    string
	Output   string
	Findings []Finding
	HasPII   bool
}

type Engine struct {
	rules         []Rule
	config        Config
	ctxValidators map[string]func(line string) func(string) bool
}

func luhnValid(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		n := int(s[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func validIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return addr.Is4()
}

func validPhone(s string) bool {
	num, err := phonenumbers.Parse(s, "JP")
	if err != nil {
		return false
	}
	return phonenumbers.IsValidNumberForRegion(num, "JP")
}

var defaultRules = []Rule{
	{
		ID: "email", Name: "Email Address", Priority: 10,
		Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		Replace: "[EMAIL]",
	},
	{
		ID: "credit_card", Name: "Credit Card (separated)", Priority: 20,
		Pattern: regexp.MustCompile(`\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}`),
		Replace: "[CREDIT_CARD]",
		Validate: func(s string) bool {
			digits := strings.NewReplacer(" ", "", "-", "").Replace(s)
			return luhnValid(digits)
		},
	},
	{
		ID: "credit_card", Name: "Credit Card (continuous)", Priority: 21,
		Pattern: regexp.MustCompile(`\b\d{13,16}\b`),
		Replace: "[CREDIT_CARD]",
		Validate: func(s string) bool {
			return luhnValid(s)
		},
	},
	{
		ID: "phone", Name: "Phone Number (JP)", Priority: 30,
		Pattern:  regexp.MustCompile(`\+?\d[\d\-\(\)\s]{8,15}\d`),
		Replace:  "[PHONE]",
		Validate: validPhone,
	},
	{
		ID: "postal", Name: "Postal Code (〒)", Priority: 40,
		Pattern: regexp.MustCompile(`〒\d{3}-?\d{4}`),
		Replace: "〒[POSTAL]",
	},
	{
		ID: "postal", Name: "Postal Code", Priority: 41,
		Pattern: regexp.MustCompile(`\b\d{3}-\d{4}\b`),
		Replace: "[POSTAL]",
	},
	{
		ID: "ip_addr", Name: "IPv4 Address", Priority: 50,
		Pattern:  regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`),
		Replace:  "[IP_ADDR]",
		Validate: validIP,
	},
}

var hyphenReplacer = strings.NewReplacer(
	"−", "-",
	"–", "-",
	"—", "-",
)

func normalize(s string) string {
	s = norm.NFKC.String(s)
	s = hyphenReplacer.Replace(s)
	return s
}

func ValidatePreset(preset string) error {
	if preset == "" {
		return nil
	}
	if _, ok := presets[preset]; !ok {
		validPresets := make([]string, 0, len(presets))
		for k := range presets {
			validPresets = append(validPresets, k)
		}
		return fmt.Errorf("unknown preset %q (valid: %v)", preset, validPresets)
	}
	return nil
}

func NewEngine(cfg Config) *Engine {
	sourceRules := allRulesWithJP()

	var rules []Rule
	for _, r := range sourceRules {
		if cfg.Disabled[r.ID] {
			continue
		}
		if cfg.EnabledPreset != "" {
			if !isRuleInPreset(cfg.EnabledPreset, r.ID) {
				continue
			}
		} else {
			isJPExtra := false
			for _, jp := range jpExtraRules {
				if r.ID == jp.ID {
					isJPExtra = true
					break
				}
			}
			if isJPExtra {
				continue
			}
		}
		if repl, ok := cfg.Replacements[r.ID]; ok {
			r.Replace = repl
		}
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
	return &Engine{rules: rules, config: cfg, ctxValidators: contextualValidators()}
}

func (e *Engine) Detect(s string) []Finding {
	s = normalize(s)
	var candidates []Finding

	for _, rule := range e.rules {
		validator := contextualDetect(rule, s, e.ctxValidators)

		locs := rule.Pattern.FindAllStringIndex(s, -1)
		for _, loc := range locs {
			matched := s[loc[0]:loc[1]]
			if validator != nil && !validator(matched) {
				continue
			}
			if e.config.Allowlist.IsAllowed(matched) {
				continue
			}
			candidates = append(candidates, Finding{
				RuleID:  rule.ID,
				Name:    rule.Name,
				Start:   loc[0],
				End:     loc[1],
				Text:    matched,
				Replace: rule.Replace,
			})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Start != candidates[j].Start {
			return candidates[i].Start < candidates[j].Start
		}
		return (candidates[i].End - candidates[i].Start) > (candidates[j].End - candidates[j].Start)
	})

	var resolved []Finding
	lastEnd := 0
	for _, f := range candidates {
		if f.Start >= lastEnd {
			resolved = append(resolved, f)
			lastEnd = f.End
		}
	}

	return resolved
}

func (e *Engine) Apply(original string, findings []Finding) string {
	s := normalize(original)
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		var repl string
		if e.config.MaskStyle == MaskStylePartial {
			repl = applyPartialMask(f.RuleID, f.Text)
		} else if e.config.MaskStyle == MaskStylePseudo {
			repl = pseudonymize(f.RuleID, f.Text)
		} else {
			repl = f.Replace
		}
		s = s[:f.Start] + repl + s[f.End:]
	}
	return s
}

func (e *Engine) Process(input string) Result {
	normalized := normalize(input)
	findings := e.Detect(input)
	result := Result{
		Input:    normalized,
		Findings: findings,
		HasPII:   len(findings) > 0,
	}
	if e.config.Mode == ModeMask {
		result.Output = e.Apply(input, findings)
	} else {
		result.Output = normalized
	}
	return result
}

package main

import "regexp"

func validMyNumber(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}

	// MOD 11 check digit: position n from right, q = n+1 (1<=n<=6) or n-5 (7<=n<=11)
	sum := 0
	for i := 0; i < 11; i++ {
		digit := int(s[i] - '0')
		pos := 11 - i // position from right (1-based, excluding check digit)
		var q int
		if pos <= 6 {
			q = pos + 1
		} else {
			q = pos - 5
		}
		sum += digit * q
	}

	remainder := sum % 11
	var expected int
	if remainder <= 1 {
		expected = 0
	} else {
		expected = 11 - remainder
	}

	checkDigit := int(s[11] - '0')
	return checkDigit == expected
}

var bankKeywords = regexp.MustCompile(`(?:銀行|口座|普通|当座|支店|振込|預金)`)

var jpExtraRules = []Rule{
	{
		ID: "my_number", Name: "My Number (JP)", Priority: 25,
		Pattern:  regexp.MustCompile(`\b\d{12}\b`),
		Replace:  "[MY_NUMBER]",
		Validate: validMyNumber,
	},
	{
		ID: "bank_account", Name: "Bank Account (JP)", Priority: 55,
		Pattern: regexp.MustCompile(`\b\d{7}\b`),
		Replace: "[BANK_ACCOUNT]",
		// Validate is set dynamically per line via contextual validation
	},
}

var presets = map[string][]string{
	"jp-strict": {"email", "credit_card", "phone", "postal", "ip_addr", "my_number", "bank_account"},
}

func isRuleInPreset(preset string, ruleID string) bool {
	ids, ok := presets[preset]
	if !ok {
		return false
	}
	for _, id := range ids {
		if id == ruleID {
			return true
		}
	}
	return false
}

func allRulesWithJP() []Rule {
	all := make([]Rule, len(defaultRules))
	copy(all, defaultRules)
	all = append(all, jpExtraRules...)
	return all
}

func contextualValidators() map[string]func(line string) func(string) bool {
	return map[string]func(line string) func(string) bool{
		"bank_account": func(line string) func(string) bool {
			hasKeyword := bankKeywords.MatchString(line)
			return func(s string) bool {
				if len(s) != 7 {
					return false
				}
				return hasKeyword
			}
		},
	}
}

// contextualDetect returns the validator for a rule, using line-level context when available.
func contextualDetect(rule Rule, line string, ctxValidators map[string]func(line string) func(string) bool) func(string) bool {
	if cv, ok := ctxValidators[rule.ID]; ok {
		return cv(line)
	}
	return rule.Validate
}


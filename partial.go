package main

import (
	"fmt"
	"strings"
)

type MaskStyle string

const (
	MaskStyleLabel   MaskStyle = "label"
	MaskStylePartial MaskStyle = "partial"
)

func partialMaskEmail(s string) string {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return strings.Repeat("*", len([]rune(s)))
	}
	local := s[:at]
	domain := s[at+1:]

	dot := strings.LastIndex(domain, ".")
	if dot < 0 {
		return strings.Repeat("*", len([]rune(s)))
	}
	domainName := domain[:dot]
	tld := domain[dot:]

	maskedLocal := maskKeepFirst(local, 1)
	maskedDomain := maskKeepFirst(domainName, 1)

	return maskedLocal + "@" + maskedDomain + tld
}

func partialMaskDigits(s string, keepLast int) string {
	runes := []rune(s)
	digitCount := 0
	for _, r := range runes {
		if r >= '0' && r <= '9' {
			digitCount++
		}
	}

	maskedDigits := digitCount - keepLast
	if maskedDigits < 0 {
		maskedDigits = 0
	}
	result := make([]rune, len(runes))
	digitIdx := 0
	for i, r := range runes {
		if r >= '0' && r <= '9' {
			if digitIdx < maskedDigits {
				result[i] = '*'
			} else {
				result[i] = r
			}
			digitIdx++
		} else {
			result[i] = r
		}
	}
	return string(result)
}

func partialMaskCreditCard(s string) string {
	return partialMaskDigits(s, 4)
}

func partialMaskPhone(s string) string {
	return partialMaskDigits(s, 4)
}

func partialMaskGeneric(s string, keepLast int) string {
	runes := []rune(s)
	if len(runes) <= keepLast {
		return s
	}
	return strings.Repeat("*", len(runes)-keepLast) + string(runes[len(runes)-keepLast:])
}

func maskKeepFirst(s string, keep int) string {
	runes := []rune(s)
	if len(runes) <= keep {
		return s
	}
	return string(runes[:keep]) + strings.Repeat("*", len(runes)-keep)
}

var partialMaskFuncs = map[string]func(string) string{
	"email":       partialMaskEmail,
	"credit_card": partialMaskCreditCard,
	"phone":       partialMaskPhone,
}

func applyPartialMask(ruleID, text string) string {
	if fn, ok := partialMaskFuncs[ruleID]; ok {
		return fn(text)
	}
	return partialMaskGeneric(text, 0)
}

func formatDryRunDiff(original, masked string, lineNum int) string {
	if original == masked {
		return ""
	}
	return fmt.Sprintf("@@ line %d @@\n-%s\n+%s", lineNum, original, masked)
}

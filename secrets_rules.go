package main

// secretsRules is filled in by the credential-rule commit. The engine
// consults this slice so Group-based spans and default-preset exclusion
// have a single source of extra rule IDs.
var secretsRules []Rule

func allRulesWithSecrets() []Rule {
	return append(allRulesWithJP(), secretsRules...)
}

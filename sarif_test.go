package main

import (
	"encoding/json"
	"testing"
)

func TestSarifOutputSchema(t *testing.T) {
	findings := []Finding{
		{RuleID: "email", Name: "Email Address", Start: 8, End: 26, Text: "tanaka@example.com", Replace: "[EMAIL]"},
	}
	data := buildSarif("test.txt", map[int]lineData{1: {Findings: findings, Text: "contact tanaka@example.com here"}})
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}

	if result["$schema"] == nil {
		t.Error("SARIF output should have $schema")
	}
	if result["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", result["version"])
	}

	runs := result["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}

	r := results[0].(map[string]any)
	if r["ruleId"] != "email" {
		t.Errorf("ruleId = %v, want email", r["ruleId"])
	}
}

func TestSarifOutputMultipleFindings(t *testing.T) {
	lines := map[int]lineData{
		1: {
			Findings: []Finding{
				{RuleID: "email", Name: "Email Address", Start: 0, End: 18, Text: "tanaka@example.com", Replace: "[EMAIL]"},
			},
			Text: "tanaka@example.com",
		},
		3: {
			Findings: []Finding{
				{RuleID: "phone", Name: "Phone Number (JP)", Start: 5, End: 18, Text: "090-1234-5678", Replace: "[PHONE]"},
				{RuleID: "ip_addr", Name: "IPv4 Address", Start: 20, End: 33, Text: "192.168.1.100", Replace: "[IP_ADDR]"},
			},
			Text: "call 090-1234-5678 192.168.1.100 here",
		},
	}
	data := buildSarif("app.log", lines)
	b, _ := json.Marshal(data)

	var result map[string]any
	json.Unmarshal(b, &result)

	runs := result["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}
}

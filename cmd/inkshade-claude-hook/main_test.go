package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

func decode(t *testing.T, out []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output is not JSON: %v: %s", err, out)
	}
	return m
}

func TestUserPromptSubmitPrintsNothingWhenClean(t *testing.T) {
	out, code := run([]byte(`{"hook_event_name":"UserPromptSubmit","prompt":"hello"}`), "stop")
	if code != 0 || len(out) != 0 {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestUserPromptSubmitBlocksAndShowsOnlyMaskedText(t *testing.T) {
	out, code := run([]byte(`{"hook_event_name":"UserPromptSubmit","prompt":"token `+secret+` here"}`), "stop")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if strings.Contains(string(out), secret) {
		t.Fatalf("raw secret leaked: %s", out)
	}
	m := decode(t, out)
	if m["decision"] != "block" {
		t.Fatalf("decision=%v", m["decision"])
	}
	if !strings.Contains(m["reason"].(string), "token [GITHUB_TOKEN] here") {
		t.Fatalf("reason=%v", m["reason"])
	}
	hso := m["hookSpecificOutput"].(map[string]any)
	if hso["suppressOriginalPrompt"] != true {
		t.Fatalf("hookSpecificOutput=%v", hso)
	}
}

func postToolUse(resp string) []byte {
	return []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":` + resp + `}`)
}

func TestPostToolUsePrintsNothingWhenClean(t *testing.T) {
	out, code := run(postToolUse(`{"stdout":"ok","stderr":"","interrupted":false,"isImage":false}`), "mask")
	if code != 0 || len(out) != 0 {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestPostToolUseMaskKeepsOutputShape(t *testing.T) {
	out, _ := run(postToolUse(`{"stdout":"token `+secret+`\nnext","stderr":"","interrupted":false,"isImage":false}`), "mask")
	if strings.Contains(string(out), secret) {
		t.Fatalf("raw secret leaked: %s", out)
	}
	m := decode(t, out)
	if _, ok := m["continue"]; ok {
		t.Fatalf("mask mode must not stop: %v", m)
	}
	hso := m["hookSpecificOutput"].(map[string]any)
	got := hso["updatedToolOutput"].(map[string]any)
	want := map[string]any{"stdout": "token [GITHUB_TOKEN]\nnext", "stderr": "", "interrupted": false, "isImage": false}
	if mustJSONString(got) != mustJSONString(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func mustJSONString(v any) string { return string(mustJSON(v)) }

func TestPostToolUseMasksNestedStringsAndKeepsNumbers(t *testing.T) {
	in := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"type":"text","file":{"filePath":"/a","content":"mail tanaka@example.com","numLines":1}}}`)
	out, _ := run(in, "mask")
	got := decode(t, out)["hookSpecificOutput"].(map[string]any)["updatedToolOutput"]
	want := `{"file":{"content":"mail [EMAIL]","filePath":"/a","numLines":1},"type":"text"}`
	if mustJSONString(got) != want {
		t.Fatalf("got %s", mustJSONString(got))
	}
}

func TestPostToolUseStopAlsoMasksOutput(t *testing.T) {
	out, _ := run(postToolUse(`{"stdout":"`+secret+`","stderr":"","interrupted":false,"isImage":false}`), "stop")
	if strings.Contains(string(out), secret) {
		t.Fatalf("raw secret leaked: %s", out)
	}
	m := decode(t, out)
	if m["continue"] != false || m["stopReason"] == nil {
		t.Fatalf("not stopped: %v", m)
	}
	got := m["hookSpecificOutput"].(map[string]any)["updatedToolOutput"].(map[string]any)
	if got["stdout"] != "[GITHUB_TOKEN]" {
		t.Fatalf("got %v", got)
	}
}

func TestRunExits2OnInvalidInput(t *testing.T) {
	if _, code := run([]byte(`{`), "stop"); code != 2 {
		t.Fatalf("code=%d", code)
	}
}

func TestRunIgnoresOtherEvents(t *testing.T) {
	out, code := run([]byte(`{"hook_event_name":"Stop","prompt":"`+secret+`"}`), "stop")
	if code != 0 || len(out) != 0 {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

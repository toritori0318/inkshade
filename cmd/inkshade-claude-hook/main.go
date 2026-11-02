package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/toritori0318/inkshade/pkg/inkshade"
)

var engine = inkshade.NewEngine(inkshade.DefaultConfig())

type hookInput struct {
	HookEventName string `json:"hook_event_name"`
	Prompt        string `json:"prompt"`
	ToolResponse  any    `json:"tool_response"`
	Error         any    `json:"error"`
	ToolCalls     any    `json:"tool_calls"`
}

func run(in []byte, action string) ([]byte, int) {
	var h hookInput
	d := json.NewDecoder(bytes.NewReader(in))
	d.UseNumber() // keep numeric fields byte-for-byte when echoing the output back
	if err := d.Decode(&h); err != nil {
		return nil, 2
	}
	switch h.HookEventName {
	case "UserPromptSubmit":
		r := engine.Process(h.Prompt)
		if !r.HasFindings {
			return nil, 0
		}
		// The prompt can't be rewritten by a hook, so show the masked text for the user to resend.
		return mustJSON(map[string]any{
			"decision": "block",
			"reason":   "inkshade: blocked the prompt because it contains sensitive data. Masked text:\n" + r.Output,
			"hookSpecificOutput": map[string]any{
				"hookEventName":          "UserPromptSubmit",
				"suppressOriginalPrompt": true,
			},
		}), 0
	case "PostToolUse":
		// Built-in tools ignore an updatedToolOutput whose shape differs, sending the original instead,
		// so mask string leaves in place rather than replacing the whole output.
		masked, found := mask(h.ToolResponse)
		if !found {
			return nil, 0
		}
		// Even when stopping, the masked output goes back: the tool result stays in the
		// transcript and would be sent with the next request.
		out := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":     "PostToolUse",
				"updatedToolOutput": masked,
			},
		}
		if action != "mask" {
			out["continue"] = false
			out["stopReason"] = "inkshade: stopped because the tool output contains sensitive data (Claude only receives the masked output)"
		}
		return mustJSON(out), 0
	case "PostToolUseFailure":
		// No updatedToolOutput on this event. continue:false is not enough on its
		// own: Claude Code 2.1.312 still makes the model call. PostToolBatch, which
		// runs after this and sees the same error text, is what stops that call.
		if _, found := mask(h.Error); !found {
			return nil, 0
		}
		return mustJSON(map[string]any{
			"continue":   false,
			"stopReason": "inkshade: stopped because a failed tool result contains sensitive data (the error text cannot be masked and remains in the transcript)",
		}), 0
	case "PostToolBatch":
		// tool_calls is the text about to be sent. Successful results were already
		// masked by PostToolUse, so a clean batch passes through. A failed command's
		// output cannot be masked and still shows up here.
		if _, found := mask(h.ToolCalls); !found {
			return nil, 0
		}
		return mustJSON(map[string]any{
			"decision":   "block",
			"reason":     "inkshade: stopped because a tool result still contains sensitive data",
			"continue":   false,
			"stopReason": "inkshade: stopped because a tool result still contains sensitive data (a failed command's output cannot be masked and remains in the transcript)",
		}), 0
	}
	return nil, 0
}

func mask(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		r := engine.Process(x)
		if !r.HasFindings {
			return x, false
		}
		return r.Output, true
	case map[string]any:
		found := false
		for k, e := range x {
			var f bool
			x[k], f = mask(e)
			found = found || f
		}
		return x, found
	case []any:
		found := false
		for i, e := range x {
			var f bool
			x[i], f = mask(e)
			found = found || f
		}
		return x, found
	}
	return v, false
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	out, code := run(in, os.Getenv("CLAUDE_PLUGIN_OPTION_ACTION"))
	if code == 2 {
		fmt.Fprintln(os.Stderr, "inkshade-claude-hook: blocked because the hook input could not be parsed")
	}
	os.Stdout.Write(out)
	os.Exit(code)
}

# inkshade-claude-hook

A [Claude Code](https://code.claude.com/docs/en/hooks) plugin that runs inkshade on what Claude Code sends to the model.

| Hook event | What it does |
|---|---|
| `UserPromptSubmit` | Blocks a prompt that contains sensitive data and shows the masked text so you can resend it. Hooks can't rewrite a prompt. |
| `PostToolUse` | Masks sensitive data in a successful tool result (Bash, Read, MCP tools, ...) before Claude sees it. By default it also stops Claude. |
| `PostToolUseFailure` | A failed tool result cannot be rewritten. `PostToolBatch` stops the model call when that text contains sensitive data. |
| `PostToolBatch` | Stops the next model call when a tool result still contains sensitive data. If this hook cannot start, that call is blocked too. |

## Install

1. Install the binary. The Homebrew formula ships it with `inkshade`:

   ```bash
   brew install inkshade
   ```

   Or with Go: `go install github.com/toritori0318/inkshade/cmd/inkshade-claude-hook@latest`

2. Install the plugin in Claude Code:

   ```
   /plugin marketplace add toritori0318/inkshade
   /plugin install inkshade@inkshade
   ```

Choose `stop` (default) or `mask` for a successful tool result in `/config`. `mask` keeps Claude running with that result masked. A failed tool result that still contains sensitive data stops Claude at `PostToolBatch`, in either mode.

The hooks set `"onFailure": "block"`. A missing or crashed `inkshade-claude-hook` blocks the prompt. A tool that already ran is not rewritten: `PostToolUse` and `PostToolUseFailure` cannot block after the fact. `PostToolBatch` blocks the next model call instead. The raw tool output can remain in the local transcript. This needs Claude Code v2.1.295 or later.

## Limitations

- Only prompts and tool results are checked. CLAUDE.md, memory, the system prompt and images are sent without passing through any hook.
- A successful tool result is masked string by string so it keeps the tool's output shape. Claude Code ignores a replacement for a built-in tool when the shape differs.
- A failed tool result cannot be masked. `PostToolBatch` stops the next model call when that text still contains sensitive data. The raw error can remain in the session transcript and be sent on a later turn.
- If the hook does not start, a tool result that already ran is not rewritten. `PostToolBatch` stops the next model call, and the raw output can remain in the session transcript.
- A blocked prompt can still be stored in local files such as the session transcript.

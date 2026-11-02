# inkshade-claude-hook

A [Claude Code](https://code.claude.com/docs/en/hooks) plugin that runs inkshade on what Claude Code sends to the model.

| Hook event | What it does |
|---|---|
| `UserPromptSubmit` | Blocks a prompt that contains sensitive data and shows the masked text so you can resend it. Hooks can't rewrite a prompt. |
| `PostToolUse` | Masks sensitive data in tool output (Bash, Read, MCP tools, ...) before Claude sees it. By default it also stops Claude. |

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

Choose `stop` (default) or `mask` for tool output in `/config`. `mask` keeps Claude running with masked output.

The hooks set `"onFailure": "block"`, so if `inkshade-claude-hook` is missing from `PATH` or crashes, prompts and tool calls are blocked rather than let through. This needs Claude Code v2.1.295 or later.

## Limitations

- Only prompts and tool output are checked. CLAUDE.md, memory, the system prompt and images are sent without passing through any hook.
- Tool output is masked string by string so it keeps the tool's output shape. Claude Code ignores a replacement for a built-in tool when the shape differs.
- A blocked prompt can still be stored in local files such as the session transcript.

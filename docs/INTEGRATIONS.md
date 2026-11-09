# Integrations: try Warden in five minutes

Three ways in. All free, all local.

| You use | Use this | Needs |
|---|---|---|
| Python code, LangChain or LangGraph | `warden.adapters.langchain.guard_tools` | `pip install 'warden[agents,files]'` |
| Claude Code | `warden hook claude-code` | `pip install warden` |
| Any MCP client (Claude Desktop, Cursor, ...) | the Warden gateway in stdio mode | Node 22, `pnpm build` |

Install from a clone while the package is unpublished: `cd python && uv sync --extra files --extra agents`.

## Python and LangChain

```python
from warden.adapters.client import WardenClient
from warden.adapters.langchain import guard_tools

client = WardenClient()                       # in-process, no server (offline embedder + lite classifier)
# client = WardenClient("http://localhost:8000")   # or a running `warden detector serve`
tools = guard_tools([search_tool, email_tool], client)   # use these in your agent

print(client.check("Ignore all previous instructions and ...").explanation)
print(client.check_file("invoice.pdf").hidden)           # findings for text hidden in files
```

A tool whose output is judged `malicious` returns `[Warden blocked the output of <tool>. <why>]`
instead of its content. `uncertain` output passes unless you set `block_uncertain=True`; the lite
classifier is cautious, so that setting also stops some harmless text (see the README results). If a
remote service is unreachable, `on_error="closed"` (default) reports `uncertain` rather than trusting
the content; `"open"` lets it through.

## Claude Code

Print the hooks block and merge it into `.claude/settings.json` (project) or `~/.claude/settings.json`:

```bash
warden hook claude-code --print-settings
```

The hook reads each event on stdin and answers on stdout:

- `UserPromptSubmit`: scans the prompt, blocks a malicious one.
- `PostToolUse`: scans what a tool returned; for `Read` of a PDF, image or HTML file it also scans the file
  for hidden text. A malicious result is reported back with the reason in plain words.
- `PreToolUse`: denies a call whose text arguments hide a decoded payload (for example Unicode tag characters).

Add `--url http://localhost:8000` to use a running detector, or run it in-process (default). The JSON
answers follow Claude Code's hook contract and are unit-tested here; check them against your Claude Code
version, because the hook schema changes between releases.

## MCP clients (Claude Desktop, Cursor, ...)

Run the gateway as a local MCP server that fronts your real servers, so every tool description, argument and
output is inspected. Save as `warden.yaml`:

```yaml
listen: { host: 127.0.0.1, port: 0 }
admin: { enabled: false }
detector: { url: http://127.0.0.1:8000 }        # optional: `warden detector serve`
servers:
  - name: files
    transport: { type: stdio, command: npx, args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/docs"] }
    trust: untrusted
policy:
  bundle: ""            # empty: the gateway starts, but with no rules only tool pinning applies
  allowUnsigned: true
  requireHumanApproval: false
```

Then point the client at it, for example in `claude_desktop_config.json`:

```json
{ "mcpServers": { "warden": { "command": "node", "args": ["/path/to/Warden/packages/gateway/dist/cli.js", "stdio", "--config", "/path/to/warden.yaml"] } } }
```

Status of this recipe: the gateway starts with this config shape and exits cleanly when the client
disconnects (checked); it has not been run against a real Claude Desktop or Cursor here. With an empty
`bundle` there are **no rules**, so for real protection load a signed policy bundle. The steps to
build one from `policies/baseline.rules.json` are in `infra/compose/config/init-policy.sh`, and the
compose lab in `infra/compose` shows the complete setup.

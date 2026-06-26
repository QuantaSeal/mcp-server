# Contributing to the QuantaSeal MCP Server

The QuantaSeal MCP Server exposes 18 tools via the Model Context Protocol so
AI agents (Claude, GPT-4, Cursor) can interact with vault, encryption,
compliance, and proxy operations.

## Development setup

```bash
git clone https://github.com/quantaseal/mcp-server.git
cd mcp-server
npm install

# Build (outputs to dist/server.js)
npm run build

# Configure Claude Desktop
# Edit ~/Library/Application Support/Claude/claude_desktop_config.json:
# {
#   "mcpServers": {
#     "quantaseal": {
#       "command": "node",
#       "args": ["/path/to/mcp-server/dist/server.js"],
#       "env": { "QUANTASEAL_API_KEY": "qs_live_..." }
#     }
#   }
# }
```

## Pull request guidelines

- Target the `main` branch
- Each new tool must be added to both `TOOL_DEFINITIONS` and the handler map
- Tool names use snake_case and are prefixed by domain (`vault_seal`, `encrypt`, etc.)

## Licence

Apache 2.0.

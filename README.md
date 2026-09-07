# @quantaseal/mcp-server

[![npm version](https://img.shields.io/npm/v/@quantaseal/mcp-server)](https://www.npmjs.com/package/@quantaseal/mcp-server)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-published-blue)](https://registry.modelcontextprotocol.io/servers/io.github.Lokeshwaranramu/quantaseal)
[![Smithery](https://img.shields.io/badge/Smithery-listed-orange)](https://smithery.ai/server/admin-f3vp/quantaseal)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

QuantaSeal MCP (Model Context Protocol) Server — post-quantum-safe vault, encryption, compliance, and audit tools for AI agents.

**21 tools. Per-session tenant isolation. Works with Claude, GPT Actions, GitHub Copilot, and any MCP-compatible agent.**

Every tool call is PQC-protected (ML-KEM-768 + ML-DSA-65 + AES-256-GCM), tenant-isolated, and logged in a tamper-evident audit trail.

## Quickstart — one-click install

| Platform | Install |
|---|---|
| **Claude Desktop** | Add via [MCP Registry](https://registry.modelcontextprotocol.io/servers/io.github.Lokeshwaranramu/quantaseal) or manually (see below) |
| **Smithery** | [smithery.ai/server/admin-f3vp/quantaseal](https://smithery.ai/server/admin-f3vp/quantaseal) → Add to toolbox |
| **Claude.ai (remote)** | Endpoint: `https://mcp.quantaseal.io/mcp` |
| **npm** | `npx @quantaseal/mcp-server` |

Get your API key: [app.quantaseal.io/settings/api-keys](https://app.quantaseal.io/settings/api-keys)

---

## Platform setup

### Claude Desktop / Cursor / Windsurf (stdio)

**Configure** `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "quantaseal": {
      "command": "npx",
      "args": ["-y", "@quantaseal/mcp-server"],
      "env": { "QUANTASEAL_API_KEY": "qs_live_YOUR_KEY_HERE" }
    }
  }
}
```

**Restart** the app. All 21 tools appear automatically.

Get your API key: [https://app.quantaseal.io/settings/api-keys](https://app.quantaseal.io/settings/api-keys)

> **Self-hosted alternative:** `cd sdk/mcp && npm install && npm run build`, then use `"command": "node", "args": ["/path/to/sdk/mcp/dist/server.js"]`

---

### OpenAI GPT Actions

**1. Start the Streamable HTTP server** (or use `mcp.quantaseal.io` if hosted):
```bash
MCP_PUBLIC_URL=https://mcp.quantaseal.io node dist/server.js --transport streamable-http --port 3050
```

**2. In ChatGPT:** My GPTs → Create → Actions → Import from URL:
```
https://mcp.quantaseal.io/openapi.json
```

**3. Set auth:** Authentication → API Key → Header: `Authorization`, value: `Bearer qs_live_...`

The OpenAPI spec at `/openapi.json` exports all 21 tools as POST endpoints. Each operation maps directly to a QuantaSeal tool.

---

### GitHub Copilot (VS Code)

VS Code 1.99+ supports MCP natively. Add to your `settings.json`:
```json
{
  "mcp": {
    "servers": {
      "quantaseal": {
        "type": "http",
        "url": "https://mcp.quantaseal.io/mcp",
        "headers": {
          "Authorization": "Bearer qs_live_YOUR_KEY_HERE"
        }
      }
    }
  }
}
```

Or for local self-hosted:
```json
{
  "mcp.servers": {
    "quantaseal-local": {
      "type": "http",
      "url": "http://localhost:3050/mcp",
      "headers": { "Authorization": "Bearer qs_live_..." }
    }
  }
}
```

Then in VS Code: `@quantaseal` → ask Copilot to seal a credential, check compliance, or query audit logs.

---

### Claude.ai / Any MCP HTTP client

```
MCP endpoint:  https://mcp.quantaseal.io/mcp
Auth header:   Authorization: Bearer qs_live_...
Discovery:     https://mcp.quantaseal.io/.well-known/mcp.json
```

---

### Self-hosted (any platform)

```bash
# Streamable HTTP — OpenAI/Copilot/Claude remote
MCP_PUBLIC_URL=https://your-domain.com npm run start:http

# Legacy SSE — older MCP clients
QUANTASEAL_API_KEY=qs_live_... npm run start:sse
```

---

## Tools

### Health
| Tool | Description |
|------|-------------|
| `quantaseal_health` | API health, PQC algorithm status (ML-KEM-768, ML-DSA-65, AES-256-GCM) |

### Vault
| Tool | Description |
|------|-------------|
| `vault_seal` | Encrypt and store a credential (returns vault entry UUID) |
| `vault_unseal` | Decrypt and retrieve a credential |
| `vault_list` | List entries - metadata only, no plaintext |
| `vault_rotate` | Re-encrypt with fresh keys |
| `vault_delete` | Soft-delete an entry |

### Encryption
| Tool | Description |
|------|-------------|
| `encrypt` | ML-KEM-768 + AES-256-GCM encrypt - returns HybridCryptoEnvelope |
| `decrypt` | Decrypt an envelope (verifies ML-DSA-65 + HMAC-SHA-512 first) |
| `sign` | ML-DSA-65 + HMAC-SHA-512 digital signature |
| `verify_signature` | Verify a signature |

### Integrations
| Tool | Description |
|------|-------------|
| `list_integrations` | List Salesforce, SAP, AWS S3, Kafka, Postgres, etc. integrations |
| `test_integration` | Test connectivity and authentication |
| `proxy_request` | Execute an operation through the encrypted proxy |

### Compliance
| Tool | Description |
|------|-------------|
| `get_compliance_score` | Score (0–100) for SOC2, ISO27001, PCI-DSS, HIPAA, GDPR, NIST-CSF, FedRAMP, APRA-CPS-234, NIST-800-53 |
| `generate_compliance_report` | Generate report with evidence citations and PDF link |
| `list_compliance_reports` | List all reports for this tenant |

### Audit
| Tool | Description |
|------|-------------|
| `list_audit_logs` | Query tamper-evident audit trail with filters |

### Metrics
| Tool | Description |
|------|-------------|
| `get_metrics` | API calls, throughput, latency (P50/P95/P99), plan usage |

### AI Agent Market (new in v1.1.0)
| Tool | Description |
|------|-------------|
| `get_readiness_score` | Quantum Readiness Score (0–100) across 5 pillars: Encryption, Key Mgmt, Integrations, Compliance, Audit |
| `get_regulatory_alerts` | Active PQC regulatory alerts — APRA CPS 234, NIST SP 800-131A, CNSS Policy 15, ENISA, ISO 18033 |
| `get_cbom` | Cryptographic Bill of Materials — algorithm coverage and PQC migration status per integration |

---

## Configuration

| Variable | Description |
|---|---|
| `QUANTASEAL_API_KEY` | API key for stdio/SSE mode (`qs_live_...`) |
| `QUANTASHIELD_API_KEY` | Legacy name — still accepted |
| `QUANTASEAL_BASE_URL` | Override API URL (default: `https://api.quantaseal.io`) |
| `MCP_TRANSPORT` | `stdio` (default) · `streamable-http` · `sse` |
| `MCP_PORT` | HTTP port (default: `3050`) |
| `MCP_PUBLIC_URL` | Public URL for OpenAPI spec server field (e.g. `https://mcp.quantaseal.io`) |

In Streamable HTTP mode the API key is read from each request's `Authorization: Bearer` header — no env var needed.

Get your API key: [https://app.quantaseal.io/settings/api-keys](https://app.quantaseal.io/settings/api-keys)

---

## HTTP endpoints (Streamable HTTP / SSE modes)

| Endpoint | Description |
|---|---|
| `POST /mcp` | MCP Streamable HTTP endpoint (MCP 2025-11-05 spec, PKCE S256 auth) |
| `GET /sse` | MCP SSE endpoint (legacy) |
| `GET /openapi.json` | OpenAPI 3.1 spec — import into GPT Actions or Copilot Extensions |
| `GET /.well-known/mcp.json` | Agent discovery metadata |
| `GET /health` | Liveness probe |

---

## Isolation model

Each API key maps 1:1 to a QuantaSeal tenant. In HTTP mode, each session creates a dedicated server instance bound to the requesting API key. The backend enforces:
- Per-tenant AWS KMS Customer Master Keys (CMKs)
- `tenant_id` in every database query (constant-time comparison via `hmac.compare_digest`)
- ML-DSA-65 signatures bound to the tenant's public key

User A cannot access User B's vault, keys, or audit logs regardless of what tools are called.

---

## Requirements

- Node.js ≥ 18
- A QuantaSeal account: [https://app.quantaseal.io](https://app.quantaseal.io)

---

## Registries

| Registry | Identifier | Status |
|---|---|---|
| [MCP Registry](https://registry.modelcontextprotocol.io) | `io.github.Lokeshwaranramu/quantaseal` | ✅ Published |
| [Smithery](https://smithery.ai) | `admin-f3vp/quantaseal` | ✅ Listed |
| [npm](https://npmjs.com/package/@quantaseal/mcp-server) | `@quantaseal/mcp-server` | ✅ v1.1.4 |
| Hosted endpoint | `mcp.quantaseal.io` | ✅ Live |

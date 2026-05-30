# @quantaseal/mcp-server

QuantaSeal MCP (Model Context Protocol) Server - exposes quantum-safe vault, encryption, integrations, compliance, and audit capabilities as tools for AI agents.

**18 tools. Per-user tenant isolation. Works with Claude Desktop, Claude API, and any MCP-compatible agent.**

---

## What it does

External AI agents connect to this server and call tools like `vault_seal`, `encrypt`, `get_compliance_score`, and `list_audit_logs` - operating within the QuantaSeal tenant that belongs to the user whose API key is configured. Every operation:

- Is cryptographically isolated per-tenant (ML-KEM-768 + AES-256-GCM + ML-DSA-65)
- Is logged in the immutable audit trail (SHA3-256 hash chain + ML-DSA-65 signatures)
- Enforces the user's plan limits and allowed operations

## Quick start

### Claude Desktop

**1. Build:**
```bash
cd sdk/mcp
npm install && npm run build
```

**2. Configure** `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "quantaseal": {
      "command": "node",
      "args": ["/path/to/quantaseal/sdk/mcp/dist/server.js"],
      "env": {
        "QUANTASEAL_API_KEY": "qs_live_YOUR_KEY_HERE"
      }
    }
  }
}
```

**3. Restart Claude Desktop.** The 18 QuantaSeal tools appear automatically.

**4. Try it:**
> "Use the quantaseal_health tool to check the API status"
> "Seal a credential named 'openai-key' with my API key sk-proj-abc123"
> "What's our SOC2 compliance score?"

### Remote / HTTP

```bash
QUANTASEAL_API_KEY=qs_live_... node dist/server.js --transport sse --port 3050
```

Connect your agent to `http://localhost:3050/sse` (MCP SSE protocol).

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

---

## Configuration

| Environment variable | Description |
|---|---|
| `QUANTASEAL_API_KEY` | **Required.** Your API key (`qs_live_...`) |
| `QUANTASHIELD_API_KEY` | Legacy name - still accepted |
| `QUANTASEAL_BASE_URL` | Override API URL (default: `https://api.quantaseal.io`) |
| `MCP_TRANSPORT` | `stdio` (default) or `sse` |
| `MCP_PORT` | Port for SSE mode (default: `3050`) |

Get your API key: [https://app.quantaseal.io/settings/api-keys](https://app.quantaseal.io/settings/api-keys)

---

## Per-user isolation

The API key maps 1:1 to a QuantaSeal tenant. The backend enforces cryptographic isolation through:
- Per-tenant AWS KMS Customer Master Keys (CMKs)
- `tenant_id` enforcement on every database query
- ML-DSA-65 signatures bound to the tenant's public key

User A cannot access User B's vault entries, encryption keys, or audit logs - regardless of what tools are called.

---

## Transport modes

**stdio** (Claude Desktop / local agents)
- Server is spawned as a subprocess
- Communicates via stdin/stdout
- One server instance per user

**SSE** (remote agents / multi-user deployments)
- HTTP server with SSE endpoint at `/sse`
- POST messages at `/message?sessionId=<id>`
- Each SSE connection is isolated
- Deploy behind a reverse proxy with TLS for production

---

## Requirements

- Node.js ≥ 18
- A QuantaSeal account with an active subscription

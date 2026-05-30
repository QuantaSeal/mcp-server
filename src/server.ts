#!/usr/bin/env node
/**
 * QuantaSeal MCP Server
 *
 * Exposes QuantaSeal's quantum-safe vault, encryption, integrations,
 * compliance, and audit capabilities as MCP tools for AI agents.
 *
 * Each user's API key maps to exactly one tenant - all operations are
 * cryptographically isolated by the QuantaSeal backend.
 *
 * Usage (stdio - Claude Desktop):
 *   QUANTASEAL_API_KEY=qs_live_... node dist/server.js
 *
 * Usage (HTTP/SSE - remote agents):
 *   QUANTASEAL_API_KEY=qs_live_... node dist/server.js --transport sse --port 3050
 *
 * Get your API key: https://app.quantaseal.io/settings/api-keys
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import * as http from "node:http";

const VERSION = "1.0.0";
const DEFAULT_BASE_URL = "https://api.quantaseal.io";

// ─── QuantaSeal API client ────────────────────────────────────────────────────

function getApiKey(): string {
  const key =
    process.env.QUANTASEAL_API_KEY ?? process.env.QUANTASHIELD_API_KEY;
  if (!key) {
    throw new McpError(
      ErrorCode.InvalidRequest,
      "QUANTASEAL_API_KEY is not set. " +
        "Get your API key at https://app.quantaseal.io/settings/api-keys",
    );
  }
  return key;
}

function getBaseUrl(): string {
  return (
    process.env.QUANTASEAL_BASE_URL ??
    process.env.QUANTASHIELD_BASE_URL ??
    DEFAULT_BASE_URL
  );
}

interface ApiEnvelope<T = unknown> {
  success: boolean;
  data?: T;
  error?: { message: string; code?: string };
  meta?: { request_id?: string };
}

async function call<T = unknown>(
  method: string,
  path: string,
  body?: Record<string, unknown>,
  params?: Record<string, string>,
): Promise<T> {
  const apiKey = getApiKey();
  const base = getBaseUrl().replace(/\/+$/, "");
  let url = `${base}${path}`;
  if (params && Object.keys(params).length > 0) {
    url += "?" + new URLSearchParams(params).toString();
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        "X-API-Key": apiKey,
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": `quantaseal-mcp/${VERSION}`,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    throw new McpError(
      ErrorCode.InternalError,
      `Cannot reach QuantaSeal API at ${base}: ${(err as Error).message}`,
    );
  }

  // 204 No Content - success with no body
  if (response.status === 204) {
    return undefined as unknown as T;
  }

  let json: ApiEnvelope<T>;
  try {
    json = (await response.json()) as ApiEnvelope<T>;
  } catch {
    throw new McpError(
      ErrorCode.InternalError,
      `QuantaSeal API returned non-JSON (HTTP ${response.status})`,
    );
  }

  if (!response.ok || json.success === false) {
    const msg = json.error?.message ?? `HTTP ${response.status}`;
    const code = json.error?.code ?? "API_ERROR";
    const mcpCode =
      response.status === 401 || response.status === 403
        ? ErrorCode.InvalidRequest
        : ErrorCode.InternalError;
    throw new McpError(mcpCode, `[${code}] ${msg}`);
  }

  // For enveloped responses return data; for raw endpoints (no envelope) return the full body.
  if (json.data !== undefined) return json.data as T;
  // If there's no success/data/error structure it's a raw response (e.g. /health).
  if (json.success === undefined) return json as unknown as T;
  return undefined as unknown as T;
}

// ─── Tool definitions (JSON Schema) ──────────────────────────────────────────

const TOOLS = [
  // ── Health ──────────────────────────────────────────────────────────────────
  {
    name: "quantaseal_health",
    description:
      "Check QuantaSeal API health and PQC algorithm status. Returns service " +
      "health for Database, Redis, KMS, and Crypto Pool, plus the active " +
      "post-quantum algorithms (ML-KEM-768, ML-DSA-65, AES-256-GCM).",
    inputSchema: { type: "object", properties: {}, required: [] },
  },

  // ── Vault ────────────────────────────────────────────────────────────────────
  {
    name: "vault_seal",
    description:
      "Seal (encrypt and store) a credential using ML-KEM-768 + AES-256-GCM " +
      "+ ML-DSA-65 triple-layer encryption. Tenant isolation is enforced by " +
      "the API key. Returns the vault entry UUID.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Human-readable label (e.g. 'aws-prod-keys')",
        },
        credential_type: {
          type: "string",
          enum: [
            "api_key",
            "password",
            "oauth2_token",
            "oauth2_client",
            "bearer_token",
            "basic_auth",
            "mtls_cert",
            "saml_assertion",
            "jwt_signing_key",
            "aws_credentials",
            "ssh_key_pair",
            "database_dsn",
            "kafka_credentials",
            "webhook_secret",
            "custom_kv",
          ],
          description: "Credential type",
        },
        plaintext: {
          type: "object",
          description:
            "Credential key-value pairs (e.g. {\"key\": \"sk-abc123\"})",
          additionalProperties: true,
        },
        ttl_days: {
          type: "number",
          minimum: 1,
          maximum: 365,
          description: "Optional TTL in days (1–365). Omit for no expiry.",
        },
        metadata: {
          type: "object",
          description: "Optional metadata to store alongside the credential",
          additionalProperties: true,
        },
      },
      required: ["name", "credential_type", "plaintext"],
    },
  },
  {
    name: "vault_unseal",
    description:
      "Unseal (decrypt and retrieve) a credential. Verifies ML-DSA-65 " +
      "signature and HMAC-SHA-512 before any decryption. Every call is " +
      "logged in the tamper-evident audit trail.",
    inputSchema: {
      type: "object",
      properties: {
        entry_id: {
          type: "string",
          description: "UUID of the vault entry to unseal",
        },
      },
      required: ["entry_id"],
    },
  },
  {
    name: "vault_list",
    description:
      "List vault entries (metadata only - no plaintext). Use vault_unseal " +
      "to retrieve the actual credential.",
    inputSchema: {
      type: "object",
      properties: {
        include_inactive: {
          type: "boolean",
          description: "Include soft-deleted entries (default: false)",
        },
      },
      required: [],
    },
  },
  {
    name: "vault_rotate",
    description:
      "Rotate encryption keys for a vault entry. The credential is decrypted " +
      "with current keys and immediately re-encrypted with fresh keys. Old " +
      "entry is deactivated. Returns old and new entry IDs.",
    inputSchema: {
      type: "object",
      properties: {
        entry_id: {
          type: "string",
          description: "UUID of the vault entry to rotate",
        },
      },
      required: ["entry_id"],
    },
  },
  {
    name: "vault_delete",
    description:
      "Soft-delete a vault entry. Entry is deactivated and excluded from " +
      "list results. Logged in the audit trail.",
    inputSchema: {
      type: "object",
      properties: {
        entry_id: {
          type: "string",
          description: "UUID of the vault entry to delete",
        },
      },
      required: ["entry_id"],
    },
  },

  // ── Encryption ───────────────────────────────────────────────────────────────
  {
    name: "encrypt",
    description:
      "Encrypt text using ML-KEM-768 + AES-256-GCM (FIPS 203). Returns a " +
      "HybridCryptoEnvelope with ciphertext and ML-DSA-65 signature. Store " +
      "the full envelope to decrypt later.",
    inputSchema: {
      type: "object",
      properties: {
        plaintext: {
          type: "string",
          description: "Text to encrypt",
        },
        algorithm: {
          type: "string",
          enum: ["ML-KEM-768", "ML-KEM-1024"],
          description: "KEM algorithm (default: ML-KEM-768)",
        },
      },
      required: ["plaintext"],
    },
  },
  {
    name: "decrypt",
    description:
      "Decrypt a HybridCryptoEnvelope from the encrypt tool. Verifies both " +
      "ML-DSA-65 PQC signature and HMAC-SHA-512 before decrypting.",
    inputSchema: {
      type: "object",
      properties: {
        envelope: {
          type: "object",
          description: "The complete HybridCryptoEnvelope from a previous encrypt call",
          additionalProperties: true,
        },
      },
      required: ["envelope"],
    },
  },
  {
    name: "sign",
    description:
      "Sign text with ML-DSA-65 (FIPS 204) + HMAC-SHA-512. Returns the PQC " +
      "signature, HMAC signature, and public key for verification.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "string",
          description: "Text to sign",
        },
      },
      required: ["data"],
    },
  },
  {
    name: "verify_signature",
    description:
      "Verify an ML-DSA-65 + HMAC-SHA-512 signature from the sign tool. " +
      "Reports validity of both the PQC signature and HMAC independently.",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "string",
          description: "Original text that was signed",
        },
        signature: {
          type: "string",
          description: "Base64-encoded ML-DSA-65 signature",
        },
        hmac_signature: {
          type: "string",
          description: "Base64-encoded HMAC-SHA-512 signature",
        },
        public_key: {
          type: "string",
          description: "Base64-encoded public key from the sign result",
        },
      },
      required: ["data", "signature", "hmac_signature", "public_key"],
    },
  },

  // ── Integrations ─────────────────────────────────────────────────────────────
  {
    name: "list_integrations",
    description:
      "List all configured integrations for this tenant. Returns name, system " +
      "type (Salesforce, SAP, AWS S3, Kafka, Postgres, etc.), status, and " +
      "allowed operations.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
  {
    name: "test_integration",
    description:
      "Test connectivity to a configured integration. Verifies authentication " +
      "without executing data operations. Returns status and latency_ms.",
    inputSchema: {
      type: "object",
      properties: {
        integration_id: {
          type: "string",
          description: "UUID of the integration to test",
        },
      },
      required: ["integration_id"],
    },
  },
  {
    name: "proxy_request",
    description:
      "Execute an operation through an integration proxy. The credential is " +
      "automatically unsealed from the vault, the operation is performed, and " +
      "the response is encrypted. Only operations in allowed_operations are " +
      "permitted (default-deny policy).",
    inputSchema: {
      type: "object",
      properties: {
        integration_id: {
          type: "string",
          description: "UUID of the integration",
        },
        operation: {
          type: "string",
          description:
            "Operation to perform (must be listed in the integration's allowed_operations)",
        },
        payload: {
          type: "object",
          description: "Operation-specific payload",
          additionalProperties: true,
        },
      },
      required: ["integration_id", "operation", "payload"],
    },
  },

  // ── Compliance ───────────────────────────────────────────────────────────────
  {
    name: "get_compliance_score",
    description:
      "Get the current compliance score (0–100) with grade and control " +
      "breakdown. Supported: SOC2, ISO27001, PCI-DSS, HIPAA, GDPR, " +
      "NIST-CSF, FedRAMP, APRA-CPS-234, NIST-800-53.",
    inputSchema: {
      type: "object",
      properties: {
        framework: {
          type: "string",
          enum: [
            "SOC2",
            "ISO27001",
            "PCI-DSS",
            "HIPAA",
            "GDPR",
            "NIST-CSF",
            "FedRAMP",
            "APRA-CPS-234",
            "NIST-800-53",
          ],
          description: "Compliance framework",
        },
      },
      required: ["framework"],
    },
  },
  {
    name: "generate_compliance_report",
    description:
      "Generate a compliance report with evidence citations, control status, " +
      "and a PDF download link. Evidence is sourced from the immutable audit log.",
    inputSchema: {
      type: "object",
      properties: {
        framework: {
          type: "string",
          enum: [
            "SOC2",
            "ISO27001",
            "PCI-DSS",
            "HIPAA",
            "GDPR",
            "NIST-CSF",
            "FedRAMP",
            "APRA-CPS-234",
            "NIST-800-53",
          ],
          description: "Compliance framework",
        },
      },
      required: ["framework"],
    },
  },
  {
    name: "list_compliance_reports",
    description:
      "List previously generated compliance reports for a framework, " +
      "including their status and download URLs. Defaults to SOC2.",
    inputSchema: {
      type: "object",
      properties: {
        framework: {
          type: "string",
          enum: [
            "SOC2",
            "ISO27001",
            "PCI-DSS",
            "HIPAA",
            "GDPR",
            "NIST-CSF",
            "FedRAMP",
            "APRA-CPS-234",
            "NIST-800-53",
          ],
          description: "Compliance framework (default: SOC2)",
        },
      },
      required: [],
    },
  },

  // ── Audit ────────────────────────────────────────────────────────────────────
  {
    name: "list_audit_logs",
    description:
      "Query the immutable audit trail. Logs are protected by a SHA3-256 " +
      "hash chain + ML-DSA-65 signatures - tamper-evident and exportable for " +
      "compliance evidence. Filter by action, date range, or actor.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          description:
            "Filter by action (e.g. 'vault.seal', 'encryption.encrypt', " +
            "'proxy.outbound')",
        },
        start_date: {
          type: "string",
          description: "ISO 8601 start date (e.g. '2026-01-01')",
        },
        end_date: {
          type: "string",
          description: "ISO 8601 end date (e.g. '2026-12-31')",
        },
        limit: {
          type: "number",
          minimum: 1,
          maximum: 500,
          description: "Number of entries (default: 50, max: 500)",
        },
      },
      required: [],
    },
  },

  // ── Metrics ──────────────────────────────────────────────────────────────────
  {
    name: "get_metrics",
    description:
      "Get current API usage metrics - API call counts, throughput (req/min), " +
      "latency percentiles (P50/P95/P99), vault statistics, and plan limits.",
    inputSchema: { type: "object", properties: {}, required: [] },
  },
] as const;

// ─── Tool handler helpers ─────────────────────────────────────────────────────

type ToolInput = Record<string, unknown>;

function toBase64(text: string): string {
  return Buffer.from(text, "utf-8").toString("base64");
}

function tryDecodeBase64(b64: string): string {
  try {
    return Buffer.from(b64, "base64").toString("utf-8");
  } catch {
    return b64;
  }
}

function fmt(value: unknown): string {
  // JSON.stringify(undefined) returns undefined (not a string).
  // MCP SDK 1.12.0+ requires content[].text to be a non-undefined string.
  if (value === undefined || value === null) return "{}";
  return JSON.stringify(value, null, 2);
}

// ─── Tool handlers ────────────────────────────────────────────────────────────

async function handleHealth(_: ToolInput): Promise<string> {
  // /health is a raw endpoint - it does NOT use the APIResponse<T> envelope,
  // so we fetch it directly instead of going through call() which unwraps .data.
  const apiKey = getApiKey();
  const base = getBaseUrl().replace(/\/+$/, "");
  let res: Response;
  try {
    res = await fetch(`${base}/health`, {
      headers: {
        "X-API-Key": apiKey,
        Accept: "application/json",
        "User-Agent": `quantaseal-mcp/${VERSION}`,
      },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    throw new McpError(
      ErrorCode.InternalError,
      `Cannot reach QuantaSeal API at ${base}: ${(err as Error).message}`,
    );
  }
  const data = (await res.json()) as Record<string, unknown>;
  return fmt(data);
}

async function handleVaultSeal(input: ToolInput): Promise<string> {
  const body: Record<string, unknown> = {
    name: input.name,
    credential_type: input.credential_type,
    plaintext: input.plaintext,
  };
  if (input.ttl_days != null) body.ttl_days = input.ttl_days;
  if (input.metadata != null) body.metadata = input.metadata;

  const entryId = await call<string>("POST", "/api/v2/vault/seal", body);
  return fmt({ entry_id: entryId, status: "sealed" });
}

async function handleVaultUnseal(input: ToolInput): Promise<string> {
  const data = await call<Record<string, unknown>>(
    "POST",
    `/api/v2/vault/unseal/${input.entry_id as string}`,
  );
  return fmt(data);
}

async function handleVaultList(input: ToolInput): Promise<string> {
  const params: Record<string, string> = {};
  if (input.include_inactive === true) params.include_inactive = "true";
  const data = await call<unknown[]>("GET", "/api/v2/vault/entries", undefined, params);
  return fmt(data);
}

async function handleVaultRotate(input: ToolInput): Promise<string> {
  const data = await call<Record<string, unknown>>(
    "POST",
    `/api/v2/vault/rotate/${input.entry_id as string}`,
  );
  return fmt(data);
}

async function handleVaultDelete(input: ToolInput): Promise<string> {
  await call<void>("DELETE", `/api/v2/vault/entries/${input.entry_id as string}`);
  return fmt({ status: "deleted", entry_id: input.entry_id });
}

async function handleEncrypt(input: ToolInput): Promise<string> {
  const body: Record<string, unknown> = {
    plaintext: toBase64(input.plaintext as string),
    algorithm: (input.algorithm as string | undefined) ?? "ML-KEM-768",
  };
  const data = await call<Record<string, unknown>>(
    "POST",
    "/api/v2/encryption/encrypt",
    body,
  );
  return fmt(data);
}

async function handleDecrypt(input: ToolInput): Promise<string> {
  const body: Record<string, unknown> = {
    envelope: input.envelope,
    verify_signature: true,
  };
  const data = await call<Record<string, unknown>>(
    "POST",
    "/api/v2/encryption/decrypt",
    body,
  );
  // Add a decoded plaintext field for readability
  if (typeof data.plaintext === "string") {
    return fmt({ ...data, plaintext_decoded: tryDecodeBase64(data.plaintext) });
  }
  return fmt(data);
}

async function handleSign(input: ToolInput): Promise<string> {
  const body: Record<string, unknown> = {
    data: toBase64(input.data as string),
    algorithm: "ML-DSA-65",
  };
  const data = await call<Record<string, unknown>>(
    "POST",
    "/api/v2/encryption/sign",
    body,
  );
  return fmt(data);
}

async function handleVerify(input: ToolInput): Promise<string> {
  const body: Record<string, unknown> = {
    data: toBase64(input.data as string),
    signature: input.signature,
    hmac_signature: input.hmac_signature,
    public_key: input.public_key,
  };
  const data = await call<Record<string, unknown>>(
    "POST",
    "/api/v2/encryption/verify",
    body,
  );
  return fmt(data);
}

async function handleListIntegrations(_: ToolInput): Promise<string> {
  const data = await call<unknown[]>("GET", "/api/v2/proxy/integrations");
  return fmt(data);
}

async function handleTestIntegration(input: ToolInput): Promise<string> {
  const data = await call<Record<string, unknown>>(
    "POST",
    `/api/v2/proxy/integrations/${input.integration_id as string}/test`,
  );
  return fmt(data);
}

async function handleProxyRequest(input: ToolInput): Promise<string> {
  const body: Record<string, unknown> = {
    integration_id: input.integration_id,
    operation: input.operation,
    payload: input.payload ?? {},
  };
  const data = await call<Record<string, unknown>>(
    "POST",
    "/api/v2/proxy/execute",
    body,
  );
  return fmt(data);
}

async function handleGetComplianceScore(input: ToolInput): Promise<string> {
  const framework = (input.framework as string).toLowerCase();
  const data = await call<Record<string, unknown>>(
    "GET",
    `/api/v2/compliance/score/${framework}`,
  );
  return fmt(data);
}

async function handleGenerateReport(input: ToolInput): Promise<string> {
  const framework = (input.framework as string).toLowerCase();
  // Request JSON format so the MCP tool can return structured data to the agent.
  // The backend also supports "pdf" which returns a binary - not useful for agents.
  const data = await call<Record<string, unknown>>(
    "POST",
    `/api/v2/compliance/report/${framework}`,
    undefined,
    { format: "json" },
  );
  return fmt(data);
}

async function handleListReports(input: ToolInput): Promise<string> {
  // Returns compliance history for a framework (default: soc2)
  const framework = ((input.framework as string | undefined) ?? "SOC2").toLowerCase();
  const data = await call<unknown[]>("GET", `/api/v2/compliance/history/${framework}`);
  return fmt(data);
}

async function handleListAuditLogs(input: ToolInput): Promise<string> {
  const params: Record<string, string> = {
    limit: String((input.limit as number | undefined) ?? 50),
  };
  if (input.action) params.action = input.action as string;
  if (input.start_date) params.start_date = input.start_date as string;
  if (input.end_date) params.end_date = input.end_date as string;

  // Audit endpoint: GET /api/v2/audit (not /api/v2/audit/logs)
  const data = await call<unknown[]>("GET", "/api/v2/audit", undefined, params);
  return fmt(data);
}

async function handleGetMetrics(_: ToolInput): Promise<string> {
  // GET /api/v2/metrics/api-usage - combined usage metrics
  const data = await call<Record<string, unknown>>("GET", "/api/v2/metrics/api-usage");
  return fmt(data);
}

// ─── Dispatch map ─────────────────────────────────────────────────────────────

const HANDLERS: Record<string, (input: ToolInput) => Promise<string>> = {
  quantaseal_health: handleHealth,
  vault_seal: handleVaultSeal,
  vault_unseal: handleVaultUnseal,
  vault_list: handleVaultList,
  vault_rotate: handleVaultRotate,
  vault_delete: handleVaultDelete,
  encrypt: handleEncrypt,
  decrypt: handleDecrypt,
  sign: handleSign,
  verify_signature: handleVerify,
  list_integrations: handleListIntegrations,
  test_integration: handleTestIntegration,
  proxy_request: handleProxyRequest,
  get_compliance_score: handleGetComplianceScore,
  generate_compliance_report: handleGenerateReport,
  list_compliance_reports: handleListReports,
  list_audit_logs: handleListAuditLogs,
  get_metrics: handleGetMetrics,
};

// ─── MCP server factory ───────────────────────────────────────────────────────

function createServer(): Server {
  const server = new Server(
    { name: "quantaseal", version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS as unknown as Parameters<
      typeof server.setRequestHandler
    >[1] extends (req: unknown) => Promise<{ tools: infer T }> ? T : never[],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const handler = HANDLERS[name];

    if (!handler) {
      throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }

    try {
      const text = await handler((args ?? {}) as ToolInput);
      return { content: [{ type: "text", text }] };
    } catch (err) {
      if (err instanceof McpError) throw err;
      throw new McpError(
        ErrorCode.InternalError,
        `Tool ${name} failed: ${(err as Error).message}`,
      );
    }
  });

  return server;
}

// ─── Transports ───────────────────────────────────────────────────────────────

async function runStdio(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Runs until stdin is closed
}

async function runSSE(port: number): Promise<void> {
  // Each SSE connection gets its own server instance so tools are isolated per session.
  const sessions = new Map<string, SSEServerTransport>();

  const httpServer = http.createServer(async (req, res) => {
    // CORS headers for browser-based agents
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-API-Key");

    if (req.method === "OPTIONS") {
      res.writeHead(200).end();
      return;
    }

    const url = new URL(req.url ?? "/", `http://localhost:${port}`);

    // GET /sse - open SSE stream
    if (req.method === "GET" && url.pathname === "/sse") {
      const transport = new SSEServerTransport("/message", res);
      sessions.set(transport.sessionId, transport);
      res.on("close", () => sessions.delete(transport.sessionId));

      const server = createServer();
      await server.connect(transport);
      return;
    }

    // POST /message?sessionId=<id> - MCP message from client
    if (req.method === "POST" && url.pathname === "/message") {
      const sessionId = url.searchParams.get("sessionId") ?? "";
      const transport = sessions.get(sessionId);

      if (!transport) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Session not found" }));
        return;
      }

      let raw = "";
      for await (const chunk of req) raw += chunk;

      try {
        await transport.handlePostMessage(
          req,
          res,
          JSON.parse(raw) as Record<string, unknown>,
        );
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: (err as Error).message }));
      }
      return;
    }

    // GET /health - server liveness probe
    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({ status: "ok", server: "quantaseal-mcp", version: VERSION }),
      );
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, () => resolve());
  });

  console.error(`QuantaSeal MCP server listening on http://localhost:${port}`);
  console.error(`  SSE endpoint:  http://localhost:${port}/sse`);
  console.error(`  Health check:  http://localhost:${port}/health`);
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  const transportArg =
    args[args.indexOf("--transport") + 1] ??
    process.env.MCP_TRANSPORT ??
    "stdio";

  const portArg =
    args[args.indexOf("--port") + 1] ??
    process.env.MCP_PORT ??
    "3050";

  if (transportArg === "sse" || transportArg === "http") {
    await runSSE(parseInt(portArg, 10));
  } else {
    await runStdio();
  }
}

main().catch((err: unknown) => {
  console.error("Fatal:", err);
  process.exit(1);
});

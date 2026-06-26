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
 * Usage (stdio - Claude Desktop / Cursor / Windsurf):
 *   QUANTASEAL_API_KEY=qs_live_... node dist/server.js
 *
 * Usage (Streamable HTTP - OpenAI GPT Actions, GitHub Copilot, Claude.ai remote):
 *   node dist/server.js --transport streamable-http --port 3050
 *   Each agent sends its own API key in: Authorization: Bearer qs_live_...
 *
 * Usage (SSE - legacy remote agents):
 *   QUANTASEAL_API_KEY=qs_live_... node dist/server.js --transport sse --port 3050
 *
 * Get your API key: https://app.quantaseal.io/settings/api-keys
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import * as http from "node:http";
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID, createHash, timingSafeEqual } from "node:crypto";

const VERSION = "1.1.0";
const DEFAULT_BASE_URL = "https://api.quantaseal.io";

// ── PKCE Authorization Code store ─────────────────────────────────────────────
// Short-lived in-memory store for pending auth codes (TTL 10 minutes).
// Each entry maps a random code → {codeChallenge, apiKey, redirectUri, expiresAt}.
interface PendingCode {
  codeChallenge: string;
  apiKey: string;
  redirectUri: string;
  expiresAt: number;
}
const pendingCodes = new Map<string, PendingCode>();
// Sweep expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pendingCodes) if (v.expiresAt < now) pendingCodes.delete(k);
}, 5 * 60 * 1000).unref();

function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function timingSafeStringEqual(a: string, b: string): boolean {
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

// Per-request context: stores the API key extracted from the HTTP request header
// so tool handlers can call getApiKey() transparently in both stdio and HTTP modes.
const requestContext = new AsyncLocalStorage<{ apiKey: string }>();

// ─── QuantaSeal API client ────────────────────────────────────────────────────

function getApiKey(): string {
  // In Streamable HTTP / SSE hosted mode the key comes from the Authorization
  // header and is stored per-request in AsyncLocalStorage.
  const ctx = requestContext.getStore();
  if (ctx?.apiKey) return ctx.apiKey;

  // stdio mode (and local SSE with QUANTASEAL_API_KEY env var)
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

function extractApiKeyFromHeaders(headers: http.IncomingHttpHeaders): string | undefined {
  const auth = headers["authorization"];
  if (auth) return auth.replace(/^Bearer\s+/i, "").trim();
  const xKey = headers["x-api-key"];
  if (typeof xKey === "string") return xKey.trim();
  return undefined;
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
    annotations: { title: "Check API Health", readOnlyHint: true },
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
    annotations: { title: "Seal Credential", readOnlyHint: false },
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
    annotations: { title: "Unseal Credential", readOnlyHint: true },
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
    annotations: { title: "List Vault Entries", readOnlyHint: true },
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
    annotations: { title: "Rotate Vault Key", readOnlyHint: false, destructiveHint: false },
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
    annotations: { title: "Delete Vault Entry", readOnlyHint: false, destructiveHint: true },
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
    annotations: { title: "Encrypt Data", readOnlyHint: false },
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
    annotations: { title: "Decrypt Data", readOnlyHint: true },
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
    annotations: { title: "Sign Data", readOnlyHint: false },
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
    annotations: { title: "Verify Signature", readOnlyHint: true },
  },

  // ── Integrations ─────────────────────────────────────────────────────────────
  {
    name: "list_integrations",
    description:
      "List all configured integrations for this tenant. Returns name, system " +
      "type (Salesforce, SAP, AWS S3, Kafka, Postgres, etc.), status, and " +
      "allowed operations.",
    inputSchema: { type: "object", properties: {}, required: [] },
    annotations: { title: "List Integrations", readOnlyHint: true },
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
    annotations: { title: "Test Integration", readOnlyHint: true },
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
    annotations: { title: "Execute Proxy Request", readOnlyHint: false },
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
    annotations: { title: "Get Compliance Score", readOnlyHint: true },
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
    annotations: { title: "Generate Compliance Report", readOnlyHint: false },
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
    annotations: { title: "List Compliance Reports", readOnlyHint: true },
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
    annotations: { title: "List Audit Logs", readOnlyHint: true },
  },

  // ── Metrics ──────────────────────────────────────────────────────────────────
  {
    name: "get_metrics",
    description:
      "Get current API usage metrics - API call counts, throughput (req/min), " +
      "latency percentiles (P50/P95/P99), vault statistics, and plan limits.",
    inputSchema: { type: "object", properties: {}, required: [] },
    annotations: { title: "Get Usage Metrics", readOnlyHint: true },
  },

  // ── AI Agent Market tools ─────────────────────────────────────────────────────
  {
    name: "get_readiness_score",
    description:
      "Get this tenant's Quantum Readiness Score (0–100) with a letter grade " +
      "and a breakdown across 5 pillars: Encryption (PQC algorithm coverage), " +
      "Key Management (rotation + TTL), Integrations (PQC plane coverage), " +
      "Compliance (framework scores), and Audit (log completeness). Use this " +
      "to assess and report on post-quantum migration progress.",
    inputSchema: { type: "object", properties: {}, required: [] },
    annotations: { title: "Get PQC Readiness Score", readOnlyHint: true },
  },
  {
    name: "get_regulatory_alerts",
    description:
      "Retrieve active post-quantum regulatory alerts and compliance change " +
      "notifications. Covers APRA CPS 234, NIST SP 800-131A, CNSS Policy 15, " +
      "ENISA PQC guidelines, and ISO/IEC 18033. Returns severity, affected " +
      "frameworks, required action, and deadline for each alert. Use this to " +
      "stay current on regulatory changes that require cryptographic updates.",
    inputSchema: {
      type: "object",
      properties: {
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by minimum severity (default: all)",
        },
        unacknowledged_only: {
          type: "boolean",
          description: "Return only alerts not yet acknowledged (default: false)",
        },
      },
      required: [],
    },
    annotations: { title: "Get Regulatory Alerts", readOnlyHint: true },
  },
  {
    name: "get_cbom",
    description:
      "Get the Cryptographic Bill of Materials (CBOM) for all integrations " +
      "configured in this tenant. Returns algorithm coverage, PQC migration " +
      "status (quantum-safe / hybrid / classical-only / unknown), and " +
      "remediation priority for each connector. Use this to identify which " +
      "systems still use classical-only cryptography and are at risk from " +
      "'Harvest Now, Decrypt Later' attacks.",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["json", "summary"],
          description: "Response format: full JSON or executive summary (default: json)",
        },
      },
      required: [],
    },
    annotations: { title: "Get Crypto Bill of Materials", readOnlyHint: true },
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
  const data = await call<Record<string, unknown>>("GET", "/api/v2/metrics/api-usage");
  return fmt(data);
}

async function handleGetReadinessScore(_: ToolInput): Promise<string> {
  const data = await call<Record<string, unknown>>("GET", "/api/v2/security/readiness-score");
  return fmt(data);
}

async function handleGetRegulatoryAlerts(input: ToolInput): Promise<string> {
  const params: Record<string, string> = {};
  if (input.severity) params.severity = input.severity as string;
  if (input.unacknowledged_only === true) params.unacknowledged_only = "true";
  const data = await call<unknown[]>("GET", "/api/v2/regulatory-alerts", undefined, params);
  return fmt(data);
}

async function handleGetCbom(input: ToolInput): Promise<string> {
  const params: Record<string, string> = {};
  if (input.format) params.format = input.format as string;
  const data = await call<Record<string, unknown>>("GET", "/api/v2/security/cbom", undefined, params);
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
  get_readiness_score: handleGetReadinessScore,
  get_regulatory_alerts: handleGetRegulatoryAlerts,
  get_cbom: handleGetCbom,
};

// ─── MCP server factory ───────────────────────────────────────────────────────

function createServer(): Server {
  const server = new Server(
    {
      name: "QuantaSeal",
      version: VERSION,
      title: "QuantaSeal MCP Server",
      description:
        "Post-quantum cryptographic security platform for AI agents. " +
        "Seal/unseal secrets with ML-KEM-768 + AES-256-GCM, encrypt/sign data with ML-DSA-65, " +
        "and check SOC 2, HIPAA, GDPR, PCI DSS compliance — 21 tools, NIST FIPS 203/204/205.",
      websiteUrl: "https://quantaseal.io/mcp",
      icons: [
        { src: "https://quantaseal.io/logo-icon.svg", mimeType: "image/svg+xml" },
      ],
    },
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
      res.end(JSON.stringify({ status: "ok", server: "quantaseal-mcp", version: VERSION, tools: TOOLS.length }));
      return;
    }

    // GET /openapi.json - GPT Actions / Copilot Extensions compatible schema
    if (req.method === "GET" && url.pathname === "/openapi.json") {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(generateOpenApiSpec(publicUrl), null, 2));
      return;
    }

    // GET /.well-known/mcp.json - agent discovery
    if (req.method === "GET" && url.pathname === "/.well-known/mcp.json") {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        schema_version: "v1",
        name: "QuantaSeal",
        description: "Post-quantum vault, encryption, and compliance tools for AI agents.",
        mcp_endpoint: `${publicUrl}/sse`,
        auth: { type: "bearer", obtain_url: "https://app.quantaseal.io/settings/api-keys" },
        capabilities: ["tools"],
      }, null, 2));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, () => resolve());
  });

  console.error(`QuantaSeal MCP server (SSE) on http://localhost:${port}`);
  console.error(`  SSE endpoint:  http://localhost:${port}/sse`);
  console.error(`  OpenAPI spec:  http://localhost:${port}/openapi.json`);
  console.error(`  Health check:  http://localhost:${port}/health`);
}

// ─── OpenAPI 3.1 schema generator ────────────────────────────────────────────
// Exports all MCP tools as a GPT Actions / Copilot Extensions compatible spec.

function generateOpenApiSpec(publicUrl: string): Record<string, unknown> {
  const paths: Record<string, unknown> = {};

  for (const tool of TOOLS) {
    paths[`/tools/${tool.name}`] = {
      post: {
        operationId: tool.name,
        summary: tool.description.split(".")[0],
        description: tool.description,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: Object.keys((tool.inputSchema as { properties?: object }).properties ?? {}).length > 0,
          content: {
            "application/json": {
              schema: tool.inputSchema,
            },
          },
        },
        responses: {
          "200": {
            description: "Tool result",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    result: { type: "string", description: "JSON-encoded tool output" },
                  },
                },
              },
            },
          },
          "400": { description: "Invalid input" },
          "401": { description: "Missing or invalid API key" },
          "403": { description: "Forbidden - tenant isolation violation" },
        },
      },
    };
  }

  return {
    openapi: "3.1.0",
    info: {
      title: "QuantaSeal MCP Tools API",
      version: VERSION,
      description:
        "Post-quantum cryptographic vault, encryption, compliance, and audit " +
        "tools for AI agents. All operations use ML-KEM-768 + ML-DSA-65 + " +
        "AES-256-GCM (FIPS 203/204). Compatible with Claude, GPT Actions, " +
        "and GitHub Copilot Extensions.",
      contact: { name: "QuantaSeal", url: "https://quantaseal.io" },
      license: { name: "MIT" },
    },
    servers: [{ url: publicUrl, description: "QuantaSeal MCP endpoint" }],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          description: "QuantaSeal API key — obtain at https://app.quantaseal.io/settings/api-keys",
        },
        ApiKeyHeader: {
          type: "apiKey",
          in: "header",
          name: "X-API-Key",
          description: "Alternative to Authorization: Bearer — for platforms that prefer header-based auth",
        },
      },
    },
    security: [{ BearerAuth: [] }],
    paths,
  };
}

// ─── Streamable HTTP transport (MCP 2025-03-26 spec) ─────────────────────────
// This is the standard for hosted MCP: OpenAI GPT Actions, GitHub Copilot,
// VS Code built-in MCP client, and Claude.ai remote agents all use this.
// Each session is isolated: one MCP server instance per API key per session.

async function runStreamableHttp(port: number): Promise<void> {
  type Session = { transport: StreamableHTTPServerTransport; apiKey: string };
  const sessions = new Map<string, Session>();

  function addCorsHeaders(res: http.ServerResponse, reqHeaders: http.IncomingHttpHeaders): void {
    const origin = (reqHeaders["origin"] as string | undefined) ?? "*";
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-API-Key, Mcp-Session-Id",
    );
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");
  }

  const httpServer = http.createServer(async (req, res) => {
    addCorsHeaders(res, req.headers);

    if (req.method === "OPTIONS") {
      res.writeHead(204).end();
      return;
    }

    const url = new URL(req.url ?? "/", `http://localhost:${port}`);

    // ── /.well-known/oauth-protected-resource — RFC 9728 (MCP 2025-11-05 auth) ─
    // Required by Smithery and MCP clients that use OAuth discovery before
    // connecting. We use API-key Bearer tokens (not full OAuth), so we point
    // back to ourselves as the "authorization server" and expose the token
    // endpoint so clients know where to obtain a key.
    if (req.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource") {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        resource: `${publicUrl}/mcp`,
        resource_name: "QuantaSeal MCP Server",
        authorization_servers: [publicUrl],
        bearer_methods_supported: ["header"],
        resource_documentation: "https://quantaseal.io/mcp",
        resource_signing_alg_values_supported: [],
      }, null, 2));
      return;
    }

    // ── /.well-known/oauth-authorization-server — AS metadata ────────────────
    // Smithery follows oauth-protected-resource → authorization_servers[0] and
    // fetches this endpoint. We expose a minimal OAuth 2.0 AS that accepts
    // QuantaSeal API keys as client_credentials. registration_endpoint and
    // token_endpoint are required for Smithery's dynamic client registration flow.
    if (req.method === "GET" && url.pathname === "/.well-known/oauth-authorization-server") {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        issuer: publicUrl,
        authorization_endpoint: `${publicUrl}/authorize`,
        token_endpoint: `${publicUrl}/token`,
        registration_endpoint: `${publicUrl}/register`,
        token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
        grant_types_supported: ["authorization_code", "client_credentials"],
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        service_documentation: "https://quantaseal.io/mcp",
        ui_locales_supported: ["en"],
      }, null, 2));
      return;
    }

    // ── POST /register — RFC 7591 Dynamic Client Registration ─────────────────
    // Smithery (and MCP 2025-11-05 clients) POST here to register a client
    // before requesting a token. We return a public client with no secret —
    // the actual credential is the user's QuantaSeal API key supplied at
    // the token step as client_secret.
    if (req.method === "POST" && url.pathname === "/register") {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(201, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify({
        client_id: "quantaseal-mcp-public",
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0,
        token_endpoint_auth_method: "none",
        grant_types: ["client_credentials"],
        redirect_uris: [],
        client_name: "QuantaSeal MCP Server",
        client_uri: "https://quantaseal.io/mcp",
        logo_uri: "https://quantaseal.io/logo.svg",
        scope: "mcp",
        // Instructs the user where to obtain their API key
        client_description:
          "Use your QuantaSeal API key as the Bearer token. " +
          "Obtain one at https://app.quantaseal.io/settings/api-keys",
      }));
      return;
    }

    // ── POST /token — Authorization Code (PKCE S256) + client_credentials ─────
    if (req.method === "POST" && url.pathname === "/token") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const params = new URLSearchParams(raw);
      const grantType = params.get("grant_type") ?? "";

      const tokenHeaders = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
      };

      // ── authorization_code grant (PKCE S256) ──────────────────────────────
      if (grantType === "authorization_code") {
        const code = params.get("code") ?? "";
        const codeVerifier = params.get("code_verifier") ?? "";

        const pending = pendingCodes.get(code);
        if (!pending || pending.expiresAt < Date.now()) {
          pendingCodes.delete(code);
          res.writeHead(400, tokenHeaders);
          res.end(JSON.stringify({ error: "invalid_grant", error_description: "Code expired or not found" }));
          return;
        }

        // PKCE S256 verification
        const expectedChallenge = pkceS256(codeVerifier);
        if (!timingSafeStringEqual(expectedChallenge, pending.codeChallenge)) {
          pendingCodes.delete(code);
          res.writeHead(400, tokenHeaders);
          res.end(JSON.stringify({ error: "invalid_grant", error_description: "PKCE verification failed" }));
          return;
        }

        const accessToken = pending.apiKey;
        pendingCodes.delete(code); // single use
        res.writeHead(200, tokenHeaders);
        res.end(JSON.stringify({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 86400,
          scope: "mcp",
        }));
        return;
      }

      // ── client_credentials grant (direct API key as client_secret) ─────────
      if (grantType === "client_credentials" || grantType === "") {
        const clientSecret = params.get("client_secret") ??
          (req.headers["authorization"] ?? "").replace(/^Basic\s+/i, "");
        if (!clientSecret || clientSecret === "quantaseal-mcp-public") {
          res.writeHead(400, tokenHeaders);
          res.end(JSON.stringify({
            error: "invalid_client",
            error_description: "Provide your QuantaSeal API key as client_secret. Obtain one at https://app.quantaseal.io/settings/api-keys",
          }));
          return;
        }
        res.writeHead(200, tokenHeaders);
        res.end(JSON.stringify({
          access_token: clientSecret,
          token_type: "Bearer",
          expires_in: 86400,
          scope: "mcp",
        }));
        return;
      }

      res.writeHead(400, tokenHeaders);
      res.end(JSON.stringify({ error: "unsupported_grant_type" }));
      return;
    }

    // ── /authorize — Authorization Code + PKCE S256 ───────────────────────────
    // GET: serve an HTML form where the user enters their QuantaSeal API key.
    // POST: validate key format, issue a random auth code, redirect back with code.
    if (url.pathname === "/authorize") {
      const state = url.searchParams.get("state") ?? "";
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";
      const codeChallenge = url.searchParams.get("code_challenge") ?? "";
      const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "";

      if (req.method === "GET") {
        if (!codeChallenge || codeChallengeMethod !== "S256") {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "invalid_request", error_description: "code_challenge (S256) required" }));
          return;
        }
        // Serve the API key entry form
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>QuantaSeal MCP — Authorize</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0f;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{background:#13131f;border:1px solid #1e2a4a;border-radius:16px;padding:40px;max-width:440px;width:100%;margin:20px}
    .logo{display:flex;align-items:center;gap:10px;margin-bottom:28px}
    .logo img{height:36px;width:auto}
    .logo span{font-size:20px;font-weight:700;letter-spacing:-0.5px;color:#60a5fa}
    h1{font-size:18px;font-weight:600;margin-bottom:8px;color:#f1f5f9}
    p{font-size:14px;color:#94a3b8;margin-bottom:24px;line-height:1.6}
    a{color:#60a5fa;text-decoration:none}
    a:hover{text-decoration:underline}
    label{display:block;font-size:13px;font-weight:500;color:#cbd5e1;margin-bottom:6px}
    input[type=password]{width:100%;padding:10px 14px;background:#0d1117;border:1px solid #1e2a4a;border-radius:8px;color:#e2e8f0;font-size:14px;font-family:monospace;outline:none;transition:border-color 0.2s}
    input[type=password]:focus{border-color:#3b82f6}
    button{width:100%;margin-top:16px;padding:12px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:background 0.2s}
    button:hover{background:#2563eb}
    .hint{margin-top:16px;font-size:12px;color:#64748b;text-align:center}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <img src="https://quantaseal.io/logo-dark.svg" alt="QuantaSeal" onerror="this.src='https://quantaseal.io/logo.svg'">
    </div>
    <h1>Authorize MCP Access</h1>
    <p>Enter your QuantaSeal API key to connect the MCP server. Your key is used only to authenticate requests to the QuantaSeal API — it is never stored on this server.</p>
    <form method="POST">
      <input type="hidden" name="state" value="${escapeHtml(state)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}">
      <label for="api_key">QuantaSeal API Key</label>
      <input type="password" id="api_key" name="api_key" placeholder="qs_live_..." autocomplete="off" required>
      <button type="submit">Authorize Access</button>
    </form>
    <p class="hint">Don&apos;t have an API key? <a href="https://app.quantaseal.io/settings/api-keys" target="_blank">Get one here →</a></p>
  </div>
</body>
</html>`;
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(html);
        return;
      }

      if (req.method === "POST") {
        let raw = "";
        for await (const chunk of req) raw += chunk;
        const params = new URLSearchParams(raw);
        const apiKey = params.get("api_key")?.trim() ?? "";
        const postState = params.get("state") ?? "";
        const postRedirectUri = params.get("redirect_uri") ?? "";
        const postCodeChallenge = params.get("code_challenge") ?? "";

        if (!apiKey) {
          res.writeHead(302, { "Location": `/authorize?${url.searchParams.toString()}&error=missing_key` });
          res.end();
          return;
        }

        if (!postRedirectUri) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "invalid_request", error_description: "redirect_uri required" }));
          return;
        }

        // Issue a random short-lived auth code
        const code = randomUUID().replace(/-/g, "");
        pendingCodes.set(code, {
          codeChallenge: postCodeChallenge,
          apiKey,
          redirectUri: postRedirectUri,
          expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
        });

        const callbackUrl = new URL(postRedirectUri);
        callbackUrl.searchParams.set("code", code);
        if (postState) callbackUrl.searchParams.set("state", postState);
        res.writeHead(302, { "Location": callbackUrl.toString() });
        res.end();
        return;
      }

      res.writeHead(405, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "method_not_allowed" }));
      return;
    }

    function escapeHtml(s: string): string {
      return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
    }

    // ── /.well-known/mcp.json — agent discovery ───────────────────────────────
    if (req.method === "GET" && url.pathname === "/.well-known/mcp.json") {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        schema_version: "v1",
        name: "QuantaSeal",
        description:
          "Post-quantum cryptographic vault, encryption, compliance, and audit tools " +
          "for AI agents. ML-KEM-768 + ML-DSA-65 + AES-256-GCM.",
        icon_url: "https://quantaseal.io/logo.svg",
        mcp_endpoint: `${publicUrl}/mcp`,
        auth: {
          type: "bearer",
          instructions: "Include your QuantaSeal API key as: Authorization: Bearer qs_live_...",
          obtain_url: "https://app.quantaseal.io/settings/api-keys",
        },
        capabilities: ["tools"],
        tool_count: TOOLS.length,
      }, null, 2));
      return;
    }

    // ── /openapi.json — GPT Actions / Copilot Extensions schema ──────────────
    if (req.method === "GET" && url.pathname === "/openapi.json") {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(generateOpenApiSpec(publicUrl), null, 2));
      return;
    }

    // ── /health ───────────────────────────────────────────────────────────────
    if (req.method === "GET" && url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: "quantaseal-mcp", version: VERSION, tools: TOOLS.length }));
      return;
    }

    // ── /mcp — Streamable HTTP MCP endpoint ───────────────────────────────────
    if (url.pathname !== "/mcp") {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
      return;
    }

    // DELETE /mcp?sessionId=<id> — explicit session teardown
    if (req.method === "DELETE") {
      const sessionId = url.searchParams.get("sessionId") ?? req.headers["mcp-session-id"] as string;
      if (sessionId) sessions.delete(sessionId);
      res.writeHead(204).end();
      return;
    }

    if (req.method !== "POST" && req.method !== "GET") {
      res.writeHead(405, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Method not allowed" }));
      return;
    }

    // Parse body early — needed to check method before auth gate
    let body: Record<string, unknown> | undefined;
    if (req.method === "POST") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      if (raw) {
        try {
          body = JSON.parse(raw) as Record<string, unknown>;
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid JSON body" }));
          return;
        }
      }
    }

    // ── Stateless fast-path for MCP scanners (Smithery, Glama, etc.) ──────────
    // Scanners POST tools/list, resources/list, and prompts/list without going
    // through the full initialize → session → tools/list handshake. Respond
    // directly so they can discover capabilities without a session.
    const method = body?.method as string | undefined;
    if (method === "tools/list") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", result: { tools: TOOLS }, id: body?.id ?? null }));
      return;
    }
    if (method === "resources/list" || method === "prompts/list") {
      const key = method === "resources/list" ? "resources" : "prompts";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", result: { [key]: [] }, id: body?.id ?? null }));
      return;
    }

    // ── Auth gate — all stateful MCP operations require an API key ────────────
    const apiKey =
      extractApiKeyFromHeaders(req.headers) ??
      process.env.QUANTASEAL_API_KEY ??
      process.env.QUANTASHIELD_API_KEY;

    if (!apiKey) {
      const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
      res.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": `Bearer realm="QuantaSeal MCP", resource_metadata="${publicUrl}/.well-known/oauth-protected-resource"`,
      });
      res.end(JSON.stringify({
        error: "Missing API key. Send: Authorization: Bearer qs_live_...",
        obtain_url: "https://app.quantaseal.io/settings/api-keys",
      }));
      return;
    }

    // ── Stateful session management (full MCP protocol) ──────────────────────
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    let session = sessionId ? sessions.get(sessionId) : undefined;

    // Initialize request: always create a new session
    const isInit = body?.method === "initialize";
    if (isInit || !session) {
      if (!isInit && !session) {
        // Non-init request with no valid session — reject cleanly
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          error: { code: -32000, message: "No active session. Send initialize first." },
          id: body?.id ?? null,
        }));
        return;
      }

      const sid = randomUUID();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => sid,
      });

      const server = createServer();
      await server.connect(transport);

      session = { transport, apiKey };
      sessions.set(sid, session);
      transport.onclose = () => sessions.delete(sid);
    }

    // Run handler with this request's API key in AsyncLocalStorage
    await requestContext.run({ apiKey: session.apiKey }, () =>
      session!.transport.handleRequest(req, res, body),
    );
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, () => resolve());
  });

  const publicUrl = process.env.MCP_PUBLIC_URL ?? `http://localhost:${port}`;
  console.error(`QuantaSeal MCP server (Streamable HTTP) on http://localhost:${port}`);
  console.error(`  MCP endpoint:   ${publicUrl}/mcp`);
  console.error(`  OpenAPI spec:   ${publicUrl}/openapi.json`);
  console.error(`  Discovery:      ${publicUrl}/.well-known/mcp.json`);
  console.error(`  Health:         ${publicUrl}/health`);
  console.error(`  Tools:          ${TOOLS.length}`);
  console.error(`\nPlatform setup:`);
  console.error(`  Claude Desktop: use stdio transport instead`);
  console.error(`  GPT Actions:    import ${publicUrl}/openapi.json`);
  console.error(`  VS Code Copilot: add ${publicUrl}/mcp to mcp.servers in settings.json`);
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

  if (transportArg === "streamable-http" || transportArg === "streamable") {
    await runStreamableHttp(parseInt(portArg, 10));
  } else if (transportArg === "sse" || transportArg === "http") {
    await runSSE(parseInt(portArg, 10));
  } else {
    await runStdio();
  }
}

main().catch((err: unknown) => {
  console.error("Fatal:", err);
  process.exit(1);
});

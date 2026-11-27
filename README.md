# QuantaSeal

**Quantum-safe security middleware.** QuantaSeal sits between enterprise systems and protects what passes between them: credentials,
fields, files and API traffic are sealed with NIST post-quantum cryptography (ML-KEM and ML-DSA) combined with AES-256-GCM, under
keys that never leave per-tenant custody.

It is multi-tenant software: one deployment serves many customers, each isolated by key material, database rows and audit trail.

---

## What it does

| Capability | What you get |
|---|---|
| **Vault** | Seal and unseal credentials (API keys, OAuth tokens, certificates, DSNs, SSH keys). Optional split-key custody where the customer holds one share. TTLs and rotation. |
| **Encryption API** | Encrypt, decrypt, sign and verify arbitrary data, fields and files. Every ciphertext is signed (encrypt-then-sign). |
| **Proxy** | Bidirectional encrypted proxy to 40+ systems (Salesforce, HubSpot, Dynamics 365, SAP, Oracle, NetSuite, AWS, Azure, GCP, Kafka, PostgreSQL, Snowflake, Okta, Slack, ...) through one adapter contract. Operations are default-deny per integration. |
| **Tokenization** | Replace PII with opaque, format-preserving tokens. |
| **Managed file transfer** | Encrypted transfer with delivery receipts and write-once storage. |
| **Audit** | Every operation is written to a SHA3-256 hash chain, each entry signed with ML-DSA, with a write-once copy in object storage. |
| **Compliance evidence** | Maps the audit trail onto SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR Art. 32, NIST CSF, FedRAMP, APRA CPS 234 and NIST SP 800-53 controls and exports a PDF. It produces evidence; it is not a certification. |
| **Anomaly detection** | Every 15 minutes each tenant's own audit activity (vault unseals, encryption operations, proxy traffic, failed operations) is compared with that tenant's learned baseline (z-score). Alerts are recorded in the audit chain and served at `GET /api/v2/security/anomalies`. It watches volume and failure patterns, not content. |
| **Data map** | The proxy passively classifies the payloads that cross each integration for personal data (SSN, TFN, Medicare, card numbers, e-mail, ...) and records which categories appear in which fields. Only SHA3-256 fingerprints and counts are stored, never the matched values. |
| **Cryptographic discovery** | Scans integrations for cryptographic assets and produces a CBOM with risk scores. |
| **Crypto agility** | A tenant can move from the standard to the high-assurance profile online: keys are rotated atomically, existing data is re-encrypted in place, old keys are kept so already-issued ciphertext stays readable. |
| **Copilot** | An assistant that can list integrations, encrypt, decrypt, query the audit log and run proxy operations on the user's behalf, within the user's own permissions. |
| **Salesforce package** | Managed package: JWT-bearer authentication, field encryption, an outbound proxy service and bulk encryption. |
| **SDKs** | Python, Node.js, Go, a CLI and an MCP server (for AI agents). |

Plans (AUD per month, GST included): Starter A$69, Professional A$159, Growth A$299, White Label A$999, Enterprise by quote. All plans start
with a 14-day card-free trial that begins when the e-mail address is verified.

---

## Cryptography

Two profiles exist and nothing else is accepted. A tenant's profile is chosen at sign-up and decides which parameter sets its keys use.

| Profile | Key encapsulation | Signature | Symmetric |
|---|---|---|---|
| `standard` (default) | ML-KEM-768 (FIPS 203) | ML-DSA-65 (FIPS 204) | AES-256-GCM |
| `high_assurance` | ML-KEM-1024 | ML-DSA-87 | AES-256-GCM |

* **Hybrid, always.** Encapsulate with ML-KEM, derive the data key with HKDF-SHA-512, encrypt with AES-256-GCM, then sign. Verification
  checks the ML-DSA signature and an HMAC-SHA-512 together, with a bitwise `&` so neither check short-circuits.
* **Parameter sets are read from key length** everywhere except key generation, and mixed pairs are rejected. Decryption picks the key that
  matches the ciphertext, never "the active key", which is what makes profile upgrades safe.
* **Custody.** Secret keys are wrapped twice: an inner AES-256-GCM layer under a separately stored wrap key, then AWS KMS under a
  per-tenant encryption context. Keys larger than KMS's direct limit (ML-DSA-87) use KMS envelope encryption.
* **Wire format** (JSON). `encrypted`: `ciphertext_kem` (1088 or 1568 bytes), `ciphertext_data`, `nonce` (12 bytes), `tenant_id`,
  `algorithm`. `signature`: `pqc_signature` (3309 or 4627 bytes), `hmac_signature` (64 bytes), `tenant_id`, `algorithm`
  (`ML-DSA-65+HMAC-SHA-512` or `ML-DSA-87+HMAC-SHA-512`, which must match the KEM label).
* **Implementation.** liboqs 0.16.0 through liboqs-python. liboqs is not a FIPS 140-3 validated module; a validated module is a
  certification effort, not a configuration switch.

---

## Security model

* **Tenant isolation.** Every query filters on `tenant_id`; tenant identifiers are compared in constant time; vault errors return the same
  403 whether an entry is missing or forbidden, so existence cannot be probed.
* **No secrets in logs.** Plaintext, keys, tokens, nonces, payload/ciphertext/signature sizes and unmasked PII are never logged.
* **Traffic-analysis resistance.** Ciphertexts are padded to fixed buckets and response timing is normalised.
* **Replay protection.** In production every mutating request must carry a fresh `X-Nonce` (16-64 alphanumeric characters or hyphens);
  a reused nonce is rejected with 409. All first-party clients send one automatically.
* **Client address.** Per-IP limits and login lockout use `app/core/client_ip.py`, which believes only addresses written by proxies the
  deployment operates (`CLIENT_IP_SOURCE`, `TRUSTED_PROXY_HOPS`). A forged `X-Forwarded-For` or `X-Real-IP` is never trusted.
* **Outbound requests** to user-supplied URLs pass an SSRF check (`assert_public_url`) and are re-checked in the proxy engine.
* **Authentication.** JWT access and refresh tokens (separate secrets), optional ML-DSA token signature, API keys, passkeys (WebAuthn),
  TOTP / e-mail MFA, Salesforce JWT-bearer. Client assertions for provider logins are signed inside KMS; the private key never exists in
  process memory.
* **Data residency.** Hosted in ap-southeast-2 (Sydney) across multiple availability zones; the assistant's model calls honour a tenant's
  residency requirement. Other regions are not offered yet.
* **Row-Level Security is not the isolation mechanism.** A migration defines Postgres RLS policies, but the application's database role
  bypasses them and the tenant session variable is never set, so they do nothing today. Isolation rests on the `tenant_id` filter in every
  query and on the mandatory tenant binding in every KMS call. Enabling RLS needs a non-owner application role and a per-request tenant
  setting; until then it is not claimed.
* **Not offered:** confidential computing (an enclave decrypt path), and certification (SOC 2 report, FIPS 140-3 validation, penetration
  test report). The compliance engine gives evidence, not attestation.

---

## Repository layout

```
backend/                 FastAPI service (Python 3.12): API, crypto, vault, proxy, adapters, audit, billing, compliance
frontend/                Customer console (Next.js 15)
portal/                  Staff portal (Next.js)
website/                 Marketing site and public docs pages (Next.js)
salesforce/              Salesforce managed package (2GP, namespace quantaseal)
sdk/
  python/ node/ go/      Client libraries
  cli/                   `quantaseal` command line
  mcp/                   MCP server for AI agents
  wire-format/           Wire-format reference data
terraform-provider-quantaseal/   Terraform provider (Go)
infrastructure/
  docker-compose.yml     Local development stack
  docker-compose.ec2.yml Single-host deployment
  terraform/             AWS: VPC, KMS, RDS, ElastiCache, ECS Fargate, ALB, WAF, CloudFront, queues, buckets
  helm/                  Kubernetes charts for private deployments
  nginx/                 Reverse proxy for the single-host deployment
  scripts/               Operations (see below)
scripts/                 Repository utilities (bootstrap, smoke tests, key rotation, private deploy)
tests/load/              k6 and Locust load tests
```

Backend layout: `app/main.py` (entry and middleware), `app/config.py` (all settings; read first), `app/db/models.py` (the schema),
`app/core/pqc/` (KEM, signer, hybrid, parameter registry, profile switch), `app/core/vault.py`, `app/core/proxy_engine.py`,
`app/core/adapters/` (one file per system; adapters speak protocols, the proxy engine does cryptography, they never mix),
`app/core/kms_wrapper.py`, `app/core/audit.py`, `app/api/v2/` (routes), `app/tasks/` (Celery).

---

## Quick start (local)

Requires Docker, Node 20+, and for backend work Python 3.12 with liboqs 0.16.0 (the Docker image builds it; the first build takes 8-15 minutes).

```bash
cd infrastructure
cp .env.example .env              # fill in the secrets listed there
docker-compose up -d --build      # postgres 16 (pgvector), redis 7, localstack, backend
docker exec quantaseal-backend alembic upgrade head
curl -s http://localhost:8000/health

cd ../frontend && npm install && npm run dev     # console   http://localhost:3001
cd ../website  && npm install && npm run dev     # website   http://localhost:3000
```

API reference (Swagger) is served at `http://localhost:8000/docs`.

### SDKs

```python
from quantaseal import QuantaSeal           # pip install quantaseal

qs = QuantaSeal(api_key="qsk_live_...")      # or QUANTASEAL_API_KEY
sealed = qs.encrypt(b"hello world")
assert qs.decrypt(sealed.envelope)          # signature verified, then decrypted

entry = qs.vault.seal("crm-token", "api_key", {"key": "..."})
secret = qs.vault.unseal(entry)
```

```ts
import { QuantaSeal } from "@quantaseal/sdk";   // npm install @quantaseal/sdk

const qs = new QuantaSeal({ apiKey: process.env.QUANTASEAL_API_KEY! });
const sealed = await qs.encrypt(Buffer.from("hello world"));
const plain = await qs.decrypt(sealed.envelope);
```

Raw HTTP: send `X-API-Key` and, on every POST/PUT/PATCH/DELETE, a fresh `X-Nonce`. The MCP server (`sdk/mcp`) exposes the same
operations as tools; it reads `QUANTASEAL_API_KEY` at request time and never caches it.

---

## Configuration

All settings are in `backend/app/config.py` (pydantic-settings, environment variables). Production start-up runs
`validate_production_config()`: hard errors stop the process, warnings are logged. The ones that matter most:

| Group | Variables |
|---|---|
| Auth | `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY` (different), `HMAC_SECRET` |
| Data | `DATABASE_URL`, `REDIS_URL`, `REDIS_ENCRYPTION_KEY`, `DB_ENCRYPTION_KEY` |
| Keys | `KMS_CMK_ARN`, `KMS_PQC_WRAP_KEY` (never rotate or regenerate it once data exists), `JWT_SIGNING_BACKEND=kms` |
| Billing | `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_ID_<PLAN>` |
| Queues | `CELERY_SQS_QUEUE_URL`, `CELERY_RESULT_BACKEND` |
| Storage | `AUDIT_S3_BUCKET`, `S3_MFT_BUCKET`, `COMPLIANCE_S3_BUCKET` |
| Network | `TRUSTED_HOSTS_EXTRA`, `CLIENT_IP_SOURCE`, `TRUSTED_PROXY_HOPS` |
| Mail | `RESEND_API_KEY`, `FRONTEND_URL` |

---

## Deployment

**AWS (ECS Fargate)**: `infrastructure/terraform`. One configuration builds one environment (`environments/staging.tfvars`,
`environments/production.tfvars`); each environment has its own KMS key alias, wrap-key secret, task role, hostnames and certificate, and the
two can share an AWS account. Required inputs are not committed: the database password and Stripe keys come from `TF_VAR_*`, and
`alb_ingress_cidrs` (who may reach the load balancer) is a required variable with no default, so an environment is never opened to the
internet by omission.

Secrets that must never be regenerated once data exists are created outside Terraform and only read by it:
`quantaseal/<env>/kms-pqc-wrap-key` (`infrastructure/scripts/pqc-wrap-key-custody.sh`), `quantaseal/<env>/hmac-secret`,
`quantaseal/<env>/db-encryption-key` (`infrastructure/scripts/provision-app-secrets.sh`).

**Single host**: `infrastructure/docker-compose.ec2.yml` behind `infrastructure/nginx/nginx.conf`; `infrastructure/ec2-deploy.sh` deploys it.

**Private cloud**: the Helm chart in `infrastructure/helm/quantaseal`, driven by `scripts/deploy-private.sh`.

Operations scripts in `infrastructure/scripts`:

| Script | Purpose |
|---|---|
| `provision-prod-kms.sh` | Create the production platform key and its task role |
| `pqc-wrap-key-custody.sh`, `pqc-wrap-key-recovery-drill.sh`, `pqc_key_escrow.py` | Wrap-key custody, replication, recovery drill, Shamir escrow |
| `pg-backup.sh`, `pg-restore-test.sh` | Encrypted nightly dumps and a restore test |
| `backup-env-to-secrets-manager.sh` | Keep the single-host `.env` copy in Secrets Manager |
| `stack-smoke.py` | Black-box check of a deployed stack through its public URL |
| `ecs-oneoff.sh` | Run a short script inside a stack's own task definition and network |
| `ensure-ecr.sh`, `stripe-config-check.sh`, `production-readiness-check.sh` | Registries, Stripe configuration, readiness checks |

---

## Quality gates

```bash
cd backend
ruff check . && ruff format --check .
mypy app --strict
pytest                       # needs Postgres, Redis and LocalStack: see infrastructure/docker-compose.yml
pytest --cov=app --cov-report=term

cd frontend && npm run lint && npm run type-check && npm run build && npx playwright test
```

CI (`.github/workflows/ci.yml`) runs the backend suite against throwaway services with an overall coverage floor (55% today, 58%
measured) that is raised as tests are added and never lowered; the target is 90%, with full coverage expected for `core/pqc/`,
`core/vault.py` and the tenant middleware (not yet enforced per module). Lint and type checks are pinned to exact tool versions
(`ruff==0.17.6`, `mypy==1.20.2`, in CI and `backend/requirements*.txt`), so "green" does not change when a linter ships new rules.

---

## Engineering rules

These hold for every change.

1. **Algorithms.** Use only the two profile pairs above with AES-256-GCM, HKDF-SHA-512 and HMAC-SHA-512. Do not introduce RSA or
   elliptic-curve schemes for new key exchange or signatures, and no legacy ciphers, cipher modes or hash functions. Use `secrets` or
   `os.urandom` for randomness. Hybrid mode is mandatory; verification uses bitwise `&`.
2. **Tenancy.** Every database query has `tenant_id` in its `WHERE`; compare tenant ids and secrets with `hmac.compare_digest`.
3. **KMS.** Always construct `KMSWrapper(tenant_id=...)`; secret keys are never stored unwrapped.
4. **Logging.** Never log plaintext, keys, tokens, nonces, sizes of payloads, ciphertexts or signatures, or unmasked PII. Use structlog
   synchronously (`logger.info(...)`, no `await`).
5. **Errors.** Never put exception details in an HTTP response; keep vault errors uniform.
6. **Network.** Check user-supplied URLs with `assert_public_url`; never disable certificate verification; never trust a forwarding
   header (use `get_client_ip`).
7. **JWT.** Decode only through `decode_token(token, token_type=...)`; reject a missing PQC signature when PQC signing is enabled.
8. **SQLAlchemy JSON columns** are reassigned, never mutated in place.
9. **Schema changes** come with an Alembic migration; new endpoints use the `APIResponse[T]` envelope, tenant and permission
   dependencies, an audit entry for every mutation, and tests.
10. **One document.** This file is the only documentation in the repository. Explain operations in the header of the script that performs
    them. Do not commit personal addresses, account identifiers or credentials.

---

## Security reporting

Report vulnerabilities to **security@quantaseal.io** (PGP key and policy at `https://quantaseal.io/.well-known/security.txt`).
Please do not open public issues for security problems.

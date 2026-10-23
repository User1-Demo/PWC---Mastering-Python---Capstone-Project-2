This file summarizes the key endpoints.

## Authentication

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| POST | /api/v1/auth/login | No | Authenticate, returns JWT access token |

All other endpoints require an `Authorization: Bearer <token>` header.

## Subscriptions

| Method | Endpoint | Role | Description |
|---|---|---|---|
| GET | /api/v1/subscriptions | Any logged-in user | List registered subscriptions |
| POST | /api/v1/subscriptions | Admin | Register a new subscription |

## Policies

| Method | Endpoint | Role | Description |
|---|---|---|---|
| GET | /api/v1/policies | Any logged-in user | List policy rules |
| POST | /api/v1/policies | Admin | Create a new policy rule (validated) |

## Scans

| Method | Endpoint | Role | Description |
|---|---|---|---|
| POST | /api/v1/scans | Any logged-in user | Trigger a compliance scan |
| GET | /api/v1/scans/{scan_id} | Any logged-in user | Get scan status/result |

## Findings

| Method | Endpoint | Role | Description |
|---|---|---|---|
| GET | /api/v1/findings | Any logged-in user | List/filter findings (status, severity, subscription) |
| POST | /api/v1/findings/{id}/remediate | Any logged-in user | Request remediation (queued if high-risk) |
| POST | /api/v1/findings/{id}/approve | Security Officer | Approve a high-risk remediation |
| POST | /api/v1/findings/{id}/exception | Engineer/Officer/Admin | Mark an approved, time-bound exception |

## Audit Logs

| Method | Endpoint | Role | Description |
|---|---|---|---|
| GET | /api/v1/audit-logs | Admin | View the tamper-evident audit trail |

## Health

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| GET | /api/v1/health | No | Service health check |

## Example: Full Workflow via curl

```bash
# 1. Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin@cloudguard.io&password=Admin@123"

# 2. Trigger a scan (replace TOKEN and SUB_ID)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"subscription_id": "SUB_ID"}'

# 3. List findings
curl http://localhost:8000/api/v1/findings \
  -H "Authorization: Bearer TOKEN"
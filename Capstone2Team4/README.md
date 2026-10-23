# CloudGuard

CloudGuard is an educational Azure compliance platform. It provides a REST API and CLI to register Azure subscription metadata, define compliance rules, scan inventory, track findings, request/approve safe remediations, create time-limited exceptions, and review audit events.

This guide is intended for a new developer or tester. Follow the **Local mock walkthrough** first; it needs no Azure subscription and makes no cloud changes. Real Azure and Kubernetes deployment is optional and is covered in [docs/azure-deployment.md](docs/azure-deployment.md).

> **Important:** The local API is not a web application with forms. Swagger at `/docs` is an interactive API explorer, but you enter JSON request bodies. Roles are enumerated and validated by the API; there is not currently a role-selection dropdown UI.

## Contents

- [What is included](#what-is-included)
- [How the application behaves](#how-the-application-behaves)
- [Requirements and first-time setup](#requirements-and-first-time-setup)
- [Start, stop, and reset the local app](#start-stop-and-reset-the-local-app)
- [Role and permission reference](#role-and-permission-reference)
- [Using Swagger and authentication](#using-swagger-and-authentication)
- [Local mock walkthrough](#local-mock-walkthrough)
- [API reference and examples](#api-reference-and-examples)
- [Policy rule reference](#policy-rule-reference)
- [CLI reference](#cli-reference)
- [Environment configuration](#environment-configuration)
- [Troubleshooting](#troubleshooting)
- [Tests and quality checks](#tests-and-quality-checks)
- [Azure, Docker, and Kubernetes](#azure-docker-and-kubernetes)

## What is included

- FastAPI REST API with generated Swagger UI and OpenAPI document.
- Three application roles: `admin`, `cloud_engineer`, and `security_officer`.
- SQLite for local development; PostgreSQL is supported for shared workers/deployments.
- Mock inventory provider (the default) and an opt-in Azure SDK provider.
- Policy checks for required tags, exposed SSH/RDP NSG rules, idle VMs when CPU metrics are supplied, unattached disks, and expiring Key Vault secrets.
- Safe tag remediation when explicit tag values are configured; an opt-in NSG rule remediation that requires high-risk approval.
- Approval and rejection workflow, expiring exceptions, retry/backoff for provider failures, and hash-linked audit events.
- Typer CLI, Docker packaging, Kubernetes worker Jobs and scheduled scan CronJob, and GitHub Actions workflows.

This is a capstone MVP, not a production security product. Review the limitations in [docs/azure-deployment.md](docs/azure-deployment.md) before connecting to a real subscription.

## How the application behaves

```text
Swagger / API client / CLI
            |
   FastAPI authentication and role checks
            |
 Subscription + Policy + Scan + Finding + Approval APIs
            |
  Inline tasks locally, or separate Kubernetes Jobs
            |
 Mock provider (default), or Azure SDK (opt-in)
            |
       SQLite locally, PostgreSQL for deployment
```

The local mock provider supplies predictable sample VM, NSG, disk, and Key Vault secret metadata. A made-up subscription ID is enough for a local scan. Registering a subscription **only stores the subscription ID, display name, and environment in CloudGuard**; it does not authenticate to Azure, check that the ID exists, or grant Azure permissions.

At application startup, database tables are created, but users other than the bootstrap admin, subscriptions, and policy rules are not automatically populated. An empty `GET /api/v1/subscriptions` response (`[]`) means there are currently no subscriptions in this database. Create one before starting a scan.

## Requirements and first-time setup

You need Python 3.11 or newer. The steps below use Windows PowerShell and a project-local virtual environment.

### 1. Open the project folder

```powershell
Set-Location C:\Users\labuser.pythvm-9\Desktop\Capstone2
```

### 2. Create and activate a virtual environment

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can use the venv Python directly for every command, e.g. `.\.venv\Scripts\python.exe -m pip ...`, or allow scripts for the current PowerShell process with:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install the project

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[test,dev]"
```

`.[test,dev]` installs the application, tests/coverage, Ruff lint, and mypy type-check dependencies into `.venv`. This is the same environment used by the project validation commands.

### 4. Create local configuration

```powershell
Copy-Item .env.example .env
```

The checked-in example selects `AZURE_PROVIDER=mock`, `EXECUTION_MODE=inline`, and local SQLite. That is the correct configuration for the local walkthrough. Do not set `AZURE_PROVIDER=azure` until you have deliberately configured Azure credentials and permissions.

### 5. Create the first administrator

```powershell
cloudguard create-admin
```

Enter an email and a password of at least 12 characters when prompted. The password is hidden as you type. If the `cloudguard` command is unavailable in the active shell, run:

```powershell
python -m app.cli create-admin
```

Use the administrator credentials to log in through the API. For safety, the application does not automatically create a default user/password.

### 6. Optional: insert starter policies

```powershell
cloudguard seed-defaults
```

or:

```powershell
python -m app.cli seed-defaults
```

This creates the starter checks if they are not already present. It is safe to run again. The starter NSG policy detects public SSH/RDP exposure but does not enable remediation; create or update a policy with the explicit remediation setting described under [High-risk approval workflow](#workflow-b-high-risk-approval-and-remediation).

## Start, stop, and reset the local app

Start the API:

```powershell
python -m uvicorn app.main:app --reload
```

Open:

- Swagger UI: <http://127.0.0.1:8000/docs>
- ReDoc: <http://127.0.0.1:8000/redoc>
- OpenAPI JSON: <http://127.0.0.1:8000/openapi.json>
- Health: <http://127.0.0.1:8000/api/v1/health>

Stop the development server with **Ctrl+C** in its PowerShell window.

The default database is `cloudguard.db` in the project directory. It persists between server restarts. This explains why subscriptions and findings may still be present after restarting the server. To reset local data, stop the app and remove the local database:

```powershell
Remove-Item .\cloudguard.db
```

This permanently deletes local users, subscriptions, policies, scans, findings, remediation records, exceptions, and audit history. Do not use this against a database containing data you want to retain.

## Role and permission reference

| Role | Intended user | Allowed actions |
| --- | --- | --- |
| `admin` | Platform administrator | Create/list users; register/update subscriptions; create/update policies; trigger and view scans/findings/remediations; request and approve/reject remediation; create exceptions; view and verify audit history. |
| `cloud_engineer` | Cloud engineer | View subscriptions/policies/scans/findings/remediations; trigger scans; request supported remediation; create time-bounded exceptions. Cannot administer users/subscriptions/policies or approve high-risk actions. |
| `security_officer` | Security/compliance approver | View subscriptions/policies/scans/findings/remediations; trigger scans; request remediation; approve/reject high-risk remediation. Cannot administer users/subscriptions/policies or create exceptions. |

Unauthenticated endpoints are health and login. All other endpoints require `Authorization: Bearer <token>`. Admin is allowed to approve high-risk actions as well as the Security Officer.

The `POST /api/v1/users` role field accepts exactly these values: `admin`, `cloud_engineer`, `security_officer`. The schema is an enum in OpenAPI, so clients can discover valid values from `/openapi.json`; Swagger displays a JSON body, not an HTML dropdown. There is no separate public roles-list endpoint at this time.

## Using Swagger and authentication

1. In Swagger, expand `POST /api/v1/auth/login`.
2. Click **Try it out** and enter the admin email/password:

   ```json
   {
     "email": "admin@example.com",
     "password": "your-password"
   }
   ```

   Use the email/password you chose during `cloudguard create-admin`.

3. Click **Execute**. Copy `access_token` from the response.
4. Click the top-right **Authorize** button. Paste the token into the value field and authorize. Depending on the Swagger prompt, enter the raw token (not the word `Bearer`); Swagger adds the bearer prefix.
5. Try an authenticated endpoint such as `GET /api/v1/subscriptions`.

The token is time-limited. If an API call begins returning `401`, log in again and authorize with the new token. Use separate browser sessions/tokens to test different roles.

## Local mock walkthrough

This is the recommended first test. It uses mock data and does not require Azure.

### Step 1: Confirm health and log in

`GET /api/v1/health` should respond:

```json
{"status": "ok"}
```

Log in as the bootstrap admin as described above and authorize Swagger.

### Step 2: Register a local demo subscription

Call `POST /api/v1/subscriptions` as the admin:

```json
{
  "subscription_id": "sub-local-demo",
  "name": "Local demo",
  "environment": "dev"
}
```

Example response:

```json
{
  "id": 1,
  "subscription_id": "sub-local-demo",
  "name": "Local demo",
  "environment": "dev",
  "enabled": true
}
```

Your returned numeric `id` may not be `1`; use the actual value in subsequent requests. The outer `id` is CloudGuard's database ID, and the `subscription_id` is the provider-facing Azure subscription identifier. In mock mode, `subscription_id` can be any unique non-empty string.

Now call `GET /api/v1/subscriptions`; the registered record should appear. A successful `POST` followed by `[]` from `GET` usually means you are connected to a different database/configuration or running another project copy.

### Step 3: Add a policy

Call `POST /api/v1/policies` as the admin:

```json
{
  "name": "Required owner tag",
  "rule_type": "required_tags",
  "severity": "low",
  "parameters": {
    "required_tags": ["owner"]
  },
  "enabled": true,
  "auto_remediate": false
}
```

Expected response status: `201 Created`. Policy creation validates the rule type and parameters; an unsupported rule returns `422`.

Alternatively, run `cloudguard seed-defaults` to add the five starter policies. You can inspect them using `GET /api/v1/policies`.

### Step 4: Start a scan

Call `POST /api/v1/scans` as any authenticated role:

```json
{
  "subscription_id": 1,
  "trigger_source": "api"
}
```

Replace `1` with the subscription database ID from Step 2. `trigger_source` is optional and defaults to `api`; valid values are `api`, `cli`, and `schedule`.

The endpoint returns `202 Accepted` and a scan object. Depending on execution mode, it may initially say `queued` or `running`. In the local inline/mock setup it usually finishes quickly. Poll `GET /api/v1/scans/{scan_id}` until `status` is `completed` or `failed`.

### Step 5: Review findings

Call:

- `GET /api/v1/scans` to list scans.
- `GET /api/v1/scans/{scan_id}` to inspect one scan.
- `GET /api/v1/findings` to list findings.

Findings include the resource, rule ID, severity, title, details, and current status. The mock provider has sample:

- VM `demo-vm` with incomplete tags and low-CPU example metadata.
- NSG `demo-nsg` with a public inbound SSH rule.
- Unattached managed disk `orphan-disk`.
- Key Vault secret metadata with a near expiry date.

Only enabled policies are evaluated. Therefore, a scan may return no findings if there are no enabled policies, if the policy does not apply to the mock resource type, or if a valid exception suppresses the resource/rule.

### Step 6: Test the rest of the workflow

Continue with any of these:

- Create an engineer and security-officer account using `POST /api/v1/users`.
- Create a fully configured, low-risk tag policy and test auto-remediation.
- Create a high-risk rule, request remediation, and approve/reject it as a Security Officer.
- Create a time-limited exception for a finding and rescan.
- Inspect remediation records and audit events.

Detailed request examples follow below.

## API reference and examples

All routes below are prefixed with `/api/v1`. In Swagger, the route names are shown without manually adding the prefix to each request. Request bodies are JSON. IDs in URL paths and subscription references are integer IDs from the CloudGuard database unless specifically named `subscription_id` in the subscription record.

### Health and login

#### `GET /api/v1/health` — no login

Example:

```json
{"status": "ok"}
```

#### `POST /api/v1/auth/login` — no login

Request:

```json
{
  "email": "admin@example.com",
  "password": "your-password"
}
```

Response:

```json
{
  "access_token": "<signed-token>",
  "token_type": "bearer"
}
```

Use that token for all protected endpoints.

### User administration

Both endpoints require `admin`.

#### `GET /api/v1/users`

Returns user IDs, emails, roles, and active state. Password hashes are not returned.

#### `POST /api/v1/users`

Request:

```json
{
  "email": "engineer@example.com",
  "password": "Use-a-long-unique-password",
  "role": "cloud_engineer"
}
```

`password` must contain at least 12 characters. The role must be one of the three values above. Email is trimmed and converted to lowercase. A duplicate email returns `409 Conflict`.

Create a Security Officer by using `"role": "security_officer"`. Only an admin can create accounts; there is no public self-registration.

### Subscription management

`GET /api/v1/subscriptions` requires any authenticated role. `POST` and `PATCH` require `admin`.

#### `GET /api/v1/subscriptions`

Returns registered subscriptions, for example:

```json
[
  {
    "id": 1,
    "subscription_id": "sub-local-demo",
    "name": "Local demo",
    "environment": "dev",
    "enabled": true
  }
]
```

`[]` means none are registered in this database yet; it is not an error. Register one with POST.

#### `POST /api/v1/subscriptions`

```json
{
  "subscription_id": "sub-local-demo",
  "name": "Local demo",
  "environment": "dev"
}
```

- `subscription_id`: a unique provider subscription identifier. Use a fake label in mock mode or the actual Azure subscription GUID for live scans.
- `name`: human-readable label.
- `environment`: label such as `dev`, `staging`, or `production`; defaults to `unknown`.

Registration does not validate access to Azure. Duplicate `subscription_id` returns `409`.

#### `PATCH /api/v1/subscriptions/{subscription_pk}`

Use the subscription's numeric CloudGuard `id` in the path. Supply one or more fields:

```json
{
  "name": "Development sandbox",
  "environment": "dev",
  "enabled": true
}
```

`enabled: false` prevents new scans. It does not delete historical data. Empty updates, null values, or unknown IDs return `422`/`404`.

### Policy management

`GET /api/v1/policies` requires any authenticated role. `POST` and `PATCH` require `admin`.

#### `GET /api/v1/policies`

Returns policy definitions including their JSON parameters, `enabled` and `auto_remediate` flags.

#### `POST /api/v1/policies`

General shape:

```json
{
  "name": "Required resource tags",
  "rule_type": "required_tags",
  "severity": "low",
  "parameters": {
    "required_tags": ["owner", "environment"]
  },
  "enabled": true,
  "auto_remediate": false
}
```

Severity must be `low`, `medium`, `high`, or `critical`. See [Policy rule reference](#policy-rule-reference) for the correct parameters for each `rule_type`.

#### `PATCH /api/v1/policies/{policy_id}`

Updates supplied fields only. For example, disable a policy:

```json
{"enabled": false}
```

Changing a rule type or parameters revalidates the complete resulting policy. To enable auto-remediation, include valid `tag_values` in `parameters` and keep severity `low`. Policy names must be unique.

### Scans

All scan endpoints require authentication.

#### `POST /api/v1/scans`

```json
{
  "subscription_id": 1,
  "trigger_source": "api"
}
```

`subscription_id` here means the **numeric CloudGuard subscription record ID**, not the Azure subscription GUID string. Only enabled registered subscriptions can be scanned. An unknown or disabled record returns `404`.

The response is `202 Accepted` and contains the scan record, including its numeric `id` and status.

#### `GET /api/v1/scans`

Optional query parameters:

- `subscription_id`: numeric subscription record ID.
- `status`: scan status, e.g. `queued`, `running`, `completed`, or `failed`.
- `limit`: 1–500, default 100.
- `offset`: zero or greater, default 0.

Example: `/api/v1/scans?subscription_id=1&status=completed&limit=20`

#### `GET /api/v1/scans/{scan_id}`

Returns one scan and any `error_message`. A scan with `failed` status should be investigated before interpreting its findings as complete.

### Findings

All finding endpoints require authentication unless otherwise noted.

#### `GET /api/v1/findings`

Optional query parameters:

- `status`: finding state, e.g. `open`, `pending_approval`, `approved`, `remediated`, `exception`, or `remediation_failed`.
- `severity`: `low`, `medium`, `high`, or `critical`.
- `subscription_id`: numeric subscription record ID.
- `limit`: 1–500, default 100.
- `offset`: zero or greater, default 0.

Example: `/api/v1/findings?severity=high&status=open&subscription_id=1`

### Remediation history

#### `GET /api/v1/remediations`

Requires authentication. Optional filters:

- `finding_id`: numeric finding ID.
- `status`: e.g. `queued`, `pending_approval`, `running`, `succeeded`, `failed`, or `rejected`.
- `limit` and `offset`: same bounds as scan/finding list endpoints.

Example: `/api/v1/remediations?finding_id=5`

This endpoint reports actions; use `GET /api/v1/findings` to check the finding's current state.

### Remediation requests and approvals

#### `POST /api/v1/findings/{finding_id}/remediate`

Requires an authenticated user. The finding must have a supported remediation configured:

- A `required_tags` finding needs explicit `parameters.tag_values` for each missing tag.
- An `nsg_open_ports` finding needs high/critical severity and `parameters.remediation_action` set to `deny_exposed_rules`.

For a low-severity finding, a remediation job is queued/dispatched and applies only the declared changes. Re-running a finding already marked `remediated` returns `already_compliant` without applying changes again.

For a high/critical finding, the endpoint only creates a pending approval request; it does not change Azure immediately. The response contains:

```json
{"action_id": 3, "status": "pending_approval"}
```

Unsupported finding types return `422`. A finding already in a conflicting state returns `409`.

#### `POST /api/v1/findings/{finding_id}/approve`

Only `admin` and `security_officer` can call this endpoint. A pending high-risk request is required.

Approve:

```json
{
  "approved": true,
  "reason": "Reviewed the affected rule and approved the controlled change."
}
```

Reject:

```json
{
  "approved": false,
  "reason": "Keep the resource unchanged while the network owner investigates."
}
```

Reason is required and must be at least three characters. Approval dispatches the worker; rejection returns the finding to `open` and marks the action `rejected`. Approval and rejection are audit-logged.

### Time-limited exceptions

#### `POST /api/v1/findings/{finding_id}/exception`

Allowed for `admin` and `cloud_engineer`. This suppresses the same resource/rule from future scans until the exception expires; it does not delete the original finding or alter the Azure resource.

Request:

```json
{
  "reason": "Approved temporary waiver while the application is migrated.",
  "expires_at": "2026-12-01T00:00:00Z"
}
```

`expires_at` must include a timezone and be in the future. Remediated, remediating, pending-approval, or approved findings cannot be excepted. On a later scan after expiry, the exception is re-evaluated and the violation can appear as a new open finding.

### Audit history

Both audit endpoints require `admin`.

#### `GET /api/v1/audit-logs`

Returns newest events first. Supports `limit` (1–500, default 100) and `offset` (default 0).

#### `GET /api/v1/audit-logs/verify`

Checks the stored hash links and chain head:

```json
{"valid": true, "invalid_event_id": null}
```

If invalid, inspect the indicated event and your database integrity. The chain helps detect database edits; it is not immutable against a database administrator. Export/anchor audit records externally for stronger evidence.

## Policy rule reference

Every policy has a unique `name`, supported `rule_type`, `severity`, JSON `parameters`, and flags `enabled` and `auto_remediate`.

| `rule_type` | What it checks | Parameters |
| --- | --- | --- |
| `required_tags` | Resource is missing one or more tags, or has an empty value. | `{"required_tags": ["owner", "environment"]}`. For tag remediation, add `tag_values`, e.g. `{"required_tags":["owner"],"tag_values":{"owner":"platform"}}`. |
| `nsg_open_ports` | NSG contains an inbound allow rule from a public source (`*`, `Internet`, `0.0.0.0/0`, or `::/0`) matching blocked ports. | Optional `blocked_ports` list; defaults to `[22, 3389]`. Optional remediation action `remediation_action: "deny_exposed_rules"` enables an approval-gated high/critical action that denies the matched named rules. |
| `idle_vm` | VM has an `average_cpu_percent` value at/below the threshold. | Optional `cpu_threshold_percent`, default 5; valid 0–100. Live Azure provider does not fetch metrics by default. |
| `unattached_disk` | Managed disk property `diskState` equals `Unattached`. | No parameters required. |
| `expiring_secret` | Secret metadata expiry is within the configured time window, including already expired secrets. | Optional `days`, default 30; minimum 1. |

Example low-risk required-tag rule with explicit auto-remediation:

```json
{
  "name": "Auto-apply standard owner tag",
  "rule_type": "required_tags",
  "severity": "low",
  "parameters": {
    "required_tags": ["owner"],
    "tag_values": {
      "owner": "platform-team"
    }
  },
  "enabled": true,
  "auto_remediate": true
}
```

Automatic remediation requires all three gates: the policy is low severity; the policy has `auto_remediate: true`; and the global `AUTO_REMEDIATE_LOW_RISK` setting is enabled. It only writes the explicit `tag_values`. Never use an invented owner or environment value in a real subscription—choose values approved by your organization.

Example approval-gated NSG rule:

```json
{
  "name": "Review public SSH exposure",
  "rule_type": "nsg_open_ports",
  "severity": "high",
  "parameters": {
    "blocked_ports": [22],
    "remediation_action": "deny_exposed_rules"
  },
  "enabled": true,
  "auto_remediate": false
}
```

The NSG action only changes the identified inbound allow rule's access to `Deny`, and only after explicit approval. Validate the actual effective network configuration and impact before using a live Azure identity.

## End-to-end workflows

### Workflow A: Local scan and finding review

1. Start the app and log in as admin.
2. `POST /subscriptions` with a fake ID such as `sub-local-demo`.
3. `POST /policies` with a supported rule.
4. `POST /scans` using the returned numeric subscription record ID.
5. Poll `GET /scans/{scan_id}`; wait for `completed`.
6. Review `GET /findings`, optionally filtering by subscription, severity, or status.
7. Inspect `GET /audit-logs` as admin.

### Workflow B: High-risk approval and remediation

1. As admin, create the policy that identifies a supported high-risk remediation. For NSGs, use the example `nsg_open_ports` policy above. For a high-risk `required_tags` finding, configure `tag_values`; remediation uses those values.
2. Run a scan and identify the finding ID using `GET /findings?severity=high`.
3. As a cloud engineer or admin, call `POST /findings/{id}/remediate`. The result is `pending_approval`; no remediation has occurred yet.
4. Log in as a separate Security Officer (or admin), then call `POST /findings/{id}/approve` with `approved: true` and a meaningful reason.
5. Poll `GET /remediations?finding_id={id}` and `GET /findings?status=remediated`.
6. If rejected, submit `approved: false`; verify action status `rejected` and finding status `open`.

Use a **separate Security Officer user** to demonstrate role-based approval. Admin can also approve, so role separation is organizational practice rather than an enforced “requester cannot approve” rule in this MVP.

### Workflow C: Temporary exception

1. Scan and select an open finding.
2. As admin or cloud engineer, call `POST /findings/{id}/exception` with a reason and a future timezone-aware expiry.
3. Scan the same registered subscription again before expiry; that resource/rule is suppressed.
4. After expiry, scan again; the violation should be evaluated again and can create a new open finding.
5. Check the exception-created and exception-expired events in the audit log.

### Workflow D: Create and test a user role

1. As admin, call `POST /users` with a unique email, a password of 12+ characters, and one supported role.
2. Log in using `POST /auth/login` with the new user.
3. Authorize Swagger using that user's token.
4. Try a permitted route, then a forbidden route. A cloud engineer or security officer attempting `POST /policies` should receive `403`; a cloud engineer attempting approval should also receive `403`.

## CLI reference

Commands work from the project directory after installing the package into the active `.venv`. Prefix any command with `python -m app.cli` if the installed `cloudguard` executable is not on PATH.

| Command | Use |
| --- | --- |
| `cloudguard create-admin` | Interactively create the first admin account. Requires a unique email/password. |
| `cloudguard seed-defaults` | Insert the five starter policies if missing; safe to repeat. |
| `cloudguard scan 1` | Trigger a scan using subscription database ID `1`; replace with your ID. |
| `cloudguard schedule-all` | Create scans for every enabled subscription (used by the Kubernetes CronJob). |
| `cloudguard verify-audit` | Verify audit-chain hashes; exits with failure if invalid. |

The CLI uses the same `.env` and database as the API. If the CLI appears to operate on a different set of records, check that it is running in the project folder and uses the same `DATABASE_URL`.

## Environment configuration

Settings can be set in `.env` or environment variables. See [.env.example](.env.example). Do not commit `.env` or live credentials.

| Variable | Local default | Meaning |
| --- | --- | --- |
| `APP_ENV` | `development` | Environment label. Production requires a unique `JWT_SECRET` of 32+ characters. |
| `DATABASE_URL` | `sqlite:///./cloudguard.db` | SQLAlchemy connection URL. Use PostgreSQL for multiple API/worker replicas. |
| `JWT_SECRET` | local-only placeholder | Signing key. Replace before shared use; never publish tokens or this value. |
| `JWT_EXPIRE_MINUTES` | `60` | Bearer token lifetime in minutes. |
| `AZURE_PROVIDER` | `mock` | `mock` for local fixtures or `azure` for Azure SDK calls. |
| `EXECUTION_MODE` | `inline` | `inline` for local background execution or `kubernetes` for Job dispatch. |
| `DEFAULT_REQUIRED_TAGS` | `owner,environment,cost-center` | Required tags used by the seeded starter policy. |
| `AUTO_REMEDIATE_LOW_RISK` | `true` | Global switch in addition to explicit per-policy remediation. Disable until reviewed. |
| `REMEDIATION_MAX_RETRIES` | `3` | Maximum attempts for retryable provider errors. |
| `REMEDIATION_RETRY_BASE_SECONDS` | `1` | Exponential-backoff base delay. |
| `IDLE_CPU_THRESHOLD_PERCENT` | `5` | Threshold in the seeded idle VM rule; provider must supply CPU metrics. |
| `KEY_VAULT_EXPIRY_DAYS` | `30` | Expiry window used by the seeded Key Vault rule. |
| `WORKER_IMAGE` | `cloudguard:latest` | Image used for Kubernetes worker Jobs. Set an immutable published tag in deployments. |
| `KUBERNETES_NAMESPACE` | `cloudguard` | Namespace where worker Jobs are created. |
| `KUBERNETES_SECRET_NAME` | `cloudguard-secrets` | Existing Kubernetes Secret loaded into worker pods. |
| `KUBERNETES_SCAN_SERVICE_ACCOUNT` | `cloudguard-scan-worker` | Service account for scan jobs. |
| `KUBERNETES_REMEDIATION_SERVICE_ACCOUNT` | `cloudguard-remediation-worker` | Separate service account for remediation jobs. |

After changing `.env`, restart the server. Settings are cached within a running process.

## Troubleshooting

### `GET /subscriptions` returns `[]`

This is the expected empty state before registration. Log in as admin and call `POST /api/v1/subscriptions`. Then confirm the result with another `GET`. Registration is local metadata; it does not automatically discover subscriptions from your Azure account.

### `POST /subscriptions` returns `403`

You are likely logged in as a non-admin, or Swagger does not have your bearer token. Log in as the bootstrap admin, click **Authorize**, and retry.

### A scan returns `404 Enabled subscription not found`

The JSON field `subscription_id` in the scan request expects the subscription record's **numeric database `id`**, not the `subscription_id` string/GUID. Also make sure the subscription is enabled.

### A scan completes but has no findings

Check `GET /api/v1/policies` and make sure at least one applicable policy is enabled. `POST /api/v1/scans` does not create policies. You can run `cloudguard seed-defaults` or create one manually. Check whether a valid exception is suppressing the same resource/rule.

### Tag remediation returns `422`

The policy has to specify `parameters.tag_values` for every missing tag. For example, `required_tags: ["owner"]` needs `tag_values: {"owner":"platform-team"}`. The app does not invent a value for you.

### High-risk remediation is pending

This is expected and safe. Log in as admin or security officer and explicitly approve/reject through `POST /api/v1/findings/{id}/approve`.

### `401 Unauthorized`

The token is missing, malformed, expired, or for an inactive user. Log in again, then authorize Swagger with the fresh token.

### `403 Insufficient role`

The endpoint is working but the logged-in role is not permitted to perform that action. See [Role and permission reference](#role-and-permission-reference).

### `409 Conflict`

Common cases: duplicate user email, duplicate subscription ID, duplicate policy name, or an operation incompatible with the finding's current state. Read the response's `detail`.

### `422 Unprocessable Entity`

Usually malformed JSON, unsupported role/rule type, invalid parameters, missing remediation values, or invalid exception expiry. Check the route's request example and response `detail`.

### Data disappears or appears inconsistent between API and CLI

Verify you are in the project directory, using the same active `.venv`, `.env`, and `DATABASE_URL`. Different SQLite file paths or a second server process will use different databases. Local SQLite persists across app restarts until you explicitly delete the file.

### `cloudguard` is not recognized

Activate `.venv` again, reinstall with `python -m pip install -e ".[test,dev]"`, or run `python -m app.cli ...`.

## Tests and quality checks

Run from the project directory with the virtual environment active:

```powershell
ruff check .
mypy app
pytest --cov --cov-report=term-missing --cov-fail-under=80
```

The configured coverage scope focuses on policy evaluation and remediation. Azure SDK calls are tested with mocks; the normal test run does not require Azure credentials or make cloud changes.

## Azure, Docker, and Kubernetes

Local mode is mock + SQLite + inline execution. Do not switch to live Azure or Kubernetes mode just to try the first API flow.

For real Azure use, the Azure provider uses `DefaultAzureCredential`. The cluster configuration uses separate scan and remediation identities/service accounts so the read-only scan role can be isolated from approved writes. Key Vault scanning enumerates expiry metadata and does not read secret values. Start with a sandbox resource group, validate scans first, and only then consider the tightly scoped remediation steps.

Before deploying:

1. Read [docs/architecture.md](docs/architecture.md) for components and entity relationships.
2. Follow [docs/azure-deployment.md](docs/azure-deployment.md) for workload identity, permissions, PostgreSQL, secrets, image publishing, AKS deployment, and validation.
3. Review provider limitations and safety notes in that guide; real NSG exposure evaluation is not a complete effective-network analysis.
4. Never commit `.env`, kubeconfig, credentials, or passwords.

Optional local PostgreSQL/container run:

```powershell
docker compose up --build
```

The container setup requires Docker Desktop/the Docker engine to be running. Kubernetes manifests target an existing cluster and do not create the cluster, Azure resources, database server, or container registry.


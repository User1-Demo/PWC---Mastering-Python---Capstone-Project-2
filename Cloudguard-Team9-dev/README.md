# CloudGuard

CloudGuard is a cloud infrastructure compliance and remediation platform built with Python and FastAPI.

The MVP scans Azure-style cloud resources against compliance policies, creates findings for non-compliant resources, supports risk-based remediation workflows, and maintains an audit trail.

The current implementation uses mock Azure resource data so the full workflow can be developed and tested without requiring access to a live Azure subscription.

## Features

The CloudGuard MVP currently supports:

- Subscription management
- Compliance policy management
- On-demand compliance scans
- Required-tag validation
- Risky Network Security Group (NSG) detection
- Finding storage and filtering
- Low-risk remediation
- Approval workflow for high-risk remediation
- Audit logging
- JWT authentication
- Role-based access control
- CLI-based scanning and remediation
- PostgreSQL persistence
- Alembic database migrations
- Docker and Docker Compose
- Kubernetes deployment manifests
- GitHub Actions CI
- Automated tests with 80% coverage

---

## Architecture

```text
                      User / CLI
                          |
                          v
                       FastAPI
                          |
             +------------+------------+
             |            |            |
             v            v            v
       Subscriptions   Policies      Scans
                                       |
                                       v
                               InventoryProvider
                                /             \
                               /               \
                    MockInventoryProvider   Azure Provider
                           |                  (future)
                           v
                     Cloud Resources
                           |
                    +------+------+
                    |             |
                    v             v
               Tag Check      NSG Check
                    |             |
                    +------+------+
                           |
                           v
                       Findings
                           |
                           v
                     Remediation
                    /           \
                   v             v
              Low Risk        High Risk
                 |               |
             Automatic       Approval
                    \           /
                     +----+----+
                          |
                          v
                      Audit Log
                          |
                          v
                     PostgreSQL
```

The inventory provider separates resource collection from compliance evaluation.

The MVP currently uses `MockInventoryProvider`. A real Azure provider can later retrieve Azure resources and convert them to the same internal resource model without changing the compliance engine.

---

## Technology Stack

- Python 3.12
- FastAPI
- Pydantic
- SQLAlchemy
- PostgreSQL 16
- Alembic
- Typer
- bcrypt
- JWT / python-jose
- pytest
- pytest-cov
- Ruff
- Docker
- Docker Compose
- Kubernetes
- GitHub Actions
- Azure SDK libraries

---

## Project Structure

```text
cloudguard/
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── alembic/
│   └── versions/
│
├── k8s/
│   ├── namespace.yaml
│   ├── configmap.yaml
│   ├── secret.example.yaml
│   ├── postgres.yaml
│   ├── migration-job.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   ├── scan-job.yaml
│   └── scan-cronjob.yaml
│
├── src/
│   └── cloudguard/
│       ├── api/
│       ├── azure/
│       ├── core/
│       ├── models/
│       ├── policies/
│       ├── schemas/
│       ├── services/
│       ├── workers/
│       ├── cli.py
│       └── main.py
│
├── tests/
│   ├── fixtures/
│   └── test_*.py
├── alembic.ini
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## Local Setup

### 1. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -e ".[dev]"
```

### 3. Configure environment variables

Create `.env` based on `.env.example`.

Example:

```dotenv
APP_NAME=CloudGuard
APP_ENV=development

DATABASE_URL=postgresql+psycopg://cloudguard:cloudguard@127.0.0.1:5433/cloudguard

JWT_SECRET_KEY=<local-random-secret>
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

AZURE_SUBSCRIPTION_ID=
```

Generate a local JWT secret:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Do not commit `.env`.

---

## PostgreSQL

Start PostgreSQL:

```powershell
docker compose up -d postgres
```

Check the container:

```powershell
docker compose ps
```

CloudGuard uses PostgreSQL for local development, Docker, Kubernetes, and CI.

---

## Database Migrations

Apply all migrations:

```powershell
alembic upgrade head
```

Check the current revision:

```powershell
alembic current
```

When a SQLAlchemy model changes, generate a migration using:

```powershell
alembic revision --autogenerate -m "migration description"
```

Review generated migrations before applying them.

---

## Run the API

Start FastAPI:

```powershell
uvicorn cloudguard.main:app --reload
```

The API runs at:

[CloudGuard API](http://127.0.0.1:8000)

Swagger documentation is available at:

[CloudGuard Swagger UI](http://127.0.0.1:8000/docs)

Health endpoint:

```text
GET /api/v1/health
```

---

## Authentication and Roles

CloudGuard uses bcrypt for password hashing and JWT access tokens for authentication.

Supported roles:

```text
admin
cloud_engineer
security_officer
```

### Admin

Used for administrative operations such as subscription and policy management.

### Cloud Engineer

Can:

- Trigger scans
- View findings
- Request remediation

### Security Officer

Can:

- View findings
- View audit logs
- Approve high-risk remediation

High-risk approval uses the authenticated identity from the JWT rather than trusting an `approved_by` value supplied by the client.

---

## Compliance Checks

### Required Tags

The MVP checks whether resources contain the required:

```text
Environment
```

tag.

Example violation:

```text
Resource 'api-server-01' is missing required tag 'Environment'
```

### Risky NSG Rules

The MVP detects Azure-style Network Security Group rules that expose management ports publicly.

The current evaluator checks inbound allowed access from public sources to ports including:

```text
22
3389
```

Example:

```text
Inbound + Allow + Source * + TCP/22
```

This creates a high-severity finding.

---

## Scan Workflow

```text
Scan requested
      |
      v
Scan = running
      |
      v
Load resources
      |
      v
Load enabled policies
      |
      v
Evaluate resources
      |
      v
Create findings
      |
      v
Write audit events
      |
      v
Scan = completed
```

Scans and findings are persisted in PostgreSQL.

---

## Remediation

CloudGuard uses risk-based remediation.

### Low-Risk Finding

Example: a missing required tag.

```text
Finding
   |
   v
Remediation requested
   |
   v
Completed
   |
   v
Finding closed
```

The tag-remediation logic is idempotent, so an already compliant resource results in no additional change.

### High-Risk Finding

Example: a publicly exposed SSH rule.

```text
Finding
   |
   v
Remediation requested
   |
   v
awaiting_approval
   |
   v
Security Officer approval
   |
   v
Completed
   |
   v
Finding closed
```

---

## Audit Logging

CloudGuard stores audit events for important operations, including:

```text
scan_started
scan_completed
scan_failed
finding_created
policy_created
remediation_requested
remediation_completed
remediation_approved
```

Audit records contain:

- Event type
- Entity type
- Entity ID
- Actor
- Action
- Details
- Timestamp

---

## CLI

CloudGuard includes a Typer-based CLI.

Show available commands:

```powershell
cloudguard --help
```

Check CLI health:

```powershell
cloudguard health
```

Run a scan:

```powershell
cloudguard scan --subscription-id 1
```

View findings:

```powershell
cloudguard findings
```

View findings for a specific scan:

```powershell
cloudguard findings --scan-id 1
```

Request remediation:

```powershell
cloudguard remediate --finding-id 1
```

The CLI uses the same service layer as the REST API.

---

## Docker

Build the application:

```powershell
docker compose build
```

Start the services:

```powershell
docker compose up -d
```

Check the services:

```powershell
docker compose ps
```

The Docker Compose setup includes:

```text
PostgreSQL
Migration service
CloudGuard API
```

The migration service runs:

```text
alembic upgrade head
```

against PostgreSQL before normal application usage.

---

## Kubernetes

Kubernetes manifests are available under:

```text
k8s/
```

They include:

```text
Namespace
ConfigMap
Secret template
PostgreSQL
Migration Job
API Deployment
API Service
Scan Job
Scheduled Scan CronJob
```

The Scan Job runs:

```text
cloudguard scan --subscription-id 1
```

The intended deployment flow is:

```text
PostgreSQL
    |
    v
Migration Job
    |
    v
API Deployment
    |
    +--------+
    |        |
    v        v
Scan Job   CronJob
```

The Kubernetes manifests are implemented.

Full local runtime validation is pending because Docker Desktop became unstable while starting the local Kubernetes cluster.

---

## GitHub Actions

The GitHub Actions workflow validates CloudGuard using PostgreSQL 16.

The CI workflow performs:

```text
Checkout
   |
   v
Start PostgreSQL
   |
   v
Install dependencies
   |
   v
Ruff
   |
   v
Alembic migrations
   |
   v
pytest + coverage
   |
   v
Docker build
```

PostgreSQL is used consistently in CI rather than replacing the application database with SQLite.

---

## Testing

Run all tests:

```powershell
pytest -v
```

Run tests with coverage:

```powershell
pytest --cov=cloudguard --cov-report=term-missing
```

The MVP meets the configured:

```text
80% coverage
```

target.

Run lint checks:

```powershell
ruff check src tests
```

Core compliance and remediation logic has dedicated automated tests.

---

## Azure Integration

The MVP currently uses `MockInventoryProvider` because access to a live Azure subscription is not currently available.

The architecture supports adding a real provider later:

```text
AzureInventoryProvider
        |
        v
DefaultAzureCredential
        |
        v
Azure SDK
        |
        v
Azure Subscription
        |
        v
AzureResource objects
        |
        v
Existing compliance engine
```

Real Azure implementation should replace only the inventory-provider layer.

The following components can remain unchanged:

- Compliance evaluators
- Scan service
- Finding persistence
- Remediation workflow
- Audit logging
- API
- CLI

Real Azure remediation will additionally require suitable Azure write permissions.

---

## MVP Status

### Completed

- FastAPI API
- PostgreSQL
- SQLAlchemy
- Alembic migrations
- Subscription management
- Policy management
- Scan management
- Finding management
- Required-tag validation
- Risky NSG validation
- Mock Azure inventory
- Inventory-provider abstraction
- Low-risk remediation
- High-risk approval workflow
- Audit logging
- JWT authentication
- Role-based access control
- CLI
- Docker
- Docker Compose
- Kubernetes manifests
- GitHub Actions
- Ruff
- Automated testing
- 80% code coverage

## MVP Demo Flow

A complete MVP demonstration can follow this sequence:

1. Start PostgreSQL and CloudGuard.
2. Run Alembic migrations.
3. Open Swagger.
4. Register users and log in.
5. Register a subscription.
6. Create the required-tag policy.
7. Create the risky-NSG policy.
8. Trigger a compliance scan.
9. Review the generated findings:
   - VM missing the `Environment` tag
   - Storage account missing the `Environment` tag
   - NSG publicly exposing SSH
10. Remediate a tag finding.
11. Verify that the finding is closed.
12. Request remediation for the high-risk NSG finding.
13. Verify the `awaiting_approval` status.
14. Authenticate as a Security Officer.
15. Approve the remediation.
16. Verify that the finding is closed.
17. Review the audit trail.
18. Demonstrate the CLI.
19. Run pytest and show 80% coverage.
20. Run Ruff.
21. Demonstrate Docker Compose.
22. Show the Kubernetes manifests.
23. Show the GitHub Actions workflow.

---

## Known MVP Limitations

- Azure resources are currently represented by realistic mock fixtures.
- Real Azure inventory integration requires Azure subscription access.
- Real Azure remediation requires additional Azure permissions.
- Kubernetes manifests are implemented, but full local-cluster validation is pending.
- Authentication is appropriate for the MVP; a production deployment should integrate with an enterprise identity provider.
- Production secret management, monitoring, TLS, rate limiting, backups, and advanced operational hardening are outside the current MVP scope.

---

## Summary

CloudGuard demonstrates the cloud-compliance lifecycle:

```text
Discover resources
        |
        v
Evaluate policies
        |
        v
Create findings
        |
        v
Remediate
        |
        v
Approve high-risk changes
        |
        v
Maintain audit history
```

The MVP provides a working foundation for cloud infrastructure compliance and remediation while keeping cloud inventory collection separate from policy evaluation, allowing real Azure integration to be added later.
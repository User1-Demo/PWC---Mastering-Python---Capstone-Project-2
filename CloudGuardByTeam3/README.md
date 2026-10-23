# CloudGuardByTeam3

CloudGuard capstone: FastAPI, JWT authentication, role-based access control, users, Azure subscription metadata, policy rules, persistence, tests, Docker, and GitLab CI.

## Roles
- `ADMIN`: users, subscriptions, policies
- `CLOUD_ENGINEER`: read subscriptions/policies; future scans and remediation requests
- `SECURITY_OFFICER`: read subscriptions/policies; future approvals
- `SERVICE_ACCOUNT`: future scheduled workloads

## Local setup (PowerShell) / VS Terminal
```powershell
python -m venv venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
Copy-Item .env.example .env
python -m cloudguard.bootstrap
uvicorn cloudguard.main:app --reload
```
Open `http://127.0.0.1:8000/docs`.

## Local setup (bash)
```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
python -m cloudguard.bootstrap
uvicorn cloudguard.main:app --reload
```

## Login
Use `POST /api/v1/auth/login` with OAuth2 form fields `username` (admin email) and `password`. Select **Authorize** in Swagger and enter the same credentials.

## Tests
```bash
pytest -q
ruff check src tests
```

## PostgreSQL with Docker
```bash
cp .env.example .env
docker compose up --build
```

## Phase 2 preparation
The Azure variables are already listed in `.env.example`, but Azure inventory calls are intentionally not implemented in Phase 1. Install Phase 2 dependencies with `pip install -e ".[azure,dev]"`. Prefer `DefaultAzureCredential`; use Azure CLI login for local development or workload/managed identity in Azure. Never commit `.env` or client secrets.

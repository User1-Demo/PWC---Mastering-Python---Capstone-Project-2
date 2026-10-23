# CloudRemedy
A runnable FastAPI + PostgreSQL/SQLite + JWT/RBAC + Azure-SDK-ready compliance platform.
It covers authentication, subscription/policy management, on-demand scans, tagging and NSG checks,
low-risk remediation, high-risk approval, audit logging, a Typer CLI, and pytest mocks.
Docker, Kubernetes, and CI/CD are intentionally not included.
### Run


``bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
copy .env.example .env  # Windows; use cp on Linux/macOS
uvicorn cloudguard.main:app --reload
```

Swagger: `http://127.0.0.1:8000/docs`

Default admin values come from `.env`. Change them before shared deployment.
 
## PostgreSQL
Set `DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/cloudguard`.
Create the database first; tables are created automatically for this training MVP.

## Mock scan flow
Keep `AZURE_MODE=mock`, register a subscription, create policies, then trigger a scan.
The mock inventory contains a VM missing the `owner` tag and an NSG exposing SSH to the internet.

## Tests
```bash
pytest --cov=cloudguard --cov-report=term-missing
`
``

## CLI
```bash
CloudRemedy login admin@cloudguard.local ChangeMe123!
CloudRemedy scans
CloudRemedy trigger-scan 1
CloudRemedy findings
```

# CloudGuard

Automated Cloud Infrastructure Compliance & Remediation Platform for Azure environments.

## What It Does
- Scans Azure subscriptions for policy violations (missing tags, risky open network ports, idle resources, expiring secrets)
- Automatically fixes safe, low-risk violations
- Requires human approval before fixing high-risk violations
- Keeps a permanent, tamper-evident audit trail of every action

## Quick Start (local, fixtures only — no real Azure subscription needed)

```bash
python -m venv .venv
source .venv/bin/activate      # on Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python scripts/seed_data.py
uvicorn cloudguard.main:app --reload --app-dir src
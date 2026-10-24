import typer
import httpx
import json
from pathlib import Path

app = typer.Typer(help="CloudGuard CLI")
CONFIG_FILE = Path.home() / ".cloudguard_cli.json"


def _base_url():
    return "http://localhost:8000/api/v1"


def _save_token(token: str):
    CONFIG_FILE.write_text(json.dumps({"token": token}))


def _load_token() -> str:
    if not CONFIG_FILE.exists():
        typer.echo("Not logged in. Run `cloudguard login`.")
        raise typer.Exit(1)
    return json.loads(CONFIG_FILE.read_text())["token"]


@app.command()
def login(email: str = typer.Option(...), password: str = typer.Option(..., prompt=True, hide_input=True)):
    resp = httpx.post(f"{_base_url()}/auth/login", data={"username": email, "password": password})
    resp.raise_for_status()
    _save_token(resp.json()["access_token"])
    typer.echo("Logged in.")


@app.command()
def scan(subscription_id: str):
    token = _load_token()
    resp = httpx.post(f"{_base_url()}/scans", json={"subscription_id": subscription_id},
                       headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    typer.echo(resp.json())


@app.command()
def scan_status(scan_id: str):
    token = _load_token()
    resp = httpx.get(f"{_base_url()}/scans/{scan_id}", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    typer.echo(resp.json())


@app.command()
def findings(status: str = typer.Option(None), severity: str = typer.Option(None)):
    token = _load_token()
    params = {k: v for k, v in {"status": status, "severity": severity}.items() if v}
    resp = httpx.get(f"{_base_url()}/findings", params=params,
                      headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    for f in resp.json():
        typer.echo(f"{f['id']}  {f['severity']:<8} {f['status']:<16} {f['resource_id']}")


@app.command()
def remediate(finding_id: str):
    token = _load_token()
    resp = httpx.post(f"{_base_url()}/findings/{finding_id}/remediate",
                       headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    typer.echo(resp.json())


@app.command()
def approve(finding_id: str):
    token = _load_token()
    resp = httpx.post(f"{_base_url()}/findings/{finding_id}/approve",
                       headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    typer.echo(resp.json())


if __name__ == "__main__":
    app()
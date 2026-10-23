import json
from pathlib import Path
import httpx, typer
app=typer.Typer(help="capstone2 CLI")
BASE="http://127.0.0.1:8000/api/v1"; TOKEN_FILE=Path.home()/".cloudguard-token"
def headers(): return {"Authorization":f"Bearer {TOKEN_FILE.read_text().strip()}"}
@app.command()
def login(username:str,password:str):
    r=httpx.post(f"{BASE}/auth/login",json={"username":username,"password":password}); r.raise_for_status(); TOKEN_FILE.write_text(r.json()["access_token"]); typer.echo("Logged in")
@app.command()
def trigger_scan(subscription_id:int):
    r=httpx.post(f"{BASE}/scans",json={"subscription_id":subscription_id},headers=headers()); r.raise_for_status(); typer.echo(json.dumps(r.json(),indent=2))
@app.command()
def scans():
    r=httpx.get(f"{BASE}/scans",headers=headers()); r.raise_for_status(); typer.echo(json.dumps(r.json(),indent=2))
@app.command()
def findings():
    r=httpx.get(f"{BASE}/findings",headers=headers()); r.raise_for_status(); typer.echo(json.dumps(r.json(),indent=2))
if __name__=="__main__": app()

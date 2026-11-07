"""fwctl - operate the myfw firewall from a policy file.

    fwctl validate policies/demo.yaml          # offline: schema + semantics
    fwctl diff policies/demo.yaml              # against the active policy
    fwctl apply policies/demo.yaml --confirm-timeout 60
    fwctl verify                               # required-service probes
    fwctl confirm CHANGE_ID
    fwctl rollback
    fwctl status [--json] | history | events | diagnose ...

Exit codes: 0 ok, 1 error, 2 validation failed, 3 conflict/busy, 4 rolled back.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from typing import List, Optional

import typer

from . import client

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Policy-as-code control of the myfw kernel firewall.")
JSON = typer.Option(False, "--json", help="machine-readable output")


def out(obj, as_json: bool, text: str = "") -> None:
    if as_json:
        print(json.dumps(obj, indent=1, default=str))
    elif text:
        print(text)


def call(op: str, **args) -> dict:
    try:
        return client.call(op, **args)
    except client.AgentUnavailable as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(1)


def fail(r: dict, as_json: bool) -> None:
    if as_json:
        out(r, True)
    else:
        typer.echo(f"error ({r.get('error')}): {r.get('message')}", err=True)
        det = r.get("detail") or {}
        for f in det.get("findings", []) if isinstance(det, dict) else []:
            if f["level"] != "info":
                typer.echo(f"  [{f['level']}] {f['code']}: {f['message']}", err=True)
    code = {"invalid": 2, "conflict": 3, "pending": 3, "busy": 3, "stale": 3}.get(r.get("error"), 1)
    raise typer.Exit(code)


def ts(t) -> str:
    return dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") if t else "-"


def findings_text(v: dict) -> str:
    lines = [f"  [{f['level']}] {f['code']}: {f['message']}" for f in v["findings"]]
    head = f"valid, policy hash {v['policy_hash']}" if v["ok"] else "INVALID"
    return "\n".join([head] + lines)


@app.command()
def validate(policy: str, inventory: str = typer.Option(
        os.environ.get("MYFW_INVENTORY", "/etc/myfw/inventory.yaml"), help="inventory file"),
        live: bool = typer.Option(False, help="also check that the zone interfaces exist here"),
        as_json: bool = JSON):
    """Validate a policy offline (no agent, no kernel)."""
    from .transactions import TxnError, compile_text, load_inventory
    try:
        _, rep = compile_text(open(policy).read(), load_inventory(inventory), check_live=live)
    except TxnError as e:
        out(e.as_dict(), as_json, f"INVALID: {e}")
        raise typer.Exit(2)
    v = rep.as_dict()
    out(v, as_json, findings_text(v))
    raise typer.Exit(0 if rep.ok else 2)


@app.command()
def diff(policy: str, as_json: bool = JSON):
    """Show what applying POLICY would change (rules, NAT, defaults, flow reset)."""
    from .compiler import diff_text
    r = call("diff", policy=open(policy).read())
    if not r.get("ok"):
        fail(r, as_json)
    d = r["diff"]
    head = (f"active {d['active_hash'][:16]} -> candidate {d['candidate_hash'][:16]}"
            + ("" if d["active_known"] else "  (active policy unknown to fwctl: full listing)"))
    out(r, as_json, head + "\n" + diff_text(d))


@app.command()
def apply(policy: str,
          confirm_timeout: int = typer.Option(60, help="seconds before automatic rollback"),
          verify: bool = typer.Option(True, help="run required-service probes after the commit"),
          reason: str = typer.Option("", help="why (audit trail); default: metadata.reason"),
          as_json: bool = JSON):
    """Commit POLICY as a new generation, pending until `fwctl confirm`."""
    r = call("apply", policy=open(policy).read(), confirm_timeout=confirm_timeout, verify=verify,
             reason=reason)
    if not r.get("ok") and r.get("state") != "rolled_back":
        fail(r, as_json)
    if as_json:
        out(r, True)
        raise typer.Exit(4 if r.get("state") == "rolled_back" else 0)
    if r.get("no_op"):
        print(f"{r['change_id']}: {r['message']} (generation {r['generation']})")
    else:
        print(f"{r['change_id']}: committed generation {r['generation']} "
              f"(gate {r['gate_ns'] / 1e6:.3f} ms, {r['flows_reset']} flow(s) reset)")
        for v in r.get("verify", []):
            print(f"  {'PASS' if v['pass'] else 'FAIL'} {v['name']}: expected {v['expect']}, got "
                  f"{v['outcome']}" + (f" (server saw {v['server_saw']})" if v.get("server_saw") else ""))
        if r.get("state") == "rolled_back":
            rb = r["rollback"]
            print(f"ROLLED BACK to {rb['to_hash'][:16]} as generation {rb['generation']}: {rb['reason']}")
            raise typer.Exit(4)
        print(f"pending: confirm with `fwctl confirm {r['change_id']}` before {ts(r['deadline'])}, "
              "or it is rolled back automatically")


@app.command()
def confirm(change_id: str, as_json: bool = JSON):
    """Confirm a pending change (must still be the active generation)."""
    r = call("confirm", change_id=change_id)
    if not r.get("ok"):
        fail(r, as_json)
    out(r, as_json, f"{change_id}: confirmed (generation {r['generation']}, "
        f"hash {r['policy_hash'][:16]}) - now the last known good policy")


@app.command()
def rollback(reason: str = typer.Option("manual", help="recorded in the audit trail"),
             to: str = typer.Option("last-confirmed", help="only last-confirmed is supported"),
             as_json: bool = JSON):
    """Re-apply the last confirmed policy as a new generation."""
    if to != "last-confirmed":
        typer.echo("error: only --to last-confirmed is supported", err=True)
        raise typer.Exit(1)
    r = call("rollback", reason=reason)
    if not r.get("ok"):
        fail(r, as_json)
    out(r, as_json, f"rolled back to {r['to_hash'][:16]} as generation {r['generation']} "
        f"in {r['seconds']}s")


@app.command("verify")
def verify_(names: Optional[List[str]] = typer.Argument(None, help="probe names (default: all)"),
            record: bool = typer.Option(False, help="store the result for the metrics endpoint"),
            as_json: bool = JSON):
    """Run the access-matrix probes from the endpoint namespaces."""
    r = call("verify", names=names or [], record=record)
    if "results" not in r:
        fail(r, as_json)
    lines = [f"generation {r['generation']}"]
    for v in r["results"]:
        lines.append(f"  {'PASS' if v['pass'] else 'FAIL'} {v['name']:24} {v['from']} -> {v['to']:20} "
                     f"expect {v['expect']:5} got {v['outcome']}"
                     + (f"  [server saw {v['server_saw']}]" if v.get("server_saw") else ""))
    out(r, as_json, "\n".join(lines))
    raise typer.Exit(0 if r["ok"] else 1)


@app.command()
def status(as_json: bool = JSON):
    """Kernel generation and hash, pending change, guard, sync with the store."""
    r = call("status")
    if not r.get("ok"):
        fail(r, as_json)
    k = r["kernel"]
    lines = [
        f"generation      {k['generation']}  hash {k['policy_hash'][:16]}  label {k['label']}",
        f"managed         {'yes' if k['managed'] else 'NO (changed outside fwctl)'}; "
        f"in sync with fwctl: {'yes' if r['in_sync'] else 'NO'}",
        f"last confirmed  {(r['last_confirmed_hash'] or '-')[:16]}",
        f"default         {k['default_action']}; {k['rules']} rules, {k['nats']} NAT, {k['zones']} zones",
        f"flows           {k['conns']} / {k['max_conns']}",
        f"last commit     {ts(k['last_commit_ns'] / 1e9)} (gate {k['last_gate_ns'] / 1e6:.3f} ms, "
        f"{k['last_flows_reset']} flows reset)",
        f"guard           {'alive' if r['guard']['alive'] else 'DOWN'} "
        f"(heartbeat {r['guard']['heartbeat_age_s']}s ago)",
    ]
    p = r.get("pending")
    if p:
        lines.append(f"PENDING         {p['id']} generation {p['generation']} - rolls back at {ts(p['deadline'])}")
    out(r, as_json, "\n".join(lines))


@app.command()
def history(limit: int = 20, as_json: bool = JSON):
    """Change records (newest first)."""
    r = call("history", limit=limit)
    if not r.get("ok"):
        fail(r, as_json)
    lines = [f"{c['id']}  {ts(c['created'])}  {c['state']:11} gen {c['generation'] or '-':>5}  "
             f"{c['policy_hash'][:12]}  {c['actor']}: {c['reason'] or ''}" for c in r["changes"]]
    out(r, as_json, "\n".join(lines) or "no changes yet")


@app.command()
def events(since: int = 0, max_n: int = typer.Option(50, "--max"), as_json: bool = JSON):
    """Kernel events (sequenced; reports overwritten ranges)."""
    r = call("events", since=since, max=max_n)
    if not r.get("ok"):
        fail(r, as_json)
    lines = []
    if r.get("lost"):
        lines.append(f"({r['lost']} event(s) before seq {r['first_seq']} were overwritten)")
    for e in r["events"]:
        if e["kind"] == "packet":
            lines.append(f"{e['seq']:>7} gen {e['generation']} {e['verdict']:6} {e['proto']} "
                         f"{e['src']}:{e['sport']} -> {e['dst']}:{e['dport']} {e['reason']} {e['ref']}")
        else:
            lines.append(f"{e['seq']:>7} gen {e['generation']} {e['kind'].upper()} {e['ref']}")
    out(r, as_json, "\n".join(lines) or "no events")


@app.command()
def diagnose(from_: str = typer.Option(..., "--from", help="source endpoint (inventory name)"),
             to: str = typer.Option(..., help="destination IPv4 address"),
             port: int = typer.Option(...),
             protocol: str = typer.Option("tcp"),
             check: str = typer.Option("tcp", help="tcp or https"),
             capture: bool = typer.Option(False, help="short filtered tcpdump on the gateway"),
             as_json: bool = JSON):
    """Explain why a new connection works or fails, from evidence (root)."""
    if os.geteuid() != 0:
        typer.echo("error: diagnose runs probes inside namespaces and needs root", err=True)
        raise typer.Exit(1)
    from . import diagnose as dg
    ev = dg.diagnose(from_, to, port, protocol, check, capture)
    out(ev, as_json, dg.text(ev))
    raise typer.Exit(0 if ev["conclusion"]["confirmed"] else 1)


def main():
    app()


if __name__ == "__main__":
    main()

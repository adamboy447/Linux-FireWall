"""myfw-ops: control plane for the myfw kernel firewall.

Layers (see docs/architecture.md):
  models      policy and inventory schema (Pydantic)
  validator   semantic checks, baseline generation
  compiler    canonical policy, semantic hash, diff, kernel blob (abi)
  backend     the only place that runs uapp (fixed path, argument lists)
  state       SQLite transaction state + hash-addressed snapshots
  transactions apply / confirm / rollback / guard tick / boot restore
  agent       Unix-socket server with peer-credential checks
  guard       independent rollback guard (systemd service)
  collector   events cursor -> JSONL, metrics endpoint
  diagnose    policy prediction + live evidence
"""
__version__ = "2.0.0"

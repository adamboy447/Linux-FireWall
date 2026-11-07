"""The only module that talks to the kernel: it runs uapp.

uapp is called with a fixed executable path and an argument list (never a
shell string), always with --json, and with a timeout. Blobs are written to
a private directory and passed by path.
"""
from __future__ import annotations

import errno
import json
import os
import subprocess
import tempfile
from typing import Optional

from . import abi

UAPP = os.environ.get("MYFW_UAPP", "/usr/local/sbin/uapp")
STAGE_DIR = os.environ.get("MYFW_STAGE_DIR", "/run/myfw/stage")


class BackendError(Exception):
    def __init__(self, message: str, errnum: int = 0, kind: str = "kernel"):
        super().__init__(message)
        self.errnum = errnum
        self.kind = kind

    @property
    def conflict(self) -> bool:
        return self.errnum == errno.ESTALE


def _run(args: list[str], timeout: float = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([UAPP, "--json", *args], capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError:
        raise BackendError(f"{UAPP} not found", kind="uapp-missing") from None
    except subprocess.TimeoutExpired:
        raise BackendError(f"uapp {' '.join(args)} timed out after {timeout}s", kind="timeout") from None


def _json(args: list[str], timeout: float = 30) -> dict:
    p = _run(args, timeout)
    if p.returncode != 0 and not p.stdout.strip().startswith("{"):
        msg = (p.stderr or p.stdout).strip().removeprefix("error: ")
        kind = "module-missing" if "not loaded" in msg else "kernel"
        raise BackendError(msg or f"uapp exit {p.returncode}", kind=kind)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise BackendError(f"uapp returned invalid JSON: {p.stdout[:200]!r}") from None


def status() -> dict:
    return _json(["status"])


def counters() -> dict:
    return _json(["counters"])


def module_abi() -> dict:
    return _json(["abi"])


def check_abi() -> None:
    problems = abi.check_module_abi(module_abi())
    if problems:
        raise BackendError("ABI mismatch: " + "; ".join(problems), kind="abi")


def policy_show() -> dict:
    return _json(["policy", "show"])


def conns() -> dict:
    return _json(["conn"], timeout=60)


def events(since: int = 0, max_n: Optional[int] = None) -> dict:
    args = ["events", "--since", str(since)]
    if max_n:
        args += ["--max", str(max_n)]
    return _json(args)


def _write_blob(blob: bytes) -> str:
    os.makedirs(STAGE_DIR, mode=0o700, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="candidate-", suffix=".bin", dir=STAGE_DIR)
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    return path


def apply_blob(blob: bytes, expected_generation: int, validate_only: bool = False) -> dict:
    """Stage, kernel-validate and (unless validate_only) commit. Raises
    BackendError; .conflict is True when the generation moved meanwhile."""
    path = _write_blob(blob)
    try:
        args = ["policy", "apply", path]
        args += ["--validate-only"] if validate_only else ["--expected-gen", str(expected_generation)]
        p = _run(args, timeout=60)
        try:
            res = json.loads(p.stdout)
        except json.JSONDecodeError:
            raise BackendError((p.stderr or p.stdout).strip() or f"uapp exit {p.returncode}") from None
        if not res.get("ok"):
            raise BackendError(res.get("error", "commit failed"), res.get("errno", 0))
        return res
    finally:
        os.unlink(path)

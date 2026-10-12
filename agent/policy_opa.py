"""Bonus — PEP chạy bằng OPA (bonus/opa/lab24.rego) thay cho agent/policy.py.

Cùng interface với `agent.policy.check(context) -> (allow, reason)` để
runner có thể đổi engine mà không sửa logic. Gọi binary `opa` trong PATH
(v1.x) qua `opa eval`; principal nạp từ data/principals.json với prefix
`principals`. Fail closed: OPA thiếu, lỗi hoặc trả kết quả lạ đều là deny
kèm reason.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path

from agent.policy import PRINCIPALS_FILE, PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
REGO_FILE = BASE_DIR / "bonus" / "opa" / "lab24.rego"
OPA_TIMEOUT = 30


def opa_binary() -> str | None:
    return shutil.which("opa")


def _context_dict(context: PolicyContext) -> dict:
    values = asdict(context)
    values["agent_scopes"] = list(context.agent_scopes)
    values["parent_scopes"] = list(context.parent_scopes)
    values["egress_enabled"] = bool(context.egress_enabled)
    return values


def _deny_all(n: int, why: str) -> list[tuple[bool, str]]:
    return [(False, f"deny: PEP OPA fail closed — {why}")] * n


def check_many(contexts: list[PolicyContext]) -> list[tuple[bool, str]]:
    """Đánh giá nhiều context trong một lần gọi `opa eval` (rule `batch`)."""
    if not contexts:
        return []
    binary = opa_binary()
    if binary is None:
        return _deny_all(len(contexts), "không tìm thấy binary opa trong PATH")
    payload = json.dumps({"contexts": [_context_dict(c) for c in contexts]}, ensure_ascii=False)
    try:
        proc = subprocess.run(
            [binary, "eval", "--format", "json", "--stdin-input",
             "-d", str(REGO_FILE), "-d", f"principals:{PRINCIPALS_FILE}",
             "data.lab24.pep.batch"],
            input=payload.encode("utf-8"), capture_output=True, timeout=OPA_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _deny_all(len(contexts), f"không chạy được opa ({exc.__class__.__name__})")
    if proc.returncode != 0:
        return _deny_all(len(contexts), f"opa eval exit {proc.returncode}")
    try:
        results = json.loads(proc.stdout.decode("utf-8"))["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError):
        return _deny_all(len(contexts), "kết quả opa eval không đọc được")
    if not isinstance(results, list) or len(results) != len(contexts):
        return _deny_all(len(contexts), "số quyết định không khớp số context")

    decisions = []
    for item in results:
        allow = isinstance(item, dict) and item.get("allow") is True
        reason = str(item.get("reason", "")).strip() if isinstance(item, dict) else ""
        if not reason:
            allow, reason = False, "deny: PEP OPA fail closed — quyết định thiếu reason"
        decisions.append((allow, reason))
    return decisions


def check(context: PolicyContext) -> tuple[bool, str]:
    return check_many([context])[0]

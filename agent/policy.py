"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    return expires if expires.tzinfo is not None else None


def check(context: PolicyContext) -> tuple[bool, str]:
    tool = context.requested_tool or "<tool?>"

    # Rule tối thiểu đứng đầu: không quyền OBO nào gỡ được nó.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, (f"deny {tool}: dữ liệu restricted không được đi kèm egress "
                       "(rule tối thiểu restricted+egress)")
    if context.data_classification not in CLASSIFICATIONS:
        return False, f"deny {tool}: classification không hợp lệ {context.data_classification!r}"

    if not context.principal_id:
        return False, f"deny {tool}: thiếu principal_id (không rõ hành động thay ai)"
    principal = _load_principals().get(context.principal_id)
    if principal is None:
        return False, f"deny {tool}: principal {context.principal_id!r} không có trong data/principals.json"

    expires = _parse_expiry(context.expires_at)
    if expires is None:
        return False, f"deny {tool}: expires_at thiếu hoặc không phải ISO-8601 có timezone"
    if expires <= datetime.now(timezone.utc):
        return False, f"deny {tool}: uỷ quyền đã hết hạn lúc {context.expires_at}"

    if not context.requested_tool:
        return False, "deny: thiếu requested_tool"
    if context.delegation_depth < 0:
        return False, f"deny {tool}: delegation_depth âm"

    effective = set(principal.get("allowed_tools", ())) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective &= set(context.parent_scopes)
    if tool not in effective:
        if tool not in principal.get("allowed_tools", ()):
            missing = f"principal {context.principal_id} không có quyền {tool}"
        elif tool not in context.agent_scopes:
            missing = f"agent_scopes không gồm {tool}"
        else:
            missing = f"parent_scopes không gồm {tool} (agent con không được vượt agent cha)"
        return False, f"deny {tool}: ngoài quyền hiệu lực — {missing}"

    if context.request_purpose not in principal.get("purposes", ()):
        return False, (f"deny {tool}: purpose {context.request_purpose!r} không thuộc "
                       f"purposes của {context.principal_id}")

    return True, (f"allow {tool}: trong quyền hiệu lực của {context.principal_id} "
                  f"cho purpose {context.request_purpose!r}, classification="
                  f"{context.data_classification}, egress={context.egress_enabled}, "
                  f"hết hạn {context.expires_at}")

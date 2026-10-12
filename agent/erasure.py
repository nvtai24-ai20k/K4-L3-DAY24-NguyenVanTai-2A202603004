"""Bonus — xoá dữ liệu một khách theo yêu cầu (delete cascade), ledger vẫn verify.

Quyết định xoá đi qua cùng PEP với mọi tool (`policy.check`, tool
`erase_customer`, purpose `privacy-audit`): chỉ principal có quyền này trong
data/principals.json (`dpo`) được xoá. Cascade gồm:

  1. Xoá ticket gắn với khách qua `related_tickets` (nguồn tin cậy, cùng cách
     runner map ticket -> customer).
  2. Thay mọi định danh của khách (customer_id, tên, CCCD, SĐT, STK, email)
     còn sót trong các ticket khác bằng `[ĐÃ XOÁ]`.
  3. Xoá record khỏi customers.json (bước cuối, để chạy lại được nếu lỗi giữa chừng).

Ledger KHÔNG bị sửa: nó chỉ chứa `args_hash`, không chứa PII thô, nên chỉ cần
append thêm các dòng cascade và hash chain vẫn verify. Xoá dòng ledger nhắc
tới khách sẽ làm đứt chuỗi (xem tests/test_bonus_erasure.py).

Giới hạn: `args_hash` là sha256 không salt của args như {"customer_id": ...}.
Không gian ID nhỏ (KH-000000..999999) nên dò ngược được: đây là dữ liệu bút
danh hoá, chưa phải ẩn danh. Hệ thống thật nên dùng HMAC có khoá theo từng
chủ thể rồi huỷ khoá khi xoá (crypto-shredding). Log evidence trong
reports/ (attack-before.log) nằm ngoài phạm vi cascade.

    python -m agent.erasure KH-000999 --as dpo --customers <copy>.json --corpus <copy-dir>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, tools
from agent.policy import PolicyContext, check
from agent.runner import _TICKET_FILE_RE, AGENT_ID, DEFAULT_LEDGER_PATH

ERASE_TOOL = "erase_customer"
ERASE_PURPOSE = "privacy-audit"
REDACTED = "[ĐÃ XOÁ]"
IDENTIFIER_FIELDS = ("customer_id", "name", "cccd", "phone", "bank_account", "email")


class _ErasureRun:
    def __init__(self, principal_id: str, ledger_path: Path):
        self.principal_id = principal_id
        self.ledger_path = ledger_path
        self.run_id = f"{uuid.uuid4().hex[:12]}-erase"
        self.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")

    def log(self, tool: str, args: dict, allow: bool, reason: str) -> None:
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent_id": AGENT_ID,
            "run_id": self.run_id,
            "agent_owner": f"{AGENT_ID}/{self.run_id}",
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "purpose": ERASE_PURPOSE,
            "delegation_depth": 0,
            "tool": tool,
            "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            "classification": "restricted",
            "egress": False,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        }, self.ledger_path)


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def erase_customer(customer_id: str, principal_id: str, *, customers_file: Path | None = None,
                   corpus_dir: Path | None = None, ledger_path: Path | None = None) -> dict:
    customers_file = Path(customers_file or tools.CUSTOMERS_FILE)
    corpus_dir = Path(corpus_dir or tools.CORPUS_DIR)
    run = _ErasureRun(principal_id, Path(ledger_path or DEFAULT_LEDGER_PATH))

    allow, reason = check(PolicyContext(
        data_classification="restricted",
        request_purpose=ERASE_PURPOSE,
        agent_owner=f"{AGENT_ID}/{run.run_id}",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool=ERASE_TOOL,
        agent_scopes=(ERASE_TOOL,),
        expires_at=run.expires_at,
    ))
    run.log(ERASE_TOOL, {"customer_id": customer_id}, allow, reason)
    if not allow:
        return {"erased": False, "reason": reason}

    customers = json.loads(customers_file.read_text(encoding="utf-8"))
    target = next((c for c in customers if str(c["customer_id"]) == customer_id), None)
    if target is None:
        reason = f"deny {ERASE_TOOL}: không có {customer_id} trong {customers_file.name}, không xoá gì"
        run.log(f"{ERASE_TOOL}:lookup", {"customer_id": customer_id}, False, reason)
        return {"erased": False, "reason": reason}

    related = set(target.get("related_tickets", []))
    deleted = []
    for path in sorted(corpus_dir.glob("*.md")):
        match = _TICKET_FILE_RE.match(path.name)
        if match and int(match.group(1)) in related:
            path.unlink()
            deleted.append(path.name)
    run.log(f"{ERASE_TOOL}:delete_tickets", {"customer_id": customer_id, "files": deleted}, True,
            f"allow cascade: xoá {len(deleted)} ticket gắn với khách qua related_tickets")

    identifiers = [str(target[f]) for f in IDENTIFIER_FIELDS if target.get(f)]
    redacted = []
    for path in sorted(corpus_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        cleaned = text
        for value in identifiers:
            cleaned = cleaned.replace(value, REDACTED)
        if cleaned != text:
            _write_atomic(path, cleaned)
            redacted.append(path.name)
    run.log(f"{ERASE_TOOL}:redact_mentions", {"customer_id": customer_id, "files": redacted}, True,
            f"allow cascade: thay định danh của khách bằng {REDACTED} trong {len(redacted)} ticket khác")

    remaining = [c for c in customers if c is not target]
    _write_atomic(customers_file, json.dumps(remaining, ensure_ascii=False, indent=2) + "\n")
    run.log(f"{ERASE_TOOL}:delete_record", {"customer_id": customer_id}, True,
            f"allow cascade: xoá record khỏi {customers_file.name} ({len(customers)} -> {len(remaining)})")

    return {"erased": True, "reason": reason, "deleted_tickets": deleted,
            "redacted_tickets": redacted, "remaining_customers": len(remaining)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Delete cascade cho một khách (bonus).")
    parser.add_argument("customer_id")
    parser.add_argument("--as", dest="principal_id", required=True)
    parser.add_argument("--customers", type=Path, required=True, help="customers.json (nên dùng bản copy)")
    parser.add_argument("--corpus", type=Path, required=True, help="thư mục ticket (nên dùng bản copy)")
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER_PATH)
    args = parser.parse_args()
    report = erase_customer(args.customer_id, args.principal_id, customers_file=args.customers,
                            corpus_dir=args.corpus, ledger_path=args.ledger)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"ledger verify: {ledger.verify(args.ledger)}")


if __name__ == "__main__":
    main()

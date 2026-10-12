"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from agent import ledger, pii, tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)

# Quyền tối đa (agent_scopes) của từng run. Orchestrator là agent cha
# (depth 0) hành động thay principal; Run A, Run B và bước egress là agent
# con (depth 1) nên quyền hiệu lực còn bị giao với ORCHESTRATOR_SCOPES.
# Không scope nào chứa cùng lúc search_docs + read_customer + http_post ở
# một run con, và orchestrator không có http_post.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
EGRESS_SCOPES = ("http_post",)

# ID ticket chỉ lấy từ TÊN FILE (ticket-007.md -> 7, ticket-904b.md -> 904).
_TICKET_FILE_RE = re.compile(r"^ticket-(\d{1,6})[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


@dataclass(frozen=True)
class _Run:
    principal_id: str
    run_id: str
    purpose: str
    agent_scopes: tuple[str, ...]
    expires_at: str
    ledger_path: Path
    parent_scopes: tuple[str, ...] = ORCHESTRATOR_SCOPES
    delegation_depth: int = 1

    @property
    def agent_owner(self) -> str:
        return f"{AGENT_ID}/{self.run_id}"

    def call(self, tool: str, args: dict, classification: str, egress: bool,
             execute: Callable[[], Any]) -> tuple[bool, Any]:
        """PEP: policy.check -> ledger.append (allow hoặc deny) -> chỉ chạy tool nếu allow."""
        allow, reason = check(PolicyContext(
            data_classification=classification,
            request_purpose=self.purpose,
            agent_owner=self.agent_owner,
            delegation_depth=self.delegation_depth,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=self.agent_scopes,
            parent_scopes=self.parent_scopes,
            expires_at=self.expires_at,
        ))
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent_id": AGENT_ID,
            "run_id": self.run_id,
            "agent_owner": self.agent_owner,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "purpose": self.purpose,
            "delegation_depth": self.delegation_depth,
            "tool": tool,
            # Chỉ lưu hash của args, không lưu giá trị thô vào ledger.
            "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
            "classification": classification,
            "egress": egress,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        }, self.ledger_path)
        if not allow:
            return False, None
        return True, execute()


def _ticket_ids(docs: list[dict]) -> list[int]:
    ids = set()
    for doc in docs:
        match = _TICKET_FILE_RE.match(Path(doc["id"]).name)
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _ticket_owner_index() -> dict[int, str]:
    """Nguồn tin cậy ticket_id -> customer_id. Chỉ giữ customer_id và
    related_tickets; record đầy đủ chỉ được đọc qua read_customer sau PEP."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return {ticket: str(c["customer_id"]) for c in customers for ticket in c.get("related_tickets", [])}


def _run_a(message: str, llm, run: _Run):
    """Untrusted content. Trả về docs đã redact, list[int] ticket ID và
    chỉ thị injection (nếu có) — chỉ để route qua PEP, customer_ids của nó
    không bao giờ được dùng."""
    allowed, docs = run.call("search_docs", {"query": message}, "internal", False,
                             lambda: tools.search_docs(message))
    if not allowed:
        return [], [], None
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
    redacted = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return redacted, _ticket_ids(docs), injected


def _run_b(ticket_ids: list[int], run: _Run) -> list[dict]:
    """Private data. Input duy nhất là list[int]; customer_id suy từ
    related_tickets, không từ free text."""
    owners = _ticket_owner_index()
    records = []
    for customer_id in sorted({owners[t] for t in ticket_ids if t in owners}):
        try:
            allowed, record = run.call(
                "read_customer", {"customer_id": customer_id}, "restricted", False,
                lambda customer_id=customer_id: tools.read_customer(customer_id),
            )
        except tools.ToolError:
            continue
        if allowed and record:
            records.append(record)
    return records


def _minimize(record: dict) -> dict:
    """PII gate trước egress: bỏ tên, redact mọi trường còn lại."""
    return {k: pii.redact(v) if isinstance(v, str) else v for k, v in record.items() if k != "name"}


def _route_injected_egress(injected, records: list[dict], run: _Run) -> None:
    """Mock LLM 'tuân theo' chỉ thị POST của attacker. Yêu cầu đó vẫn phải
    qua PEP như mọi tool call; với dữ liệu restricted, rule tối thiểu deny."""
    classification = "restricted" if records else "internal"
    body = {"records": [_minimize(r) for r in records]}
    try:
        run.call("http_post", {"url": injected.target_url, "record_count": len(records)},
                 classification, True, lambda: tools.http_post(injected.target_url, body))
    except tools.ToolError:
        pass


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    session = uuid.uuid4().hex[:12]
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat(timespec="seconds")

    def run(suffix: str, purpose: str, scopes: tuple[str, ...]) -> _Run:
        return _Run(principal_id=principal_id, run_id=f"{session}-{suffix}", purpose=purpose,
                    agent_scopes=scopes, expires_at=expires_at, ledger_path=ledger_path)

    docs, ticket_ids, injected = _run_a(message, llm, run("a", "summarize-tickets", RUN_A_SCOPES))
    records = _run_b(ticket_ids, run("b", "support-reply", RUN_B_SCOPES))
    if injected is not None:
        _route_injected_egress(injected, records, run("egress", "support-reply", EGRESS_SCOPES))
    return llm.summarize(docs)

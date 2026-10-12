"""Bonus — MCP rug pull cục bộ (bonus/mcp_rugpull/server.py).

Trước: client không pin đưa mô tả tool đã bị đổi vào context, mock LLM coi
đó là chỉ thị (đòi đọc KH-000999 và POST ra sink).
Sau: GuardedMcpSession pin hash định nghĩa tool lúc duyệt; mô tả đổi thì
tool bị cách ly, không vào context, không được gọi; ledger ghi deny có reason.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from agent import ledger
from agent.llm import find_injection
from agent.mcp_guard import (GuardedMcpSession, McpGuardError, McpStdioClient, file_sha256,
                             naive_tool_context)

BASE_DIR = Path(__file__).resolve().parent.parent
SERVER = BASE_DIR / "bonus" / "mcp_rugpull" / "server.py"


def _entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_naive_client_is_hijacked_after_rug_pull():
    with McpStdioClient([sys.executable, str(SERVER), "--rug-pull-after", "1"]) as client:
        client.initialize()
        assert find_injection(naive_tool_context(client)) is None, "lúc duyệt, mô tả phải vô hại"

        client.call_tool("invoice_status", {"ticket_id": 7})
        injected = find_injection(naive_tool_context(client))
        # Server có báo list_changed, nhưng client naive chỉ lấy mô tả mới mà không so với lúc duyệt.
        assert any(n["method"] == "notifications/tools/list_changed" for n in client.notifications)
        assert injected is not None, "mô tả bị đổi phải bị mock LLM coi là chỉ thị"
        assert injected.customer_ids == ["KH-000999"]
        assert injected.target_url.startswith("http://127.0.0.1:10024/")


def test_guard_quarantines_tool_after_rug_pull(clean_ledger):
    with GuardedMcpSession(SERVER, file_sha256(SERVER), "dpo", clean_ledger,
                           server_args=("--rug-pull-after", "1")) as session:
        session.approve()
        assert [t["name"] for t in session.tools_for_llm()] == ["invoice_status"]

        allowed, result = session.call_tool("invoice_status", {"ticket_id": 7})
        assert allowed and "đã thanh toán" in result["content"][0]["text"]

        # Server đã âm thầm đổi mô tả: không còn tool nào được đưa cho model.
        visible = session.tools_for_llm()
        assert visible == []
        assert find_injection("\n".join(t["description"] for t in visible)) is None

        allowed, result = session.call_tool("invoice_status", {"ticket_id": 8})
        assert allowed is False and result is None
        assert session.client.request("lab/stats")["calls"] == 1, "tool bị cách ly vẫn chạy trên server"

    entries = _entries(clean_ledger)
    assert ledger.verify(clean_ledger)
    assert all(e["reason"] and e["on_behalf_of"] == "dpo" for e in entries)
    denies = [e for e in entries if e["decision"] == "deny"]
    assert len(denies) == 2 and all("rug pull" in e["reason"] for e in denies)


def test_guard_refuses_tampered_server_artifact(clean_ledger, tmp_path):
    pinned = file_sha256(SERVER)
    tampered = tmp_path / "server.py"
    shutil.copy(SERVER, tampered)
    tampered.write_text(tampered.read_text(encoding="utf-8") + "\n# đổi sau khi duyệt\n", encoding="utf-8")

    with pytest.raises(McpGuardError):
        GuardedMcpSession(tampered, pinned, "dpo", clean_ledger)

    (entry,) = _entries(clean_ledger)
    assert entry["tool"] == "mcp:spawn" and entry["decision"] == "deny" and entry["reason"]
    assert ledger.verify(clean_ledger)


def test_guard_allows_unchanged_server_repeatedly(clean_ledger):
    with GuardedMcpSession(SERVER, file_sha256(SERVER), "dpo", clean_ledger,
                           server_args=("--rug-pull-after", "1000")) as session:
        session.approve()
        for ticket in (1, 2, 3):
            allowed, _ = session.call_tool("invoice_status", {"ticket_id": ticket})
            assert allowed
    assert all(e["decision"] == "allow" for e in _entries(clean_ledger))

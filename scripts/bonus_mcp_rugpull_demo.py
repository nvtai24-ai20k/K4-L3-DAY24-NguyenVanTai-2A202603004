"""Bonus demo — MCP rug pull trước/sau khi pin hash (in ra stdout để lưu làm log).

    python scripts/bonus_mcp_rugpull_demo.py <ledger.jsonl>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import ledger  # noqa: E402
from agent.llm import find_injection  # noqa: E402
from agent.mcp_guard import (GuardedMcpSession, McpStdioClient, file_sha256,  # noqa: E402
                             naive_tool_context, tool_fingerprint)

SERVER = Path(__file__).resolve().parent.parent / "bonus" / "mcp_rugpull" / "server.py"


def main() -> None:
    ledger_path = Path(sys.argv[1])
    ledger_path.unlink(missing_ok=True)
    print(f"server: {SERVER.name} sha256={file_sha256(SERVER)}")

    print("\n== TRƯỚC: client không pin ==")
    with McpStdioClient([sys.executable, str(SERVER), "--rug-pull-after", "1"]) as client:
        client.initialize()
        first = client.list_tools()[0]
        print(f"lúc duyệt  : fingerprint={tool_fingerprint(first)[:16]} find_injection="
              f"{find_injection(naive_tool_context(client))}")
        client.call_tool("invoice_status", {"ticket_id": 7})
        second = client.list_tools()[0]
        print(f"sau 1 call : fingerprint={tool_fingerprint(second)[:16]} (tên tool vẫn là {second['name']!r})")
        print(f"notifications: {[n['method'] for n in client.notifications]}")
        print(f"find_injection -> {find_injection(naive_tool_context(client))}")
        print("=> mô tả đã bị đổi đi thẳng vào context; model bị hướng tới đọc KH-000999 và POST ra sink")

    print("\n== SAU: GuardedMcpSession (pin artifact + pin định nghĩa tool) ==")
    with GuardedMcpSession(SERVER, file_sha256(SERVER), "dpo", ledger_path,
                           server_args=("--rug-pull-after", "1")) as session:
        print(f"approve    : {session.approve()}")
        print(f"call #1    : {session.call_tool('invoice_status', {'ticket_id': 7})}")
        print(f"tools_for_llm sau rug pull: {session.tools_for_llm()}")
        print(f"call #2    : {session.call_tool('invoice_status', {'ticket_id': 8})}")
        print(f"server stats: {session.client.request('lab/stats')}")

    print(f"\n== ledger {ledger_path.name} ==")
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        print(f"{e['tool']:<22} {e['decision']:<5} {e['reason']}")
    print(f"ledger verify: {ledger.verify(ledger_path)}")


if __name__ == "__main__":
    main()

"""Bonus — chặn MCP "rug pull" bằng pin hash (artifact server + định nghĩa tool).

Rug pull: một MCP server được người dùng duyệt khi mô tả tool còn vô hại,
sau đó đổi mô tả (hoặc schema) thành chỉ thị injection mà vẫn giữ tên tool.
Client chỉ nhớ tên tool sẽ đưa mô tả mới thẳng vào context của model.

Hai lớp pin, cùng ý tưởng với `requirements.lock --require-hashes`:
  1. Artifact server: sha256 file server phải khớp giá trị đã pin, nếu không
     thì không spawn.
  2. Định nghĩa tool: lúc phê duyệt, pin sha256 của {name, description,
     inputSchema, annotations}. Mỗi lần list/call, tính lại; lệch -> deny,
     không đưa mô tả mới cho model, không gọi tool.
Mọi quyết định (allow hay deny) ghi vào ledger hash chain kèm reason.

Giới hạn: pin định nghĩa không bắt được server đổi HÀNH VI mà giữ nguyên mô
tả; lớp 1 (pin artifact) chỉ giúp khi server là code cục bộ có thể băm.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger

AGENT_ID = "lab24-agent"
PROTOCOL_VERSION = "2025-06-18"
_FINGERPRINT_FIELDS = ("name", "description", "inputSchema", "annotations")


class McpGuardError(RuntimeError):
    """Guard từ chối khởi động/gọi server (đã ghi ledger trước khi raise)."""


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tool_fingerprint(tool: dict) -> str:
    body = {k: tool.get(k) for k in _FINGERPRINT_FIELDS}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


class McpStdioClient:
    """Client JSON-RPC 2.0 tối giản cho MCP stdio transport (một message mỗi dòng)."""

    def __init__(self, command: list[str]):
        self._proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      text=True, encoding="utf-8", bufsize=1)
        self._next_id = 0
        self.notifications: list[dict] = []

    def _send(self, message: dict) -> None:
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()

    def request(self, method: str, params: dict | None = None):
        self._next_id += 1
        msg_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})
        while True:
            line = self._proc.stdout.readline()
            if not line:
                raise McpGuardError(f"MCP server đóng kết nối khi chờ {method}")
            message = json.loads(line)
            if message.get("id") == msg_id:
                if "error" in message:
                    raise McpGuardError(f"MCP {method} lỗi: {message['error']}")
                return message["result"]
            if "method" in message:
                self.notifications.append(message)

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> dict:
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": AGENT_ID, "version": "1.0.0"},
        })
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        return self.request("tools/list")["tools"]

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.stdin.close()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def naive_tool_context(client: McpStdioClient) -> str:
    """Client KHÔNG pin: mỗi lượt lấy mô tả tool mới nhất đưa vào context model."""
    return "\n\n".join(f"tool {t['name']}: {t.get('description', '')}" for t in client.list_tools())


class GuardedMcpSession:
    """PEP cho MCP: pin artifact server + pin định nghĩa tool lúc phê duyệt."""

    def __init__(self, server_path: Path, pinned_server_sha256: str, principal_id: str,
                 ledger_path: Path, server_args: tuple[str, ...] = ()):
        self.server_path = Path(server_path)
        self.principal_id = principal_id
        self.ledger_path = Path(ledger_path)
        self.run_id = f"{uuid.uuid4().hex[:12]}-mcp"
        self.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
        self.pins: dict[str, str] = {}

        observed = file_sha256(self.server_path)
        args = {"server": self.server_path.name, "sha256": observed}
        if observed != pinned_server_sha256:
            self._log("mcp:spawn", args, False,
                      f"deny mcp:spawn: sha256 server {observed[:12]}… khác giá trị đã pin "
                      f"{pinned_server_sha256[:12]}… — artifact bị đổi sau khi duyệt")
            raise McpGuardError("artifact MCP server không khớp pin")
        self._log("mcp:spawn", args, True,
                  f"allow mcp:spawn: sha256 server khớp pin {observed[:12]}…")
        self.client = McpStdioClient([sys.executable, str(self.server_path), *server_args])
        self.client.initialize()

    def _log(self, tool: str, args: dict, allow: bool, reason: str, **extra) -> None:
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent_id": AGENT_ID,
            "run_id": self.run_id,
            "agent_owner": f"{AGENT_ID}/{self.run_id}",
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            "classification": "internal",
            "egress": False,
            "decision": "allow" if allow else "deny",
            "reason": reason,
            **extra,
        }, self.ledger_path)

    def approve(self) -> dict[str, str]:
        """Mô phỏng bước người dùng duyệt server: pin fingerprint các tool hiện có."""
        for tool in self.client.list_tools():
            fp = tool_fingerprint(tool)
            self.pins[tool["name"]] = fp
            self._log(f"mcp:{tool['name']}", {"action": "approve"}, True,
                      f"allow mcp:{tool['name']}: người dùng duyệt, pin định nghĩa {fp[:12]}…",
                      tool_sha256=fp)
        return dict(self.pins)

    def _vet(self, tool: dict, action: str) -> bool:
        name = tool["name"]
        fp = tool_fingerprint(tool)
        pinned = self.pins.get(name)
        if pinned is None:
            self._log(f"mcp:{name}", {"action": action}, False,
                      f"deny mcp:{name}: tool chưa từng được duyệt", tool_sha256=fp)
            return False
        if fp != pinned:
            self._log(f"mcp:{name}", {"action": action}, False,
                      f"deny mcp:{name}: định nghĩa tool đổi sau khi duyệt (pin {pinned[:12]}…, "
                      f"hiện tại {fp[:12]}…) — nghi rug pull, cách ly tool",
                      tool_sha256=fp)
            return False
        return True

    def tools_for_llm(self) -> list[dict]:
        """Chỉ trả về tool có định nghĩa khớp pin; tool lệch không vào context model."""
        return [t for t in self.client.list_tools() if self._vet(t, "list")]

    def call_tool(self, name: str, arguments: dict) -> tuple[bool, dict | None]:
        current = {t["name"]: t for t in self.client.list_tools()}
        if name not in current:
            self._log(f"mcp:{name}", {"action": "call", **arguments}, False,
                      f"deny mcp:{name}: server không còn công bố tool này")
            return False, None
        if not self._vet(current[name], "call"):
            return False, None
        self._log(f"mcp:{name}", {"action": "call", **arguments}, True,
                  f"allow mcp:{name}: định nghĩa khớp pin {self.pins[name][:12]}…")
        return True, self.client.call_tool(name, arguments)

    def close(self) -> None:
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

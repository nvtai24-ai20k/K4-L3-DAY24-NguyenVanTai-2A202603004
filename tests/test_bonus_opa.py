"""Bonus — policy port sang OPA (bonus/opa/lab24.rego).

1. Parity: cùng một lưới PolicyContext, agent/policy.py và OPA phải ra
   đúng cùng (allow, reason).
2. End-to-end: runner dùng PEP OPA thay cho policy.py vẫn chặn rò rỉ và vẫn
   phục vụ dpo hợp lệ.

SKIP nếu `opa` không có trong PATH (bonus, không thuộc phần bắt buộc).
"""
from __future__ import annotations

import itertools
import json
import random
import subprocess
from pathlib import Path

import pytest

from agent import ledger, policy, policy_opa, runner, tools
from agent.loop import run_once
from agent.policy import PolicyContext
from sink.sink import REPORTS_DIR

pytestmark = pytest.mark.skipif(policy_opa.opa_binary() is None, reason="opa không có trong PATH")

BASE_DIR = Path(__file__).resolve().parent.parent
QUERY = "Tổng hợp các ticket còn mở tuần này"
SINK_LOG_PATH = REPORTS_DIR / "sink.log"

FUTURE = "2099-01-01T00:00:00+00:00"
PAST = "2000-01-01T00:00:00+00:00"


def _grid() -> list[PolicyContext]:
    axes = dict(
        data_classification=["public", "internal", "restricted", "secret"],
        request_purpose=["support-reply", "summarize-tickets", "billing-reconciliation", "privacy-audit", "x"],
        delegation_depth=[0, 1, -1],
        egress_enabled=[False, True],
        principal_id=["support_l1", "billing", "dpo", "nobody", ""],
        requested_tool=["search_docs", "read_customer", "http_post", ""],
        agent_scopes=[(), ("search_docs",), ("read_customer",), ("http_post",),
                      ("search_docs", "read_customer")],
        parent_scopes=[(), ("search_docs",), ("search_docs", "read_customer")],
        expires_at=[FUTURE, PAST, "not-a-date", "", "2099-01-01T00:00:00Z"],
    )
    names = list(axes)
    rows = [dict(zip(names, values))
            for values in random.Random(24).sample(list(itertools.product(*axes.values())), 3000)]
    # Thêm đủ các tổ hợp quan trọng nhất (principal × tool × classification × egress)
    # với scope rộng và TTL hợp lệ, để nhánh allow được phủ kỹ.
    for cls, egress, pid, tool in itertools.product(
            axes["data_classification"], [False, True], axes["principal_id"], axes["requested_tool"]):
        rows.append(dict(data_classification=cls, request_purpose="support-reply", delegation_depth=1,
                         egress_enabled=egress, principal_id=pid, requested_tool=tool,
                         agent_scopes=("search_docs", "read_customer", "http_post"),
                         parent_scopes=("search_docs", "read_customer"), expires_at=FUTURE))
    return [PolicyContext(agent_owner="lab24-agent/grid", **row) for row in rows]


def test_opa_unit_tests_pass():
    proc = subprocess.run(
        [policy_opa.opa_binary(), "test", str(BASE_DIR / "bonus" / "opa"),
         f"principals:{policy.PRINCIPALS_FILE}"],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_opa_matches_python_policy_on_grid():
    contexts = _grid()
    expected = [policy.check(c) for c in contexts]
    actual = policy_opa.check_many(contexts)
    mismatches = [(c, e, a) for c, e, a in zip(contexts, expected, actual) if e != a]
    assert not mismatches, f"{len(mismatches)}/{len(contexts)} lệch, ví dụ: {mismatches[:3]}"
    assert all(reason for _, reason in actual)
    assert any(allow for allow, _ in actual) and not all(allow for allow, _ in actual)


def test_opa_fails_closed_without_binary(monkeypatch):
    monkeypatch.setattr(policy_opa, "opa_binary", lambda: None)
    allow, reason = policy_opa.check(PolicyContext(
        data_classification="internal", request_purpose="summarize-tickets",
        agent_owner="x", delegation_depth=0, egress_enabled=False, principal_id="dpo",
        requested_tool="search_docs", agent_scopes=("search_docs",), expires_at=FUTURE))
    assert allow is False and "fail closed" in reason


@pytest.mark.parametrize("principal", ["support_l1", "dpo"])
def test_runner_with_opa_engine_blocks_exfil(principal, clean_sink, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "check", policy_opa.check)
    reads: list[str] = []
    real_read = tools.read_customer

    def spy(customer_id, *args, **kwargs):
        reads.append(customer_id)
        return real_read(customer_id, *args, **kwargs)

    monkeypatch.setattr(tools, "read_customer", spy)

    run_once(QUERY, mock=True, log_dir=tmp_path, principal_id=principal)

    sink_log = SINK_LOG_PATH.read_text(encoding="utf-8") if SINK_LOG_PATH.exists() else ""
    assert sink_log.strip() == "", f"sink nhận dữ liệu khi dùng PEP OPA: {sink_log!r}"
    path = tmp_path / "ledger.jsonl"
    entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert ledger.verify(path)
    assert any(e["tool"] == "http_post" and e["decision"] == "deny" for e in entries)
    if principal == "support_l1":
        assert not reads
    else:
        assert "KH-000999" in reads, "dpo phải vẫn đọc được khách gắn với ticket"

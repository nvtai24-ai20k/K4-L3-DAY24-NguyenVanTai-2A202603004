"""Bonus — delete cascade (agent/erasure.py) giữ ledger verify.

Mọi thao tác chạy trên BẢN COPY của data/customers.json và corpus/ trong
tmp_path; dữ liệu gốc của repo không bị đụng tới.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from agent import ledger, tools
from agent.erasure import IDENTIFIER_FIELDS, REDACTED, erase_customer
from agent.loop import run_once

BASE_DIR = Path(__file__).resolve().parent.parent
QUERY = "Tổng hợp các ticket còn mở tuần này"
SUBJECT = "KH-000999"


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Copy customers.json + corpus/ và trỏ tools sang bản copy (runner đọc qua tools)."""
    customers = tmp_path / "customers.json"
    corpus = tmp_path / "corpus"
    shutil.copy(BASE_DIR / "data" / "customers.json", customers)
    shutil.copytree(BASE_DIR / "corpus", corpus)
    record = next(c for c in json.loads(customers.read_text(encoding="utf-8")) if c["customer_id"] == SUBJECT)
    # Một ticket KHÔNG nằm trong related_tickets nhưng có nhắc SĐT của khách.
    (corpus / "ticket-050.md").write_text(
        f"# Ticket #050 — gọi lại\n\nKhách để lại số {record['phone']} nhờ gọi lại.\n", encoding="utf-8")
    monkeypatch.setattr(tools, "CUSTOMERS_FILE", customers)
    monkeypatch.setattr(tools, "CORPUS_DIR", corpus)
    return {"customers": customers, "corpus": corpus, "ledger": tmp_path / "logs" / "ledger.jsonl",
            "record": record}


def _identifiers(record: dict) -> list[str]:
    return [str(record[f]) for f in IDENTIFIER_FIELDS if record.get(f)]


def _reads(monkeypatch) -> list[str]:
    seen: list[str] = []
    real_read = tools.read_customer

    def spy(customer_id, *args, **kwargs):
        seen.append(customer_id)
        return real_read(customer_id, *args, **kwargs)

    monkeypatch.setattr(tools, "read_customer", spy)
    return seen


def test_dpo_erasure_cascades_and_ledger_still_verifies(sandbox, clean_sink, monkeypatch):
    seen = _reads(monkeypatch)
    log_dir = sandbox["ledger"].parent
    run_once(QUERY, mock=True, log_dir=log_dir, principal_id="dpo")
    assert SUBJECT in seen, "trước khi xoá, dpo đọc được khách gắn ticket 901–904"
    before = len(sandbox["ledger"].read_text(encoding="utf-8").splitlines())

    report = erase_customer(SUBJECT, "dpo", customers_file=sandbox["customers"],
                            corpus_dir=sandbox["corpus"], ledger_path=sandbox["ledger"])

    assert report["erased"] is True
    assert set(report["deleted_tickets"]) == {"ticket-901.md", "ticket-902.md", "ticket-903.md",
                                              "ticket-904.md", "ticket-904b.md"}
    assert report["redacted_tickets"] == ["ticket-050.md"]
    assert REDACTED in (sandbox["corpus"] / "ticket-050.md").read_text(encoding="utf-8")

    customers_text = sandbox["customers"].read_text(encoding="utf-8")
    corpus_text = "".join(p.read_text(encoding="utf-8") for p in sandbox["corpus"].glob("*.md"))
    for value in _identifiers(sandbox["record"]):
        assert value not in customers_text and value not in corpus_text, f"còn sót {value!r}"

    # Ledger: chuỗi cũ giữ nguyên, chỉ append; vẫn verify.
    assert ledger.verify(sandbox["ledger"])
    lines = sandbox["ledger"].read_text(encoding="utf-8").splitlines()
    assert len(lines) == before + 4
    entries = [json.loads(line) for line in lines]
    assert [e["tool"] for e in entries[before:]] == [
        "erase_customer", "erase_customer:delete_tickets",
        "erase_customer:redact_mentions", "erase_customer:delete_record"]

    # Sau khi xoá, runner không còn đường nào tới khách này.
    seen.clear()
    run_once(QUERY, mock=True, log_dir=log_dir, principal_id="dpo")
    assert SUBJECT not in seen and seen, "dpo vẫn phải đọc được các khách hợp lệ khác"
    assert ledger.verify(sandbox["ledger"])
    ledger_text = sandbox["ledger"].read_text(encoding="utf-8")
    for value in _identifiers(sandbox["record"])[1:]:  # bỏ customer_id; còn lại là PII thô
        assert value not in ledger_text, "ledger không được chứa PII thô"


def test_support_l1_cannot_erase(sandbox):
    snapshot = {p.name: p.read_bytes() for p in sandbox["corpus"].glob("*.md")}
    customers_before = sandbox["customers"].read_bytes()

    report = erase_customer(SUBJECT, "support_l1", customers_file=sandbox["customers"],
                            corpus_dir=sandbox["corpus"], ledger_path=sandbox["ledger"])

    assert report["erased"] is False and report["reason"]
    assert sandbox["customers"].read_bytes() == customers_before
    assert {p.name: p.read_bytes() for p in sandbox["corpus"].glob("*.md")} == snapshot
    (entry,) = [json.loads(line) for line in sandbox["ledger"].read_text(encoding="utf-8").splitlines()]
    assert entry["tool"] == "erase_customer" and entry["decision"] == "deny" and entry["reason"]


def test_unknown_customer_is_logged_not_erased(sandbox):
    report = erase_customer("KH-123456", "dpo", customers_file=sandbox["customers"],
                            corpus_dir=sandbox["corpus"], ledger_path=sandbox["ledger"])
    assert report["erased"] is False
    entries = [json.loads(line) for line in sandbox["ledger"].read_text(encoding="utf-8").splitlines()]
    assert [e["decision"] for e in entries] == ["allow", "deny"] and all(e["reason"] for e in entries)
    assert ledger.verify(sandbox["ledger"])


def test_purging_ledger_lines_instead_breaks_the_chain(sandbox, clean_sink):
    """Vì sao cascade KHÔNG xoá dòng ledger: xoá dòng giữa file làm đứt hash chain."""
    run_once(QUERY, mock=True, log_dir=sandbox["ledger"].parent, principal_id="dpo")
    subject_hash = hashlib.sha256(
        json.dumps({"customer_id": SUBJECT}, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    lines = sandbox["ledger"].read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if json.loads(line)["args_hash"] != subject_hash]
    assert len(kept) < len(lines), "ledger phải có dòng read_customer của khách"
    sandbox["ledger"].write_text("\n".join(kept) + "\n", encoding="utf-8")
    assert ledger.verify(sandbox["ledger"]) is False

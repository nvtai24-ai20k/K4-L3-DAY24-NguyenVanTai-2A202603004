"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re
import unicodedata

_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# Chuỗi số liền nhau: ứng viên cho CCCD / STK / SĐT viết liền.
_DIGITS_RE = re.compile(r"(?<![\w+])\d{8,16}(?![\w])")
# SĐT viết có dấu cách / chấm / gạch: "0912 345 678", "+84 912-345-678".
_SPACED_PHONE_RE = re.compile(r"(?<![\w+])(?:\+84|0)\d{1,4}(?:[ .-]\d{2,4}){2,4}(?![\w])")

# Từ khoá ngữ cảnh, so khớp trên text đã bỏ dấu + hạ chữ thường. Một chuỗi
# 10-12 chữ số có thể là SĐT, CCCD hoặc STK; từ khoá GẦN NHẤT phía trước
# quyết định loại, chỉ khi không có từ khoá mới đoán theo độ dài.
_CONTEXT_KEYWORDS = {
    "VN_BANK_ACCOUNT": ("stk", "so tai khoan", "tai khoan", "so tk", "account"),
    "VN_CCCD": ("cccd", "cmnd", "can cuoc", "chung minh"),
    "VN_PHONE": ("sdt", "so dien thoai", "dien thoai", "hotline", "phone", "zalo"),
}
_CONTEXT_WINDOW = 40


def _fold(text: str) -> str:
    """Bỏ dấu tiếng Việt (giữ nguyên độ dài để offset vẫn khớp) và hạ chữ thường."""
    out = []
    for ch in text:
        if ch in "đĐ":
            out.append("d")
            continue
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
        out.append((base or ch)[0].lower())
    return "".join(out)


def _context_type(folded: str, start: int) -> str | None:
    window = folded[max(0, start - _CONTEXT_WINDOW):start]
    best_type, best_pos = None, -1
    for entity_type, keywords in _CONTEXT_KEYWORDS.items():
        for keyword in keywords:
            for m in re.finditer(rf"\b{re.escape(keyword)}\b", window):
                if m.end() > best_pos:
                    best_type, best_pos = entity_type, m.end()
    return best_type


def _is_phone(digits: str) -> bool:
    return (digits.startswith("0") and len(digits) in (10, 11)) or (
        digits.startswith("84") and len(digits) in (11, 12)
    )


def _classify(digits: str, context: str | None, spaced: bool) -> str | None:
    if spaced:
        return "VN_PHONE" if _is_phone(digits) else None
    if context == "VN_BANK_ACCOUNT" and 8 <= len(digits) <= 16:
        return "VN_BANK_ACCOUNT"
    if context == "VN_CCCD" and len(digits) in (9, 12):
        return "VN_CCCD"
    if context == "VN_PHONE" and _is_phone(digits):
        return "VN_PHONE"
    # Không có (hoặc ngữ cảnh không khớp độ dài): đoán theo hình dạng.
    if len(digits) == 12:
        return "VN_CCCD"
    if _is_phone(digits):
        return "VN_PHONE"
    return None


def detect(text: str) -> list[dict]:
    folded = _fold(text)
    entities = [{"type": "EMAIL", "start": m.start(), "end": m.end()} for m in _EMAIL_RE.finditer(text)]

    def free(start: int, end: int) -> bool:
        return all(end <= e["start"] or start >= e["end"] for e in entities)

    for regex, spaced in ((_DIGITS_RE, False), (_SPACED_PHONE_RE, True)):
        for m in regex.finditer(text):
            if not free(m.start(), m.end()):
                continue
            digits = re.sub(r"\D", "", m.group())
            entity_type = _classify(digits, _context_type(folded, m.start()), spaced)
            if entity_type:
                entities.append({"type": entity_type, "start": m.start(), "end": m.end()})

    return sorted(entities, key=lambda e: e["start"])


def redact(text: str) -> str:
    # Thay từ cuối về đầu để offset của các entity phía trước không bị lệch;
    # bỏ qua entity chồng lấn với entity đã thay.
    out = text
    boundary = len(text) + 1
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        if entity["end"] > boundary:
            continue
        out = out[: entity["start"]] + f"[REDACTED_{entity['type']}]" + out[entity["end"]:]
        boundary = entity["start"]
    return out

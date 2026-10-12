# DPIA-lite — checkpoint 5

> Toàn bộ dữ liệu là **synthetic** (`scripts/generate_fixtures.py`, seed cố định). Không có người thật nào bị ảnh hưởng. Đánh giá này áp dụng cho bản mô phỏng `--mock`, không phải hệ thống production.

## 1. Loại dữ liệu và phân loại

| Nguồn | Nội dung | Phân loại dùng trong PEP |
|---|---|---|
| `corpus/ticket-*.md` | Ticket hỗ trợ dạng free text. Một số ticket chứa STK/SĐT (vd `ticket-001.md`). Đây là **untrusted**, attacker có thể cài lure (901–904b). | `internal` |
| `data/customers.json` | 26 hồ sơ: họ tên, CCCD, SĐT, STK, email, `related_tickets` | `restricted` |
| `data/principals.json` | Principal giả lập, `allowed_tools`, `purposes` | cấu hình tin cậy |
| `reports/ledger.jsonl` | Metadata tool call, `args_hash` (không có giá trị PII) | `internal` |

## 2. Mục đích xử lý và principal

| Principal | Tool được phép | Purpose | Kết quả trong lab |
|---|---|---|---|
| `support_l1` | `search_docs` | `summarize-tickets`, `support-reply` | Tóm tắt ticket được; mọi `read_customer` bị deny (`reports/ledger.jsonl:25-45`) |
| `dpo` | `search_docs`, `read_customer`, `erase_customer` (bonus) | `summarize-tickets`, `support-reply`, `privacy-audit` | Đọc được 21 hồ sơ gắn với ticket tìm thấy (`reports/ledger.jsonl:2-22`). `erase_customer` chỉ dùng cho delete cascade, purpose `privacy-audit` (`reports/bonus/erasure.log`) |
| `billing` | `search_docs`, `read_customer` | `summarize-tickets`, `billing-reconciliation` | Không dùng `support-reply`, nên `read_customer` của Run B sẽ bị deny vì sai purpose |

Purpose theo run: Run A = `summarize-tickets`, Run B và bước egress = `support-reply`. Không principal nào có `http_post`.

## 3. Dữ liệu đi qua những run/tool nào, endpoint nào

```
user query ──► Run A  (scopes: search_docs)          classification internal, egress=False
                 │  search_docs(corpus/) → text đầy đủ (untrusted)
                 │  pii.redact(text) → dùng cho summarize
                 │  find_injection(text) → chỉ để route yêu cầu POST qua PEP
                 ▼  CHỈ list[int] ticket ID từ tên file (vd ticket-904b.md → 904)
               Run B  (scopes: read_customer)        classification restricted, egress=False
                 │  ticket_id → related_tickets → customer_id (nguồn tin cậy)
                 │  PEP kiểm TRƯỚC mỗi read_customer
                 ▼  record giữ trong bộ nhớ, không trả cho người dùng
               Egress step (scopes: http_post)       classification restricted, egress=True
                    PEP: restricted + egress → DENY; tools.http_post không chạy
```

- Orchestrator (depth 0) có scopes `search_docs, read_customer`. Ba run con chạy ở depth 1, nên quyền hiệu lực còn bị giao với scopes của orchestrator (`agent/runner.py:85-87`).
- Endpoint duy nhất có thể nhận dữ liệu là `http://127.0.0.1:10024/*` (sink cục bộ, allowlist cứng ở `agent/tools.py:26,77`). Sau containment không có request nào tới đó: `reports/attack-after.log` = 0 byte.
- Đầu ra cho người dùng (`llm.summarize`) chỉ dựa trên docs đã redact; mock chỉ in tên file ticket.

## 4. Bằng chứng deny/allow và giới hạn của mock

**Bằng chứng**

- Trước: `reports/attack-before.log`, baseline gửi record đầy đủ của `KH-000999` ra sink.
- Sau: `reports/attack-after.log` rỗng (chạy `--as dpo`, cùng query).
- `reports/ledger.jsonl:23`: `dpo` `http_post` **deny**, reason `dữ liệu restricted không được đi kèm egress (rule tối thiểu restricted+egress)`, `on_behalf_of: dpo`.
- `reports/ledger.jsonl:25-46`: `support_l1` có 21 `read_customer` deny và 1 `http_post` deny, mỗi dòng đều có reason.
- `verify(reports/ledger.jsonl)` = True; sửa một dòng mà không tính lại hash → False.
- `pytest tests/ -q`: 33 passed (xem `reports/verification.md`).

**Rủi ro còn lại và giới hạn**

- **Mock không phải model thật.** `find_injection` là heuristic dựa trên marker. Model thật có thể bị thuyết phục bởi lure không chứa marker nào. Containment không phụ thuộc vào việc phát hiện, nhưng phần "phát hiện" trong log thì có.
- **Principal giả lập.** `--as` chọn principal từ file JSON, không có xác thực, không ký token, không thu hồi phiên. TTL 5 phút do chính runner đặt.
- **Run B vẫn đọc PII cho `dpo`**, gồm cả hồ sơ `KH-000999`, vì ticket lure được gắn vào hồ sơ đó. Bảo vệ lúc này hoàn toàn dựa vào PEP ở egress. Nếu có principal được cấp `http_post` cho dữ liệu `internal`, phải đảm bảo payload restricted luôn được gắn nhãn đúng.
- **Index ticket → customer** được dựng bằng cách đọc `customers.json` rồi chỉ giữ `customer_id` + `related_tickets` (`agent/runner.py:161`). Ở production nên tách thành một bảng mapping riêng, không chứa PII.
- **Attacker có quyền ghi `corpus/`** có thể đặt tên file theo ticket của khách khác để Run B đọc khách đó (dưới `dpo`). Hiện tại vẫn bị chặn ở egress, nhưng đọc thừa vẫn vi phạm tối thiểu hoá. Cần kiểm soát quyền ghi vào kho ticket.
- **PII gate** dùng regex cho 4 loại; không nhận tên người, địa chỉ, ngày sinh. Test set synthetic có cùng mẫu câu với bộ sinh dữ liệu.
- **Ledger** là hash chain trong một file: không phát hiện cắt đuôi hay viết lại toàn bộ nếu thiếu mốc tin cậy bên ngoài.

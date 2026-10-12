# Verification — kết quả tự kiểm trước khi nộp

- **OS / Python / Gitleaks version:** Windows 11 (10.0.26300), chạy **native qua Git Bash**, không qua WSL2 (README ghi Windows native chưa được pilot). Python 3.11.0 trong `.venv`. Gitleaks **8.30.1** (`gitleaks version`), binary từ release chính thức, SHA-256 khớp file checksums của release. pre-commit 4.6.2, pip-tools 7.6.2.
- **`python -m pytest tests/ -q`:** `33 passed in 3.21s` cho phần bắt buộc (trước khi thêm bonus); sau khi thêm bonus là `46 passed` (33 + 13 test bonus, xem mục Bonus). Bao gồm `test_injection.py` 8/8 (4 biến thể × `support_l1`/`dpo`), `test_split.py`, `test_obo.py` 5/5, `test_policy.py` 4/4, `test_ledger.py` 3/3, `test_supply_chain.py` 3/3. Không sửa file test nào.
- **PII (`pytest tests/test_pii.py -s`):** `gold=118 pred=118 tp=118`, `precision=1.000 recall=1.000`.
- **`python -m agent.check_lure corpus/ticket-90*.md`:** `4/4 lure sẵn sàng`.
- **`pre-commit run --all-files`:** `Detect hardcoded secrets....Passed` (hook `gitleaks-system`, `rev: v8.30.1`).
- **Gitleaks:** quét lịch sử ra 1 finding `lab24-synthetic-token` ở commit `1bdd849` (exit 1, như dự kiến). `gitleaks dir` quét file hiện tại: `no leaks found` (exit 0). Chi tiết ở `reports/secrets-incident.md`.
- **Hash lock:** `requirements.lock` có 11 package, đều có `--hash=sha256`. `pip install --require-hashes -r requirements.lock` thành công.
- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` → `True` (46 dòng, dòng nào cũng có reason). Kiểm sửa đổi bằng tay: copy ledger, đổi `"decision": "deny"` → `"allow"` ở dòng 23 mà không tính lại hash → `verify()` = `False`.
- **Before/after:** `reports/attack-before.log` = 299 byte, chứa record synthetic của `KH-000999` (chạy baseline khi runner còn là scaffold). `reports/attack-after.log` = 0 byte, chạy theo trình tự reset sink → pytest → reset sink → `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → copy `sink.log`.

## Các lỗi / lưu ý còn lại

- Lần chạy đầu của `pip-compile` lỗi `ReadTimeoutError` tới `files.pythonhosted.org` (mạng). Chạy lại với `PIP_DEFAULT_TIMEOUT=120` thì thành công. Không phải lỗi code.
- `gitleaks dir .` ban đầu báo 1 finding `generic-api-key` trong `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py`. Đây là code bên thứ ba trong virtualenv đã `.gitignore`. Em thêm `[[allowlists]]` chỉ cho đường dẫn `.venv/` vào `.gitleaks.toml`; rule của lab giữ nguyên. Tái hiện: tạo `.venv` rồi chạy `gitleaks dir --config .gitleaks.toml .` khi chưa có allowlist.
- Chạy trên Windows native thay vì WSL2/macOS/Linux như README khuyến nghị. Mọi lệnh trong CHECKPOINTS đều chạy được qua Git Bash với `.venv/Scripts/python.exe`. Lệnh `python` mặc định của máy trỏ tới alias Microsoft Store nên phải gọi interpreter trong venv.
- `requirements.lock` sinh trên Windows/Python 3.11, có `colorama` (phụ thuộc của pytest trên Windows). Trên Linux/macOS nên sinh lại lock nếu grader yêu cầu khớp nền tảng.
- Bonus không làm phần so sánh GLiNER với regex: cần tải torch và model từ Hugging Face, quá nặng để chạy trên máy này.

## Bonus

Mỗi phần có test riêng (`tests/test_bonus_*.py`) và log riêng (`reports/bonus/*.log`). Không phần nào sửa test bắt buộc hay đổi hành vi của runner mặc định.

| Bonus | Code | Test / log | Kết quả |
|---|---|---|---|
| Port policy sang **OPA** (4) | `bonus/opa/lab24.rego`, `bonus/opa/lab24_test.rego`, adapter `agent/policy_opa.py` (cùng interface `check(context) -> (allow, reason)`, fail closed) | `tests/test_bonus_opa.py`, `reports/bonus/opa.log` | `opa test` 7/7 PASS. Parity với `agent/policy.py` trên 3.160 `PolicyContext` (3.000 mẫu ngẫu nhiên seed 24 + 160 tổ hợp principal × tool × classification × egress): khớp 100% cả `allow` lẫn `reason`. Runner chạy bằng PEP OPA dưới `support_l1` và `dpo`: sink rỗng, ledger có `http_post` deny, `dpo` vẫn đọc được `KH-000999`. |
| **MCP rug pull** local (4) | Server MCP stdio (JSON-RPC 2.0, stdlib) `bonus/mcp_rugpull/server.py`; guard `agent/mcp_guard.py`; demo `scripts/bonus_mcp_rugpull_demo.py` | `tests/test_bonus_mcp_rugpull.py`, `reports/bonus/mcp-rugpull.log` | Trước: sau 1 lần gọi, server đổi mô tả `invoice_status` (giữ tên), client không pin đưa mô tả mới vào context, mock LLM ra chỉ thị đọc `KH-000999` và POST `127.0.0.1:10024/mcp-sync`. Sau: guard pin sha256 artifact server + định nghĩa tool lúc duyệt; mô tả lệch thì tool bị cách ly (không vào context, không gọi; server đếm `calls=1`), ledger 2 dòng deny có reason, `verify()` = True. Server bị sửa file thì từ chối spawn. |
| **Delete cascade** giữ ledger verify (3) | `agent/erasure.py` (CLI `python -m agent.erasure`); thêm `erase_customer` vào `allowed_tools` của `dpo` trong `data/principals.json` | `tests/test_bonus_erasure.py`, `reports/bonus/erasure.log` | Chạy trên bản copy. `support_l1` bị deny, không file nào đổi. `dpo`: xoá 5 ticket gắn qua `related_tickets`, thay định danh còn sót trong ticket khác bằng `[ĐÃ XOÁ]`, xoá record (26 → 25); ledger chỉ append 4 dòng, `verify()` = True. Sau khi xoá, runner không còn đọc `KH-000999` nhưng vẫn đọc khách khác. Test đối chứng: xoá dòng ledger nhắc tới khách thì `verify()` = False. |

Môi trường bonus: OPA **v1.20.2** (`opa_windows_amd64.exe` từ release chính thức, sha256 khớp file `.sha256` của release), đặt trong PATH. `tests/test_bonus_opa.py` tự SKIP nếu không có `opa`.

Giới hạn của bonus:

- **OPA:** principal vẫn là fixture tĩnh nạp qua `-d principals:data/principals.json`. Adapter gọi `opa eval` bằng subprocess cho mỗi tool call (khoảng 50 ms trên Windows); production nên chạy OPA server/sidecar hoặc dùng bản build Wasm. Python `fromisoformat` chấp nhận vài dạng thời gian mà RFC 3339 không chấp nhận (vd dấu cách thay cho `T`); lưới parity chỉ dùng chuỗi chuẩn và chuỗi rác.
- **MCP:** server và client tự viết theo hình dạng message MCP, không dùng SDK chính thức. Pin định nghĩa không bắt được server đổi **hành vi** mà giữ nguyên mô tả; pin artifact chỉ dùng được khi server là code cục bộ có thể băm. Tool MCP chưa đi qua OBO của `policy.check`.
- **Erasure:** `args_hash` là sha256 không salt, nên với không gian ID nhỏ vẫn dò ngược được customer_id: đây là dữ liệu bút danh hoá, chưa phải ẩn danh. Hướng production là HMAC có khoá theo từng chủ thể và huỷ khoá khi xoá (crypto-shredding). Log evidence trong `reports/` (vd `attack-before.log`) nằm ngoài phạm vi cascade.

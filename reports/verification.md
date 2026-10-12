# Verification — kết quả tự kiểm trước khi nộp

- **OS / Python / Gitleaks version:** Windows 11 (10.0.26300), chạy **native qua Git Bash**, không qua WSL2 (README ghi Windows native chưa được pilot). Python 3.11.0 trong `.venv`. Gitleaks **8.30.1** (`gitleaks version`), binary từ release chính thức, SHA-256 khớp file checksums của release. pre-commit 4.6.2, pip-tools 7.6.2.
- **`python -m pytest tests/ -q`:** `33 passed in 3.21s`. Bao gồm `test_injection.py` 8/8 (4 biến thể × `support_l1`/`dpo`), `test_split.py`, `test_obo.py` 5/5, `test_policy.py` 4/4, `test_ledger.py` 3/3, `test_supply_chain.py` 3/3. Không sửa file test nào.
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
- Không làm phần bonus.

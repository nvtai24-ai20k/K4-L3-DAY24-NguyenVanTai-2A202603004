# Secret giả trong lịch sử Git — checkpoint 4

- **Scanner và phiên bản:** Gitleaks **8.30.1** (`gitleaks version` → `8.30.1`). Binary tải từ release chính thức `gitleaks_8.30.1_windows_x64.zip`; SHA-256 `d29144de…8332afc4e` khớp file `gitleaks_8.30.1_checksums.txt` của cùng release.
- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, "chore: seed student lab with synthetic secret exercise", 2026-10-09). Commit sau đó đã xoá file khỏi HEAD.
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` quét 4 commit, ra **1 finding**, exit code 1 (như dự kiến):
  - File `lab-fake-secret.txt`, dòng 1
  - RuleID `lab24-synthetic-token` (định nghĩa ở `.gitleaks.toml:7`, regex `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`)
  - Fingerprint `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`
  - Giá trị đã được `--redact` che, không chép vào báo cáo.

  Đây là token **giả và vô hiệu**, do đề bài cài sẵn làm bài tập. Đây không phải sự cố bảo mật thật.
- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`, exit 0. Lần đầu chạy có 1 finding `generic-api-key` trong `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py`. Đó là code bên thứ ba trong virtualenv cục bộ, đã nằm trong `.gitignore` và không thuộc repo. Vì vậy em thêm một `[[allowlists]]` chỉ cho đường dẫn `.venv/` (`.gitleaks.toml:14`). Rule mặc định và rule `lab24-synthetic-token` giữ nguyên.
- **Hook:** `.pre-commit-config.yaml` dùng `https://github.com/gitleaks/gitleaks`, `rev: v8.30.1`, hook `gitleaks-system` (binary trong PATH), `pass_filenames: false`, thêm `--config .gitleaks.toml`. `pre-commit run --all-files` → `Detect hardcoded secrets....Passed`. Hook chạy `gitleaks git --pre-commit --staged`, tức chặn secret **trước khi** vào commit mới; nó không quét lại lịch sử cũ.
- **Dependency lock:** `requirements.lock` sinh bằng `pip-compile --generate-hashes` (pip-tools 7.6.2, Python 3.11). Có 11 package, package nào cũng có `--hash=sha256:`. `pip install --require-hashes -r requirements.lock` chạy thành công.

## Nếu đây là credential thật, cần xử lý thế nào

1. **Thu hồi / rotate ngay** credential tại hệ thống phát hành nó. Coi như đã lộ từ thời điểm push commit `1bdd849`: bất kỳ ai đã clone, fork, hay CI cache đều có thể đang giữ bản sao.
2. Rà soát log truy cập của dịch vụ liên quan trong khoảng từ lúc commit đến lúc rotate để tìm truy cập bất thường.
3. Sau khi đã rotate, mới cân nhắc viết lại lịch sử (`git filter-repo`) và yêu cầu các bản fork/clone xoá bản cũ, để giảm nhiễu cho scanner. Bước này **không thay** cho việc rotate.
4. Ghi nhận sự cố, người phụ trách và thời điểm; thêm rule/allowlist phù hợp để hook bắt sớm lần sau.

## Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ

- Xoá file ở commit sau chỉ đổi HEAD; blob vẫn nằm trong lịch sử và trong mọi bản clone. `gitleaks git` vẫn tìm thấy nó, nghĩa là attacker cũng tìm được. Credential chỉ hết giá trị khi bên phát hành **thu hồi** nó.
- Pin dependency bằng hash và hook pre-commit là control **phòng ngừa**: hash lock chống package bị tráo trên đường cài, hook chặn secret *mới* trước khi commit. Cả hai không tác động gì tới một secret **đã lộ** trong quá khứ, nên không thay thế được bước rotate.

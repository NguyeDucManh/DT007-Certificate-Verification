# Bản bổ sung DT007 – Nghiên cứu và thực nghiệm

Bản này tạo từ ZIP DT007 được gửi trước đây. **Không chứa các cập nhật `/demo` gần nhất trên máy người dùng.**

## Tệp thay đổi/bổ sung

- `experiments/synthetic_cases.py`: thêm tham số `profile='baseline'|'extended'` (mặc định extended giữ logic cũ) và ca đối chứng `VALID_CONTROL` chỉ dùng cho nghiên cứu.
- `experiments/research_evaluation.py`: thực nghiệm 3+ lần chạy, baseline/extended, lưu raw results và metric.
- `experiments/dataset_profile.py`: metadata, checksum và thống kê chất lượng Google CT Log List.
- `tests/test_research_evaluation.py`: kiểm thử ablation và đối chứng.
- `reports/paper_review.md`, `reports/research_protocol.md`, `reports/bao_cao_khung.md`: nghiên cứu, threat model, giao thức và khung báo cáo.
- `reports/research_results/*`, `reports/ct_dataset_profile.json`: kết quả chạy trên môi trường hỗ trợ; **phải chạy lại trên máy nhóm**.

## Cách tích hợp vào project hiện tại

**Không giải nén ghi đè toàn bộ project đang chạy!** Chỉ chép các file mới; với `experiments/synthetic_cases.py` cần dùng Codex merge phần `profile` và `VALID_CONTROL` vào phiên bản mới nhất, vì bản máy nhóm đã thêm `/demo` và có thể khác.

Trong PowerShell tại thư mục DT007 (sau khi merge):

```powershell
.\.venv\Scripts\python.exe experiments\dataset_profile.py
.\.venv\Scripts\python.exe experiments\research_evaluation.py --repeats 3
.\.venv\Scripts\python.exe -m pytest -v --basetemp=.pytest_tmp -p no:cacheprovider
.\.venv\Scripts\python.exe -m pip freeze > reports\requirements_lock.txt
```

Sau khi chạy, đối chiếu `reports/research_results/summary.json`, không chép số từ lần chạy trên môi trường khác vào báo cáo như thể do máy nhóm đo.

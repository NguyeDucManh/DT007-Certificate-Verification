# DT007 – Báo cáo thực nghiệm offline

Ngày chạy (UTC): 2026-10-10T06:27:15.396446+00:00
Số lần lặp: 3; số ca lỗi: 14; ca chứng thư hợp lệ đối chứng: 1/lần lặp.

| Profile | Coverage trung bình | Khớp kỳ vọng trung bình | Runtime trung bình/ca | FP trên control |
|---|---:|---:|---:|---:|
| baseline | 71.43% | 71.43% | 0.002861s | 0.00% |
| extended | 100.00% | 100.00% | 0.003192s | 0.00% |

baseline: FP=0, FN=6.
extended: FP=0, FN=0.

**Định nghĩa:** Coverage = số loại lỗi có kết quả khớp kỳ vọng VÀ detected=True / 14 loại lỗi.
Chính xác hơn, 14 mục là điều kiện kiểm thử: gồm 13 lỗi/điều kiện cần lưu ý và 1 hồi quy semantics SCT. Misconfiguration coverage riêng trên 13 mục nằm trong summary.json.
FP = số chứng thư đối chứng hợp lệ bị gán FAIL / số chứng thư đối chứng đã hoàn thành. WARNING được báo riêng.
Baseline giữ validity/hostname/chain/algorithm và bỏ CT; extended thêm CT metadata matching.

**Không suy rộng:** Kết quả chỉ có giá trị trên fixtures của bộ thử này, không đo độ chính xác trên Internet.

## Giới hạn
- No live website ground-truth labeling
- SCT signatures and inclusion proofs not verified
- One valid control per repeat; false-positive rate not representative
- Cryptographic key generation is nondeterministic even with Python random seed
- Baseline is a CT ablation, not the paper's original implementation
- Case SCT_TIMESTAMP_OUTSIDE_INTERVAL is a corrected semantics regression, not a misconfiguration
- Profiles use freshly generated independent certificates with matched properties, not byte-identical inputs
- CT matching uses synthetic metadata; pinned Google snapshot is profiled but not used as synthetic ground truth

Chi tiết từng lần chạy: `raw_results.csv`; thông tin môi trường và checksum: `summary.json`.

# Process Hollowing Detector

Công cụ phát hiện kỹ thuật Process Hollowing mà malware sử dụng để ẩn mình.

## Nguyên lý hoạt động

Tool này phát hiện Process Hollowing bằng cách:
1. Quét tất cả processes đang chạy
2. So sánh modules từ PE file trên disk với modules được load trong memory
3. Kiểm tra PE headers, entry points, và sections integrity
4. Phát hiện các bất thường như: modules bị thiếu, entry point mismatch, unmapped executable memory

## Cài đặt

```bash
pip install -r requirements.txt
```

## Sử dụng

```bash
# Quét tất cả processes
python main.py

# Quét process cụ thể
python main.py --pid 1234

# Chế độ verbose
python main.py --verbose

# Xuất report ra file
python main.py --output report.json
```

## Yêu cầu

- Windows OS
- Python 3.8+
- Quyền Administrator (để đọc memory của processes)

## Cấu trúc

```
ProcessHollowingDetector/
├── core/
│   ├── pe_analyzer.py          # Phân tích PE file
│   ├── process_monitor.py      # Monitor processes và memory
│   ├── module_comparator.py    # So sánh modules
│   └── detector.py             # Detection engine
├── utils/
│   ├── logger.py               # Logging utilities
│   └── reporter.py             # Report generation
├── main.py                     # Entry point
└── requirements.txt
```

## Detection Indicators

- ⚠️ **Missing Modules**: DLL trong Import Table nhưng không được load
- ⚠️ **Entry Point Mismatch**: Entry point khác so với file gốc
- ⚠️ **Unmapped Executable Memory**: Memory có code nhưng không map từ file
- ⚠️ **Section Hash Mismatch**: Sections bị thay đổi
- ⚠️ **Suspicious Memory Permissions**: RWX permissions

## Lưu ý

- Cần chạy với quyền Administrator
- Một số antivirus có thể cảnh báo do tool đọc memory của processes
- False positives có thể xảy ra với các process hợp lệ sử dụng kỹ thuật tương tự

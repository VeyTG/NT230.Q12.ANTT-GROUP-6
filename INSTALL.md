# Installation Guide

## Bước 1: Cài đặt Python Dependencies

Mở terminal/command prompt với quyền Administrator và chạy:

```bash
pip install -r requirements.txt
```

## Bước 2: Kiểm tra cài đặt

```bash
python -c "import pefile, psutil, win32api; print('OK')"
```

## Bước 3: Chạy tool

### Quét tất cả processes:
```bash
python main.py
```

### Quét process cụ thể theo PID:
```bash
python main.py --pid 1234
```

### Quét theo tên process:
```bash
python main.py --name notepad.exe
```

### Chế độ verbose (xem chi tiết):
```bash
python main.py --verbose
```

### Xuất kết quả ra JSON:
```bash
python main.py --output report.json
```

### Hiển thị cả processes clean:
```bash
python main.py --show-clean
```

## Lưu ý quan trọng

1. **Phải chạy với quyền Administrator** - Tool cần quyền này để đọc memory của processes
2. **Antivirus có thể cảnh báo** - Đây là hành vi bình thường vì tool đọc memory
3. **False positives** - Một số process hợp lệ có thể bị đánh dấu suspicious

## Ví dụ sử dụng

Xem file `examples.py` để biết các ví dụ chi tiết về cách sử dụng từng module.

## Troubleshooting

### Lỗi: "Module not found"
```bash
pip install --upgrade -r requirements.txt
```

### Lỗi: "Access Denied"
- Chạy terminal/CMD với quyền Administrator
- Tắt antivirus tạm thời nếu bị block

### Lỗi khi import win32api
```bash
pip uninstall pywin32
pip install pywin32
python C:\Python3X\Scripts\pywin32_postinstall.py -install
```

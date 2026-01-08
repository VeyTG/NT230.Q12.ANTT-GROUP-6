"""
Example Usage Script
Demo cách sử dụng tool để phát hiện Process Hollowing
"""

from core.process_monitor import ProcessMonitor
from core.detector import DetectionEngine
from utils.reporter import Reporter

def example_scan_all_processes():
    """Ví dụ: Quét tất cả processes"""
    print("=== Quét tất cả processes ===\n")
    
    # Khởi tạo
    monitor = ProcessMonitor()
    detector = DetectionEngine()
    
    # Lấy danh sách processes
    processes = monitor.enumerate_processes()
    print(f"Tìm thấy {len(processes)} processes\n")
    
    # Scan một số processes (demo)
    results = []
    for proc in processes[:5]:  # Chỉ scan 5 processes đầu tiên
        try:
            result = detector.analyze_process(proc['exe_path'], proc['pid'])
            results.append(result)
            print(f"Đã scan: {proc['name']} (PID: {proc['pid']})")
        except Exception as e:
            print(f"Lỗi khi scan {proc['name']}: {e}")
    
    # Hiển thị kết quả
    print("\n")
    Reporter.print_summary(results)


def example_scan_specific_process(pid: int):
    """Ví dụ: Quét process cụ thể theo PID"""
    print(f"=== Quét process PID: {pid} ===\n")
    
    # Khởi tạo
    monitor = ProcessMonitor()
    detector = DetectionEngine()
    
    # Tìm process
    processes = monitor.enumerate_processes()
    target = next((p for p in processes if p['pid'] == pid), None)
    
    if not target:
        print(f"Không tìm thấy process với PID {pid}")
        return
    
    print(f"Process: {target['name']}")
    print(f"Path: {target['exe_path']}\n")
    
    # Analyze
    result = detector.analyze_process(target['exe_path'], target['pid'])
    
    # Hiển thị kết quả chi tiết
    Reporter.print_detailed_report(result)


def example_analyze_modules(pid: int):
    """Ví dụ: Phân tích modules của process"""
    print(f"=== Phân tích modules của PID: {pid} ===\n")
    
    monitor = ProcessMonitor()
    
    # Lấy modules
    modules = monitor.get_process_modules(pid)
    
    print(f"Tìm thấy {len(modules)} modules:\n")
    
    for i, mod in enumerate(modules[:10], 1):  # Hiển thị 10 modules đầu
        print(f"{i}. {mod['name']}")
        print(f"   Base: 0x{mod['base_address']:016X}")
        print(f"   Size: 0x{mod['size']:X}")
        print(f"   Entry: 0x{mod['entry_point']:016X}")
        print()


def example_check_memory_regions(pid: int):
    """Ví dụ: Kiểm tra memory regions của process"""
    print(f"=== Kiểm tra memory regions của PID: {pid} ===\n")
    
    monitor = ProcessMonitor()
    
    # Lấy memory regions
    regions = monitor.get_memory_regions(pid)
    
    # Lọc executable regions
    exec_regions = [r for r in regions if r['is_executable']]
    unmapped_exec = [r for r in exec_regions if not r['is_mapped']]
    
    print(f"Tổng executable regions: {len(exec_regions)}")
    print(f"Unmapped executable regions: {len(unmapped_exec)}\n")
    
    if unmapped_exec:
        print("Unmapped executable regions (đáng ngờ):")
        for i, region in enumerate(unmapped_exec[:5], 1):
            print(f"{i}. Base: 0x{region['base_address']:016X}, Size: 0x{region['size']:X}")


if __name__ == '__main__':
    import sys
    
    print("Process Hollowing Detector - Examples\n")
    print("Chọn ví dụ:")
    print("1. Quét tất cả processes")
    print("2. Quét process cụ thể theo PID")
    print("3. Phân tích modules của process")
    print("4. Kiểm tra memory regions")
    print()
    
    try:
        choice = input("Nhập lựa chọn (1-4): ").strip()
        
        if choice == '1':
            example_scan_all_processes()
        
        elif choice == '2':
            pid = int(input("Nhập PID: ").strip())
            example_scan_specific_process(pid)
        
        elif choice == '3':
            pid = int(input("Nhập PID: ").strip())
            example_analyze_modules(pid)
        
        elif choice == '4':
            pid = int(input("Nhập PID: ").strip())
            example_check_memory_regions(pid)
        
        else:
            print("Lựa chọn không hợp lệ")
    
    except KeyboardInterrupt:
        print("\n\nĐã hủy")
    except Exception as e:
        print(f"\nLỗi: {e}")

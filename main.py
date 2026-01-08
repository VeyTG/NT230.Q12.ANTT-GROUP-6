"""
Process Hollowing Detector
Main script để phát hiện Process Hollowing trong các processes đang chạy
"""

import argparse
import sys
import ctypes
from colorama import Fore, Style, init

from core.process_monitor import ProcessMonitor
from core.detector import DetectionEngine
from utils.logger import setup_logger, get_logger
from utils.reporter import Reporter

# Initialize colorama
init(autoreset=True)


def is_admin():
    """Kiểm tra xem script có chạy với quyền admin không"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def print_banner():
    """In banner của tool"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║           PROCESS HOLLOWING DETECTOR v1.0                            ║
║           Phát hiện kỹ thuật Process Hollowing                        ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)


def main():
    """Main function"""
    print_banner()
    
    # Kiểm tra quyền admin
    if not is_admin():
        print(f"{Fore.RED}[!] Tool này cần quyền Administrator để đọc memory của processes{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Vui lòng chạy lại với quyền Administrator{Style.RESET_ALL}")
        sys.exit(1)
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="Phát hiện Process Hollowing trong các processes đang chạy"
    )
    parser.add_argument(
        '--pid',
        type=int,
        help='Quét process cụ thể theo PID'
    )
    parser.add_argument(
        '--name',
        type=str,
        help='Quét process theo tên (ví dụ: notepad.exe)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Hiển thị chi tiết debug information'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Xuất kết quả ra file JSON'
    )
    parser.add_argument(
        '--show-clean',
        action='store_true',
        help='Hiển thị cả processes clean (không suspicious)'
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(args.verbose)
    
    # Initialize components
    logger.info("Khởi tạo Process Monitor...")
    process_monitor = ProcessMonitor()
    
    logger.info("Khởi tạo Detection Engine...")
    detector = DetectionEngine()
    
    # Lấy danh sách processes cần scan
    processes_to_scan = []
    
    if args.pid:
        # Scan process cụ thể theo PID
        logger.info(f"Quét process PID: {args.pid}")
        all_processes = process_monitor.enumerate_processes()
        target_proc = next((p for p in all_processes if p['pid'] == args.pid), None)
        
        if target_proc:
            processes_to_scan.append(target_proc)
        else:
            logger.error(f"Không tìm thấy process với PID {args.pid}")
            sys.exit(1)
    
    elif args.name:
        # Scan processes theo tên
        logger.info(f"Quét processes có tên: {args.name}")
        all_processes = process_monitor.enumerate_processes()
        processes_to_scan = [
            p for p in all_processes 
            if args.name.lower() in p['name'].lower()
        ]
        
        if not processes_to_scan:
            logger.error(f"Không tìm thấy process nào với tên '{args.name}'")
            sys.exit(1)
        
        logger.info(f"Tìm thấy {len(processes_to_scan)} process(es)")
    
    else:
        # Scan tất cả processes
        logger.info("Quét tất cả processes đang chạy...")
        all_processes = process_monitor.enumerate_processes()
        processes_to_scan = all_processes
        logger.info(f"Tìm thấy {len(processes_to_scan)} processes")
    
    # Scan processes
    results = []
    total = len(processes_to_scan)
    
    print(f"\n{Fore.CYAN}Bắt đầu quét {total} process(es)...{Style.RESET_ALL}\n")
    
    for idx, proc in enumerate(processes_to_scan, 1):
        try:
            if args.verbose:
                print(f"[{idx}/{total}] Scanning PID {proc['pid']} - {proc['name']}...")
            
            # Kiểm tra xem có thể access process không
            if not process_monitor.is_process_accessible(proc['pid']):
                logger.debug(f"Không thể access process {proc['pid']} - {proc['name']}")
                continue
            
            # Analyze process
            result = detector.analyze_process(proc['exe_path'], proc['pid'])
            results.append(result)
            
            # Hiển thị kết quả ngay nếu suspicious
            if result.get('is_suspicious'):
                risk_level = result.get('risk_level', 'UNKNOWN')
                risk_color = Reporter._get_risk_color(risk_level)
                print(f"  {risk_color}[!] {proc['name']} (PID: {proc['pid']}) - {risk_level}{Style.RESET_ALL}")
            elif args.show_clean:
                print(f"  {Fore.GREEN}[✓] {proc['name']} (PID: {proc['pid']}) - Clean{Style.RESET_ALL}")
        
        except Exception as e:
            logger.error(f"Lỗi khi scan process {proc['pid']}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
    
    print()
    logger.info(f"Hoàn thành quét {len(results)} processes")
    
    # Hiển thị summary
    Reporter.print_summary(results)
    
    # Hiển thị detailed report cho suspicious processes
    suspicious_results = [r for r in results if r.get('is_suspicious', False)]
    
    if suspicious_results:
        print(f"\n{Fore.YELLOW}⚠ Tìm thấy {len(suspicious_results)} process(es) đáng ngờ!{Style.RESET_ALL}")
        
        # Hiển thị detailed report nếu ít processes
        if args.pid or len(suspicious_results) <= 3:
            for result in suspicious_results:
                Reporter.print_detailed_report(result)
    else:
        print(f"\n{Fore.GREEN}✓ Không phát hiện process nào bị hollowing{Style.RESET_ALL}")
    
    # Export to JSON nếu được yêu cầu
    if args.output:
        Reporter.export_json(results, args.output)
    
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Đã dừng bởi user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Lỗi: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

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
║           PROCESS HOLLOWING DETECTOR v1.0                             ║
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
    parser.add_argument(
        '--deep-scan',
        action='store_true',
        help='Bật chế độ phân tích sâu (deep scan) để phát hiện hollowing tinh vi, shellcode obfuscation, patch, XOR, GhostHollow...'
    )
    
    args = parser.parse_args()
    
    # Setup logger
    logger = setup_logger(args.verbose)
    
    # Initialize components
    logger.info("Khởi tạo Process Monitor...")
    process_monitor = ProcessMonitor()
    
    logger.info("Khởi tạo Detection Engine...")
    detector = DetectionEngine(deep_scan=args.deep_scan if hasattr(args, 'deep_scan') else False)
    
    # Chế độ monitor: theo dõi process mới sinh ra
    if hasattr(args, 'monitor') and args.monitor:
        import time
        import psutil
        print(f"\n{Fore.CYAN}Bắt đầu theo dõi process mới sinh ra... (Nhấn Ctrl+C để dừng){Style.RESET_ALL}\n")
        known_pids = set()
        try:
            while True:
                all_processes = process_monitor.enumerate_processes()
                current_pids = set(p['pid'] for p in all_processes)
                new_pids = current_pids - known_pids
                for proc in all_processes:
                    if proc['pid'] in new_pids:
                        print(f"{Fore.YELLOW}[+] Phát hiện process mới: {proc['name']} (PID: {proc['pid']}){Style.RESET_ALL}")
                        if process_monitor.is_process_accessible(proc['pid']):
                            try:
                                result = detector.analyze_process(proc['exe_path'], proc['pid'])
                                if result.get('is_suspicious'):
                                    risk_level = result.get('risk_level', 'UNKNOWN')
                                    risk_color = Reporter._get_risk_color(risk_level)
                                    print(f"  {risk_color}[!] {proc['name']} (PID: {proc['pid']}) - {risk_level}{Style.RESET_ALL}")
                                    Reporter.print_detailed_report(result)
                                    try:
                                        p = psutil.Process(proc['pid'])
                                        p.terminate()
                                        print(f"{Fore.RED}[!] Đã dừng process {proc['name']} (PID: {proc['pid']}) do nghi ngờ hollowing!{Style.RESET_ALL}")
                                    except Exception as kill_err:
                                        print(f"{Fore.RED}[!] Lỗi khi dừng process: {kill_err}{Style.RESET_ALL}")
                            except Exception as e:
                                print(f"{Fore.RED}[!] Lỗi khi phân tích process mới: {e}{Style.RESET_ALL}")
                known_pids = current_pids
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Đã dừng theo dõi process mới.{Style.RESET_ALL}")
        return

    # Chế độ quét theo PID
    if args.pid:
        import psutil
        logger.info(f"Quét process PID: {args.pid}")
        all_processes = process_monitor.enumerate_processes()
        target_proc = next((p for p in all_processes if p['pid'] == args.pid), None)
        if not target_proc:
            logger.error(f"Không tìm thấy process với PID {args.pid}")
            sys.exit(1)
        if not process_monitor.is_process_accessible(target_proc['pid']):
            logger.error(f"Không thể access process {target_proc['pid']} - {target_proc['name']}")
            sys.exit(1)
        try:
            result = detector.analyze_process(target_proc['exe_path'], target_proc['pid'])
            if result.get('is_suspicious'):
                risk_level = result.get('risk_level', 'UNKNOWN')
                risk_color = Reporter._get_risk_color(risk_level)
                print(f"  {risk_color}[!] {target_proc['name']} (PID: {target_proc['pid']}) - {risk_level}{Style.RESET_ALL}")
                Reporter.print_detailed_report(result)
                confirm = input(f"{Fore.YELLOW}Bạn có muốn dừng process này không? (y/n): {Style.RESET_ALL}").strip().lower()
                if confirm == 'y':
                    try:
                        p = psutil.Process(target_proc['pid'])
                        p.terminate()
                        print(f"{Fore.RED}[!] Đã dừng process {target_proc['name']} (PID: {target_proc['pid']}) do nghi ngờ hollowing!{Style.RESET_ALL}")
                    except Exception as kill_err:
                        print(f"{Fore.RED}[!] Lỗi khi dừng process: {kill_err}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] Đã bỏ qua không dừng process này.{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[✓] {target_proc['name']} (PID: {target_proc['pid']}) - Clean{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Lỗi khi phân tích hoặc dừng process: {e}{Style.RESET_ALL}")
        return

    # Chế độ quét theo tên hoặc toàn bộ
    if args.name or not (args.pid or (hasattr(args, 'monitor') and args.monitor)):
        # Lấy danh sách processes cần scan
        if args.name:
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
                if not process_monitor.is_process_accessible(proc['pid']):
                    logger.debug(f"Không thể access process {proc['pid']} - {proc['name']}")
                    continue
                result = detector.analyze_process(proc['exe_path'], proc['pid'])
                results.append(result)
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
        Reporter.print_summary(results)
        suspicious_results = [r for r in results if r.get('is_suspicious', False)]
        if suspicious_results:
            print(f"\n{Fore.YELLOW}⚠ Tìm thấy {len(suspicious_results)} process(es) đáng ngờ!{Style.RESET_ALL}")
            if args.pid or len(suspicious_results) <= 3:
                for result in suspicious_results:
                    Reporter.print_detailed_report(result)
        else:
            print(f"\n{Fore.GREEN}✓ Không phát hiện process nào bị hollowing{Style.RESET_ALL}")
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

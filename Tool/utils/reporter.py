"""
Reporter Module
Tạo report từ kết quả phát hiện
"""

import json
from typing import List, Dict
from colorama import Fore, Style
from tabulate import tabulate


class Reporter:
    """Tạo và xuất reports"""
    
    @staticmethod
    def print_summary(results: List[Dict]):
        """
        In summary của tất cả processes được scan
        Args:
            results: List kết quả từ DetectionEngine
        """
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}PROCESS HOLLOWING DETECTION SUMMARY{Style.RESET_ALL}")
        print("=" * 80 + "\n")
        
        # Thống kê
        total = len(results)
        suspicious = len([r for r in results if r.get('is_suspicious', False)])
        likely_hollowed = len([r for r in results if r.get('is_likely_hollowed', False)])
        clean = total - suspicious
        
        print(f"Total Processes Scanned: {total}")
        print(f"{Fore.GREEN}Clean: {clean}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Suspicious: {suspicious}{Style.RESET_ALL}")
        print(f"{Fore.RED}Likely Hollowed: {likely_hollowed}{Style.RESET_ALL}")
        print()
        
        # Tạo bảng cho suspicious processes
        if suspicious > 0:
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}SUSPICIOUS PROCESSES:{Style.RESET_ALL}\n")
            
            suspicious_results = [r for r in results if r.get('is_suspicious', False)]
            
            table_data = []
            for r in suspicious_results:
                risk_color = Reporter._get_risk_color(r.get('risk_level', ''))
                table_data.append([
                    r.get('pid', 'N/A'),
                    r.get('process_name', 'N/A'),
                    f"{risk_color}{r.get('risk_score', 0)}{Style.RESET_ALL}",
                    f"{risk_color}{r.get('risk_level', 'UNKNOWN')}{Style.RESET_ALL}",
                    len(r.get('indicators', []))
                ])
            
            headers = ["PID", "Process Name", "Risk Score", "Risk Level", "Indicators"]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    @staticmethod
    def print_detailed_report(result: Dict):
        """
        In chi tiết report cho một process
        Args:
            result: Kết quả từ DetectionEngine
        """
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}DETAILED ANALYSIS REPORT{Style.RESET_ALL}")
        print("=" * 80 + "\n")
        
        # Thông tin process
        print(f"{Fore.CYAN}Process Information:{Style.RESET_ALL}")
        print(f"  PID: {result.get('pid', 'N/A')}")
        print(f"  Name: {result.get('process_name', 'N/A')}")
        print(f"  Path: {result.get('exe_path', 'N/A')}")
        print()
        
        # Risk assessment
        risk_level = result.get('risk_level', 'UNKNOWN')
        risk_score = result.get('risk_score', 0)
        risk_color = Reporter._get_risk_color(risk_level)
        
        print(f"{Fore.CYAN}Risk Assessment:{Style.RESET_ALL}")
        print(f"  Risk Score: {risk_color}{risk_score}/100{Style.RESET_ALL}")
        print(f"  Risk Level: {risk_color}{risk_level}{Style.RESET_ALL}")
        print()
        
        # Indicators
        indicators = result.get('indicators', [])
        if indicators:
            print(f"{Fore.CYAN}Detected Indicators:{Style.RESET_ALL}")
            for idx, indicator in enumerate(indicators, 1):
                severity = indicator.get('severity', 'UNKNOWN')
                severity_color = Reporter._get_severity_color(severity)
                
                print(f"\n  {idx}. {Fore.YELLOW}{indicator.get('name', 'Unknown')}{Style.RESET_ALL}")
                print(f"     Severity: {severity_color}{severity}{Style.RESET_ALL}")
                print(f"     Details: {indicator.get('details', 'N/A')}")
                print(f"     Weight: {indicator.get('weight', 0)}")
        else:
            print(f"{Fore.GREEN}No suspicious indicators detected{Style.RESET_ALL}")
        
        print()
        
        # Module comparison details
        raw_analysis = result.get('raw_analysis', {})
        module_comp = raw_analysis.get('module_comparison', {})
        
        if module_comp.get('success'):
            print(f"{Fore.CYAN}Module Analysis:{Style.RESET_ALL}")
            print(f"  Expected DLLs: {len(module_comp.get('expected_dlls', []))}")
            print(f"  Loaded DLLs: {len(module_comp.get('loaded_dlls', []))}")
            print(f"  Missing DLLs: {len(module_comp.get('missing_dlls', []))}")
            
            critical_missing = module_comp.get('critical_missing_dlls', [])
            if critical_missing:
                print(f"\n  {Fore.RED}Critical Missing DLLs:{Style.RESET_ALL}")
                for dll in critical_missing[:10]:  # Limit to 10
                    print(f"    - {dll}")
                if len(critical_missing) > 10:
                    print(f"    ... and {len(critical_missing) - 10} more")
            print()
        
        print("=" * 80)
    
    @staticmethod
    def export_json(results: List[Dict], output_path: str):
        """
        Xuất kết quả ra file JSON
        Args:
            results: List kết quả từ DetectionEngine
            output_path: Đường dẫn file output
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}Report exported to: {output_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Error exporting report: {e}{Style.RESET_ALL}")
    
    @staticmethod
    def _get_risk_color(risk_level: str) -> str:
        """Lấy màu cho risk level"""
        if "CRITICAL" in risk_level.upper():
            return Fore.RED + Style.BRIGHT
        elif "HIGH" in risk_level.upper():
            return Fore.RED
        elif "MEDIUM" in risk_level.upper():
            return Fore.YELLOW
        elif "LOW" in risk_level.upper():
            return Fore.BLUE
        else:
            return Fore.GREEN
    
    @staticmethod
    def _get_severity_color(severity: str) -> str:
        """Lấy màu cho severity"""
        colors = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.BLUE,
            'INFO': Fore.CYAN
        }
        return colors.get(severity, '')

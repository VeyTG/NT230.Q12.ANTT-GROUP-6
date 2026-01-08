"""
Detection Engine
Phân tích kết quả và quyết định xem process có bị hollowing không
"""

from typing import Dict, List
from core.module_comparator import ModuleComparator


class HollowingIndicator:
    """Các chỉ số phát hiện Process Hollowing"""
    
    # Severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"
    
    def __init__(self):
        self.indicators = []
        self.score = 0
        self.max_score = 100
    
    def add_indicator(self, name: str, detected: bool, severity: str, details: str):
        """Thêm indicator"""
        weights = {
            self.SEVERITY_CRITICAL: 30,
            self.SEVERITY_HIGH: 20,
            self.SEVERITY_MEDIUM: 10,
            self.SEVERITY_LOW: 5,
            self.SEVERITY_INFO: 0
        }
        
        if detected:
            self.score += weights.get(severity, 0)
            self.indicators.append({
                'name': name,
                'detected': detected,
                'severity': severity,
                'details': details,
                'weight': weights.get(severity, 0)
            })
    
    def get_risk_level(self) -> str:
        """Đánh giá mức độ nguy hiểm"""
        if self.score >= 50:
            return "CRITICAL - Very likely hollowed"
        elif self.score >= 30:
            return "HIGH - Suspicious activity detected"
        elif self.score >= 15:
            return "MEDIUM - Some anomalies detected"
        elif self.score > 0:
            return "LOW - Minor anomalies"
        else:
            return "CLEAN - No suspicious activity"


class DetectionEngine:
    """Engine chính để phát hiện Process Hollowing"""
    
    def __init__(self):
        self.comparator = ModuleComparator()
        
        # Whitelist - các process thường có behavior đặc biệt
        self.trusted_processes = {
            'zalo.exe', 'electron.exe', 'chrome.exe', 'firefox.exe',
            'msedge.exe', 'teams.exe', 'slack.exe', 'discord.exe',
            'code.exe', 'devenv.exe', 'rider64.exe', 'webstorm64.exe',
            'git.exe', 'bash.exe', 'sh.exe', 'wsl.exe',
            'python.exe', 'node.exe', 'java.exe', 'javaw.exe',
            'windowscopilot.exe', 'copilot.exe', 'FnHotkeyUtility.exe', 'NahimicService.exe'
        }
    
    def analyze_process(self, exe_path: str, pid: int) -> Dict:
        """
        Phân tích process và đưa ra kết luận
        Args:
            exe_path: Đường dẫn đến executable
            pid: Process ID
        Returns: Dict chứa kết quả phân tích và indicators
        """
        # Lấy comprehensive analysis
        analysis = self.comparator.get_comprehensive_analysis(exe_path, pid)
        
        # Tạo indicator tracker
        indicator = HollowingIndicator()
        
        # Kiểm tra xem có phải trusted process không
        process_name = exe_path.split('\\')[-1].lower()
        is_trusted = process_name in self.trusted_processes
        
        # Kiểm tra các chỉ số
        self._check_missing_modules(analysis, indicator, is_trusted)
        self._check_entry_point_mismatch(analysis, indicator, is_trusted)
        self._check_unmapped_memory(analysis, indicator, is_trusted)
        
        # Áp dụng logic kết hợp: chỉ cảnh báo nếu có nhiều indicators nghiêm trọng
        critical_indicators = len([i for i in indicator.indicators if i['severity'] == 'CRITICAL'])
        high_indicators = len([i for i in indicator.indicators if i['severity'] == 'HIGH'])
        
        # Điều chỉnh threshold dựa trên số lượng indicators
        is_suspicious = False
        is_likely_hollowed = False
        
        if not is_trusted:
            # Process không trusted: ngưỡng thấp hơn
            is_suspicious = (indicator.score >= 40) or (critical_indicators >= 2)
            is_likely_hollowed = (indicator.score >= 60) or (critical_indicators >= 3)
        else:
            # Process trusted: ngưỡng cao hơn để tránh false positive
            is_suspicious = (indicator.score >= 60) or (critical_indicators >= 3)
            is_likely_hollowed = (indicator.score >= 80)
        
        # Tạo kết quả
        result = {
            'pid': pid,
            'exe_path': exe_path,
            'process_name': process_name,
            'is_trusted': is_trusted,
            'risk_score': indicator.score,
            'risk_level': indicator.get_risk_level(),
            'is_suspicious': is_suspicious,
            'is_likely_hollowed': is_likely_hollowed,
            'indicators': indicator.indicators,
            'critical_indicators': critical_indicators,
            'high_indicators': high_indicators,
            'raw_analysis': analysis
        }
        
        return result
    
    def _check_missing_modules(self, analysis: Dict, indicator: HollowingIndicator, is_trusted: bool = False):
        """Kiểm tra modules bị thiếu"""
        module_comp = analysis.get('module_comparison', {})
        
        if not module_comp.get('success'):
            return
        
        critical_missing = module_comp.get('critical_missing_count', 0)
        loaded_count = len(module_comp.get('loaded_dlls', []))
        expected_count = len(module_comp.get('expected_dlls', []))
        
        # Tính tỷ lệ DLL bị thiếu
        missing_ratio = critical_missing / max(expected_count, 1) if expected_count > 0 else 0
        
        # Chỉ cảnh báo nếu tỷ lệ thiếu quá cao (> 70%)
        if missing_ratio > 0.7 and critical_missing > 10:
            indicator.add_indicator(
                "Critical DLLs Missing",
                True,
                HollowingIndicator.SEVERITY_CRITICAL,
                f"{critical_missing}/{expected_count} DLLs missing ({missing_ratio*100:.0f}%)"
            )
        elif missing_ratio > 0.5 and critical_missing > 8:
            indicator.add_indicator(
                "Many DLLs Missing",
                True,
                HollowingIndicator.SEVERITY_HIGH,
                f"{critical_missing}/{expected_count} DLLs missing ({missing_ratio*100:.0f}%)"
            )
        
        # Chỉ cảnh báo "Very Few Modules" nếu thực sự quá ít (< 2) và không phải trusted
        if loaded_count < 2 and not is_trusted:
            indicator.add_indicator(
                "Very Few Modules Loaded",
                True,
                HollowingIndicator.SEVERITY_CRITICAL,
                f"Only {loaded_count} modules loaded - highly suspicious"
            )
    
    def _check_entry_point_mismatch(self, analysis: Dict, indicator: HollowingIndicator, is_trusted: bool = False):
        """Kiểm tra entry point có khớp không"""
        entry_check = analysis.get('entry_point_check', {})
        
        if not entry_check.get('success'):
            return
        
        if entry_check.get('mismatch'):
            offset_diff = entry_check.get('offset_difference', 0)
            
            # Chỉ cảnh báo nếu sai lệch CỰC KỲ lớn (> 1MB)
            # Bỏ qua sai lệch nhỏ do ASLR, dynamic loading, JIT compiler
            if offset_diff > 0x100000:  # > 1MB
                indicator.add_indicator(
                    "Entry Point Mismatch",
                    True,
                    HollowingIndicator.SEVERITY_CRITICAL,
                    f"Entry point differs by 0x{offset_diff:X} from expected"
                )
            elif offset_diff > 0x50000 and not is_trusted:  # > 320KB và không trusted
                indicator.add_indicator(
                    "Entry Point Deviation",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"Entry point differs by 0x{offset_diff:X} from expected"
                )
    
    def _check_unmapped_memory(self, analysis: Dict, indicator: HollowingIndicator, is_trusted: bool = False):
        """Kiểm tra unmapped executable memory"""
        unmapped_check = analysis.get('unmapped_memory_check', {})
        
        if not unmapped_check.get('success'):
            return
        
        unmapped_count = unmapped_check.get('unmapped_executable_regions', 0)
        
        # JIT compilers (Chrome, .NET, Java) thường có nhiều unmapped executable memory
        # Chỉ cảnh báo nếu có RẤT NHIỀU (> 30) và không phải trusted
        if unmapped_count > 50:
            indicator.add_indicator(
                "Excessive Unmapped Executable Memory",
                True,
                HollowingIndicator.SEVERITY_HIGH,
                f"{unmapped_count} executable memory regions not mapped from files"
            )
        elif unmapped_count > 30 and not is_trusted:
            indicator.add_indicator(
                "Many Unmapped Executable Regions",
                True,
                HollowingIndicator.SEVERITY_MEDIUM,
                f"{unmapped_count} executable memory regions not mapped from files"
            )
    
    def batch_analyze(self, process_list: List[Dict]) -> List[Dict]:
        """
        Phân tích nhiều processes
        Args:
            process_list: List các dict chứa {'pid': int, 'exe_path': str}
        Returns: List kết quả phân tích
        """
        results = []
        
        for proc in process_list:
            try:
                result = self.analyze_process(proc['exe_path'], proc['pid'])
                results.append(result)
            except Exception as e:
                results.append({
                    'pid': proc['pid'],
                    'exe_path': proc['exe_path'],
                    'error': str(e),
                    'success': False
                })
        
        return results

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
    
    def __init__(self, deep_scan: bool = False):
        self.comparator = ModuleComparator()
        self.deep_scan = deep_scan
        # Whitelist - các process thường có behavior đặc biệt
        self.trusted_processes = {
            'zalo.exe', 'electron.exe', 'chrome.exe', 'firefox.exe',
            'msedge.exe', 'teams.exe', 'slack.exe', 'discord.exe',
            'code.exe', 'devenv.exe', 'rider64.exe', 'webstorm64.exe',
            'git.exe', 'bash.exe', 'sh.exe', 'wsl.exe',
            'python.exe', 'node.exe', 'java.exe', 'javaw.exe',
            'windowscopilot.exe', 'copilot.exe', 'FnHotkeyUtility.exe', 'NahimicService.exe',
            'svchost.exe', 'winlogon.exe', 'dwm.exe', 'explorer.exe', 'services.exe',
            'lsass.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'system.exe',
            'spoolsv.exe', 'taskhostw.exe', 'fontdrvhost.exe', 'sihost.exe',
            'searchui.exe', 'searchapp.exe', 'ctfmon.exe', 'audiodg.exe',
            'onedrive.exe', 'widgetservice.exe', 'runtimebroker.exe', 'startmenuexperiencehost.exe',
            'securityhealthservice.exe', 'wudfhost.exe', 'conhost.exe', 'msmpeng.exe',
            'backgroundtaskhost.exe', 'applicationframehost.exe', 'dllhost.exe', 'wmiapsrv.exe',
            'wlanext.exe', 'wscript.exe', 'taskeng.exe', 'sppsvc.exe', 'dasHost.exe',
            'mousocoreworker.exe', 'userinit.exe', 'logonui.exe', 'winlogon.exe',
            'shellexperiencehost.exe', 'searchfilterhost.exe', 'searchprotocolhost.exe',
            'searchindexer.exe', 'systemsettings.exe', 'msiexec.exe', 'wermgr.exe',
            'wudfsvc.exe', 'wuauserv.exe', 'wlanext.exe', 'wscript.exe', 'taskeng.exe',
            'sppsvc.exe', 'dasHost.exe', 'mousocoreworker.exe', 'userinit.exe',
            'logonui.exe', 'fontdrvhost.exe', 'audiodg.exe', 'backgroundtaskhost.exe',
            'applicationframehost.exe', 'dllhost.exe', 'wmiapsrv.exe', 'wlanext.exe',
            'wscript.exe', 'taskeng.exe', 'sppsvc.exe', 'dasHost.exe',
            'securityhealthsystray.exe', 'vgauthservice.exe', 'vmtoolsd.exe', 'msdtc.exe',
            'wmiprvse.exe', 'aggregatorhost.exe', 'filecoauth.exe', 'shellhost.exe',
            'crossdeviceresume.exe', 'searchhost.exe', 'mintty.exe', 'widgets.exe',
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
        analysis = self.comparator.get_comprehensive_analysis(exe_path, pid, deep_scan=self.deep_scan)
        # Tạo indicator tracker
        indicator = HollowingIndicator()
        # Kiểm tra xem có phải trusted process không
        process_name = exe_path.split('\\')[-1].lower()
        is_trusted = process_name in self.trusted_processes
        # Kiểm tra các chỉ số
        self._check_missing_modules(analysis, indicator, is_trusted)
        self._check_entry_point_mismatch(analysis, indicator, is_trusted)
        self._check_unmapped_memory(analysis, indicator, is_trusted)
        self._check_sandbox_bypass_behavior(pid, indicator, is_trusted)
        self._check_dll_hollowing(analysis, indicator, is_trusted)
        self._check_text_section_memory(analysis, indicator)
        self._check_unmapped_shellcode(analysis, indicator)
        # Deep scan indicators
        if self.deep_scan and 'deep_scan' in analysis:
            self._check_deep_scan(analysis['deep_scan'], indicator)
            # Special rule: fallback memory scan (no valid module/base address)
            deep_scan = analysis['deep_scan']
            if deep_scan.get('fallback_memory_scan'):
                suspicious = [r for r in deep_scan.get('suspicious_regions', []) if (r['entropy'] > 6.5 or r['entropy_regions'] or r['xor_regions'] or r['patch_regions'])]
                if not analysis['module_comparison']['loaded_modules']:
                    indicator.add_indicator(
                        "No valid module in process memory (possible hollowing/unlink/reflective/packed)",
                        True,
                        HollowingIndicator.SEVERITY_CRITICAL,
                        f"No modules found. Suspicious memory regions: {len(suspicious)}"
                    )
                elif suspicious:
                    indicator.add_indicator(
                        "Suspicious Executable Memory Region(s) (fallback scan)",
                        True,
                        HollowingIndicator.SEVERITY_HIGH,
                        f"Suspicious memory regions: {len(suspicious)}"
                    )
        # Áp dụng logic kết hợp: chỉ cảnh báo nếu có nhiều indicators nghiêm trọng
        critical_indicators = len([i for i in indicator.indicators if i['severity'] == 'CRITICAL'])
        high_indicators = len([i for i in indicator.indicators if i['severity'] == 'HIGH'])
        # Điều chỉnh threshold dựa trên số lượng indicators
        is_suspicious = False
        is_likely_hollowed = False
        if not is_trusted:
            # Process không trusted: ngưỡng thấp hơn
            # Chỉ coi thiếu DLL là nghi ngờ nếu có thêm dấu hiệu khác (entry point, code section, sandbox bypass...)
            has_dll_indicator = any(i['name'].startswith('Critical DLLs Missing') or i['name'].startswith('Many DLLs Missing') for i in indicator.indicators)
            has_other_indicator = len(indicator.indicators) > (1 if has_dll_indicator else 0)
            is_suspicious = ((indicator.score >= 40) or (critical_indicators >= 2)) and (not has_dll_indicator or has_other_indicator)
            is_likely_hollowed = ((indicator.score >= 60) or (critical_indicators >= 3)) and (not has_dll_indicator or has_other_indicator)
        else:
            # Process trusted: ngưỡng cao hơn để tránh false positive
            # Tăng ngưỡng cảnh báo cho trusted process
            is_suspicious = (indicator.score >= 80) or (critical_indicators >= 4)
            is_likely_hollowed = (indicator.score >= 95)
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
        # If deep scan, add summary of deep scan findings
        if self.deep_scan and 'deep_scan' in analysis:
            result['deep_scan'] = analysis['deep_scan']
        return result

    def _check_deep_scan(self, deep_scan: dict, indicator: HollowingIndicator):
        """Phân tích kết quả deep scan và thêm indicators nếu phát hiện bất thường"""
        # .text section
        text = deep_scan.get('text_section', {})
        if text:
            if text.get('entropy_regions'):
                indicator.add_indicator(
                    "High Entropy Regions in .text (Deep Scan)",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"Suspicious entropy regions: {len(text['entropy_regions'])}"
                )
            if text.get('xor_regions'):
                indicator.add_indicator(
                    "XOR Pattern Detected in .text (Deep Scan)",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"Suspicious XOR regions: {len(text['xor_regions'])}"
                )
            if text.get('patch_regions'):
                indicator.add_indicator(
                    "Patch/Jump Detected in .text (Deep Scan)",
                    True,
                    HollowingIndicator.SEVERITY_MEDIUM,
                    f"Suspicious patch/jump regions: {len(text['patch_regions'])}"
                )
        # Unmapped shellcode regions
        shellcode = deep_scan.get('shellcode_regions', [])
        for region in shellcode:
            if region.get('entropy_regions'):
                indicator.add_indicator(
                    "High Entropy in Unmapped Executable Memory (Deep Scan)",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"Base: 0x{region['base']:X}, size: {region['size']}, suspicious entropy regions: {len(region['entropy_regions'])}"
                )
            if region.get('xor_regions'):
                indicator.add_indicator(
                    "XOR Pattern in Unmapped Executable Memory (Deep Scan)",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"Base: 0x{region['base']:X}, size: {region['size']}, suspicious XOR regions: {len(region['xor_regions'])}"
                )
            if region.get('patch_regions'):
                indicator.add_indicator(
                    "Patch/Jump in Unmapped Executable Memory (Deep Scan)",
                    True,
                    HollowingIndicator.SEVERITY_MEDIUM,
                    f"Base: 0x{region['base']:X}, size: {region['size']}, suspicious patch/jump regions: {len(region['patch_regions'])}"
                )
        # No return needed

    def _check_text_section_memory(self, analysis: Dict, indicator: HollowingIndicator):
        """Cảnh báo nếu hash .text giữa file và memory khác, entropy cao"""
        text_mem = analysis.get('text_section_memory', {})
        if not text_mem.get('success'):
            return
        if not text_mem.get('hash_match'):
            indicator.add_indicator(
                "Code Section Modified (Hollowing)",
                True,
                HollowingIndicator.SEVERITY_CRITICAL,
                f".text hash mismatch: file {text_mem.get('file_hash')} vs mem {text_mem.get('mem_hash')}"
            )
        if text_mem.get('mem_entropy', 0) > 6.5:
            indicator.add_indicator(
                "High Entropy .text (Possible Shellcode)",
                True,
                HollowingIndicator.SEVERITY_HIGH,
                f".text entropy in memory: {text_mem.get('mem_entropy'):.2f}"
            )

    def _check_unmapped_shellcode(self, analysis: Dict, indicator: HollowingIndicator):
        """Cảnh báo nếu có vùng unmapped executable nhỏ, entropy cao (dấu hiệu shellcode)"""
        unmapped = analysis.get('unmapped_shellcode', {})
        if not unmapped.get('success'):
            return
        count = unmapped.get('count', 0)
        if count > 0:
            indicator.add_indicator(
                "Suspicious Unmapped Executable Region(s)",
                True,
                HollowingIndicator.SEVERITY_CRITICAL if count > 1 else HollowingIndicator.SEVERITY_HIGH,
                f"{count} region(s) with high entropy (possible shellcode)"
            )

    def _check_sandbox_bypass_behavior(self, pid: int, indicator: HollowingIndicator, is_trusted: bool = False):
        """Kiểm tra process có dấu hiệu sandbox bypass bằng vòng lặp lớn, CPU time cao, thread count lớn"""
        import psutil
        try:
            p = psutil.Process(pid)
            cpu_time = sum(p.cpu_times()[:2])  # user + system
            num_threads = p.num_threads()
            ctx_switches = p.num_ctx_switches().voluntary + p.num_ctx_switches().involuntary
            # Nếu CPU time > 1000s hoặc thread > 1000 hoặc context switch > 10 triệu => nghi ngờ bypass
            if cpu_time > 1000 or num_threads > 1000 or ctx_switches > 10_000_000:
                indicator.add_indicator(
                    "Suspicious Loop/Sandbox Bypass",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"CPU time: {cpu_time:.0f}s, Threads: {num_threads}, CtxSwitch: {ctx_switches}"
                )
        except Exception:
            pass

    def _check_dll_hollowing(self, analysis: Dict, indicator: HollowingIndicator, is_trusted: bool = False):
        """Kiểm tra DLL hollowing: code section nhỏ, entry point đổi nhẹ, import/export bất thường"""
        peinfo = analysis.get('pe_info', {})
        entry_check = analysis.get('entry_point_check', {})
        if not peinfo or not entry_check:
            return
        # Kiểm tra code section nhỏ bất thường
        sections = peinfo.get('sections', [])
        code_sections = [s for s in sections if s['name'].lower().startswith('.text') or (s['characteristics'] & 0x20)]
        if code_sections:
            code_size = sum(s['virtual_size'] for s in code_sections)
            if code_size < 4096:  # <4KB code section
                indicator.add_indicator(
                    "Tiny Code Section (DLL Hollowing)",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"Total code section size: {code_size} bytes"
                )
        # Kiểm tra entry point đổi nhẹ nhưng code nhỏ
        if entry_check.get('mismatch') and abs(entry_check.get('offset_difference', 0)) < 0x10000:
            if code_sections and sum(s['virtual_size'] for s in code_sections) < 4096:
                indicator.add_indicator(
                    "Entry Point Changed (DLL Hollowing)",
                    True,
                    HollowingIndicator.SEVERITY_HIGH,
                    f"Entry point changed by {entry_check.get('offset_difference', 0)} bytes, code section tiny"
                )
        # Kiểm tra số lượng import/export bất thường
        num_imports = len(peinfo.get('imported_dlls', []))
        if num_imports < 2:
            indicator.add_indicator(
                "Very Few Imports (DLL Hollowing)",
                True,
                HollowingIndicator.SEVERITY_MEDIUM,
                f"Only {num_imports} DLLs imported"
            )
        # Có thể bổ sung kiểm tra export nếu cần
    
    def _check_missing_modules(self, analysis: Dict, indicator: HollowingIndicator, is_trusted: bool = False):
        """Kiểm tra modules bị thiếu (giảm trọng số, chỉ cảnh báo mạnh khi có dấu hiệu khác)"""
        module_comp = analysis.get('module_comparison', {})
        if not module_comp.get('success'):
            return
        critical_missing = module_comp.get('critical_missing_count', 0)
        loaded_count = len(module_comp.get('loaded_dlls', []))
        expected_count = len(module_comp.get('expected_dlls', []))
        missing_ratio = critical_missing / max(expected_count, 1) if expected_count > 0 else 0
        # Giảm trọng số: chỉ HIGH nếu >80%, CRITICAL nếu >90% và thiếu >20 DLL
        if missing_ratio > 0.9 and critical_missing > 20:
            indicator.add_indicator(
                "Critical DLLs Missing",
                True,
                HollowingIndicator.SEVERITY_CRITICAL,
                f"{critical_missing}/{expected_count} DLLs missing ({missing_ratio*100:.0f}%)"
            )
        elif missing_ratio > 0.8 and critical_missing > 15:
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

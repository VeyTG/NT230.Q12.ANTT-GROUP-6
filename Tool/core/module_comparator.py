"""
Module Comparator
So sánh modules giữa PE file trên disk và modules loaded trong memory
"""

from typing import Dict, List, Set
from core.pe_analyzer import PEAnalyzer
from core.process_monitor import ProcessMonitor


class ModuleComparator:
    """So sánh modules để phát hiện Process Hollowing"""
    
    def __init__(self):
        self.process_monitor = ProcessMonitor()
    
    def compare_modules(self, exe_path: str, pid: int) -> Dict:
        """
        So sánh modules từ PE file với modules trong memory
        Args:
            exe_path: Đường dẫn đến executable
            pid: Process ID
        Returns: Dict chứa kết quả so sánh
        """
        # Phân tích PE file
        pe_analyzer = PEAnalyzer(exe_path)
        
        if not pe_analyzer.is_valid:
            return {
                'success': False,
                'error': 'Cannot analyze PE file'
            }
        
        # Lấy DLLs từ Import Table
        expected_dlls = set(pe_analyzer.get_imported_dlls())
        
        # Lấy modules được load trong memory
        loaded_modules = self.process_monitor.get_process_modules(pid)
        loaded_dll_names = set([mod['name'] for mod in loaded_modules])
        
        # So sánh
        missing_dlls = expected_dlls - loaded_dll_names
        
        # System DLLs luôn được load ngầm, không cần cảnh báo
        system_dlls = {
            'ntdll.dll', 'kernel32.dll', 'kernelbase.dll',
            'user32.dll', 'gdi32.dll', 'msvcrt.dll'
        }
        
        # Lọc bỏ system DLLs khỏi missing list
        critical_missing_dlls = missing_dlls - system_dlls
        
        pe_analyzer.close()
        
        return {
            'success': True,
            'expected_dlls': list(expected_dlls),
            'loaded_dlls': list(loaded_dll_names),
            'missing_dlls': list(missing_dlls),
            'critical_missing_dlls': list(critical_missing_dlls),
            'missing_count': len(missing_dlls),
            'critical_missing_count': len(critical_missing_dlls),
            'loaded_modules': loaded_modules
        }
    
    def check_entry_point(self, exe_path: str, pid: int) -> Dict:
        """
        So sánh entry point từ file với entry point trong memory
        Args:
            exe_path: Đường dẫn đến executable
            pid: Process ID
        Returns: Dict chứa kết quả so sánh
        """
        pe_analyzer = PEAnalyzer(exe_path)
        
        if not pe_analyzer.is_valid:
            return {
                'success': False,
                'error': 'Cannot analyze PE file'
            }
        
        file_entry_point = pe_analyzer.get_entry_point()
        file_image_base = pe_analyzer.get_image_base()
        
        # Lấy entry point từ memory
        modules = self.process_monitor.get_process_modules(pid)
        
        if not modules:
            pe_analyzer.close()
            return {
                'success': False,
                'error': 'Cannot get process modules'
            }
        
        # Module đầu tiên là main executable
        main_module = modules[0]
        memory_base = main_module['base_address']
        memory_entry = main_module['entry_point']
        
        # Tính toán entry point tương đối
        expected_entry = memory_base + file_entry_point
        
        # So sánh (cho phép sai lệch nhỏ do ASLR)
        entry_point_mismatch = (memory_entry != expected_entry)
        
        pe_analyzer.close()
        
        return {
            'success': True,
            'file_entry_point': file_entry_point,
            'file_image_base': file_image_base,
            'memory_base': memory_base,
            'memory_entry': memory_entry,
            'expected_entry': expected_entry,
            'mismatch': entry_point_mismatch,
            'offset_difference': abs(memory_entry - expected_entry) if memory_entry and expected_entry else 0
        }
    
    def check_unmapped_executable_memory(self, pid: int) -> Dict:
        """
        Kiểm tra xem có memory regions executable nhưng không mapped từ file
        Args:
            pid: Process ID
        Returns: Dict chứa kết quả kiểm tra
        """
        memory_regions = self.process_monitor.get_memory_regions(pid)
        
        # Lọc các regions executable nhưng không phải mapped image
        unmapped_executable = [
            region for region in memory_regions
            if region['is_executable'] and not region['is_mapped']
        ]
        
        return {
            'success': True,
            'total_executable_regions': len([r for r in memory_regions if r['is_executable']]),
            'unmapped_executable_regions': len(unmapped_executable),
            'unmapped_regions': unmapped_executable,
            'has_suspicious_memory': len(unmapped_executable) > 0
        }
    
    def check_section_integrity(self, exe_path: str, pid: int) -> Dict:
        """
        Kiểm tra integrity của sections bằng cách so sánh hash
        (Đơn giản hóa - chỉ so sánh số lượng sections)
        Args:
            exe_path: Đường dẫn đến executable
            pid: Process ID
        Returns: Dict chứa kết quả kiểm tra
        """
        pe_analyzer = PEAnalyzer(exe_path)
        
        if not pe_analyzer.is_valid:
            return {
                'success': False,
                'error': 'Cannot analyze PE file'
            }
        
        sections = pe_analyzer.get_sections_info()
        
        # Trong thực tế, cần đọc memory và so sánh hash
        # Ở đây chỉ return thông tin sections
        
        pe_analyzer.close()
        
        return {
            'success': True,
            'sections': sections,
            'section_count': len(sections),
            'note': 'Full section hash comparison requires deep memory analysis'
        }
    
    def get_comprehensive_analysis(self, exe_path: str, pid: int) -> Dict:
        """
        Phân tích toàn diện process để phát hiện hollowing
        Args:
            exe_path: Đường dẫn đến executable
            pid: Process ID
        Returns: Dict chứa tất cả kết quả phân tích
        """
        results = {
            'exe_path': exe_path,
            'pid': pid,
            'module_comparison': self.compare_modules(exe_path, pid),
            'entry_point_check': self.check_entry_point(exe_path, pid),
            'unmapped_memory_check': self.check_unmapped_executable_memory(pid),
            'section_check': self.check_section_integrity(exe_path, pid)
        }
        
        return results

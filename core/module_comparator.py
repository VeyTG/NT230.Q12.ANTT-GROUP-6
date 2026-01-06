"""
Module Comparator
So sánh modules giữa PE file trên disk và modules loaded trong memory
"""

from typing import Dict, List, Set
from core.pe_analyzer import PEAnalyzer
from core.process_monitor import ProcessMonitor


class ModuleComparator:

    def deep_scan_analysis(self, exe_path: str, pid: int) -> dict:
        """Phân tích sâu: sliding window entropy, phát hiện XOR, patch, nhảy bất thường trong code section và unmapped memory"""
        import struct
        import hashlib
        suspicious_regions = []
        xor_regions = []
        patch_regions = []
        entropy_regions = []
        window_size = 256
        entropy_threshold = 6.5
        xor_threshold = 0.7  # >70% bytes are XORed with a single key
        jump_bytes = {0xE9, 0xEB, 0xEA, 0xFF}  # jmp rel32, jmp rel8, jmp far, jmp/call indirect
        # Helper: sliding window entropy
        def sliding_entropy(data, window=256, threshold=6.5):
            results = []
            for i in range(0, len(data) - window + 1, window // 2):
                chunk = data[i:i+window]
                ent = self._calc_entropy(chunk)
                if ent > threshold:
                    results.append({'offset': i, 'entropy': ent})
            return results
        # Helper: detect XOR pattern (simple: check if most bytes are XORed with a single key)
        def detect_xor(data, window=256, threshold=0.7):
            results = []
            for i in range(0, len(data) - window + 1, window // 2):
                chunk = data[i:i+window]
                key_scores = {}
                for key in range(1, 256):
                    xored = bytes([b ^ key for b in chunk])
                    score = sum(32 <= c <= 126 for c in xored) / window
                    key_scores[key] = score
                best_key, best_score = max(key_scores.items(), key=lambda x: x[1])
                if best_score > threshold:
                    results.append({'offset': i, 'key': best_key, 'score': best_score})
            return results
        # Helper: detect patch/jump (look for jump/call at entry or high density)
        def detect_patch_jump(data, window=32):
            results = []
            for i in range(0, len(data) - window + 1, window):
                chunk = data[i:i+window]
                jump_count = sum(b in jump_bytes for b in chunk)
                if jump_count / window > 0.2:
                    results.append({'offset': i, 'jump_density': jump_count / window})
            # Check entry point for jump/call
            if data and data[0] in jump_bytes:
                results.append({'offset': 0, 'jump_at_entry': True})
            return results
        # Analyze .text section in memory
        from core.pe_analyzer import PEAnalyzer
        from core.process_monitor import ProcessMonitor
        pe = PEAnalyzer(exe_path)
        pm = ProcessMonitor()
        modules = pm.get_process_modules(pid)
        # Fallback: If no modules or cannot get base address, scan all executable memory regions
        if not modules or not (modules[0].get('base_address', 0)):
            # Fallback: scan all executable memory regions
            memory_regions = pm.get_memory_regions(pid)
            suspicious_regions = []
            for r in memory_regions:
                if r['is_executable'] and r['size'] > 0x1000:
                    data = pm.read_process_memory(pid, r['base_address'], min(r['size'], 0x4000))
                    if not data:
                        continue
                    ent = self._calc_entropy(data)
                    ent_regions = sliding_entropy(data, window=window_size, threshold=entropy_threshold)
                    xor_regs = detect_xor(data, window=window_size, threshold=xor_threshold)
                    patch_regs = detect_patch_jump(data, window=32)
                    suspicious_regions.append({
                        'base': r['base_address'],
                        'size': r['size'],
                        'entropy': ent,
                        'entropy_regions': ent_regions,
                        'xor_regions': xor_regs,
                        'patch_regions': patch_regs,
                        'is_mapped': r.get('is_mapped', False)
                    })
            return {
                'success': True,
                'fallback_memory_scan': True,
                'suspicious_regions': suspicious_regions,
                'note': 'No valid module found, fallback to memory region scan.'
            }
        # Normal: scan .text section as before
        if not pe.is_valid:
            return {'success': False, 'error': 'Invalid PE'}
        text_section = None
        for s in pe.get_sections_info():
            if s['name'].lower().startswith('.text'):
                text_section = s
                break
        if not text_section:
            return {'success': False, 'error': 'No .text section'}
        base_addr = modules[0]['base_address'] if modules else None
        if not base_addr:
            return {'success': False, 'error': 'Cannot get base address'}
        mem_data = pm.read_process_memory(pid, base_addr + text_section['virtual_address'], text_section['virtual_size'])
        if not mem_data:
            return {'success': False, 'error': 'Cannot read .text memory'}
        # Sliding window entropy
        entropy_regions = sliding_entropy(mem_data, window=window_size, threshold=entropy_threshold)
        # XOR pattern detection
        xor_regions = detect_xor(mem_data, window=window_size, threshold=xor_threshold)
        # Patch/jump detection
        patch_regions = detect_patch_jump(mem_data, window=32)
        # Analyze unmapped executable memory regions
        shellcode_regions = []
        for r in pm.get_memory_regions(pid):
            if r['is_executable'] and not r['is_mapped'] and r['size'] < 0x4000:
                data = pm.read_process_memory(pid, r['base_address'], min(r['size'], 0x2000))
                if not data:
                    continue
                ent = self._calc_entropy(data)
                ent_regions = sliding_entropy(data, window=window_size, threshold=entropy_threshold)
                xor_regs = detect_xor(data, window=window_size, threshold=xor_threshold)
                patch_regs = detect_patch_jump(data, window=32)
                shellcode_regions.append({
                    'base': r['base_address'],
                    'size': r['size'],
                    'entropy': ent,
                    'entropy_regions': ent_regions,
                    'xor_regions': xor_regs,
                    'patch_regions': patch_regs
                })
        return {
            'success': True,
            'text_section': {
                'entropy_regions': entropy_regions,
                'xor_regions': xor_regions,
                'patch_regions': patch_regions
            },
            'shellcode_regions': shellcode_regions,
            'note': 'Deep scan completed'
        }
    def _calc_entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0.0
        occur = [0]*256
        for b in data:
            occur[b] += 1
        entropy = 0.0
        for c in occur:
            if c:
                p = c/len(data)
                entropy -= p * math.log2(p)
        return entropy

    def check_text_section_memory(self, exe_path: str, pid: int) -> dict:
        """So sánh hash và entropy section .text giữa file và memory"""
        from core.pe_analyzer import PEAnalyzer
        pe = PEAnalyzer(exe_path)
        if not pe.is_valid:
            return {'success': False, 'error': 'Invalid PE'}
        text_section = None
        for s in pe.get_sections_info():
            if s['name'].lower().startswith('.text'):
                text_section = s
                break
        if not text_section:
            return {'success': False, 'error': 'No .text section'}
        file_hash = text_section['hash']
        file_size = text_section['virtual_size']
        file_entropy = self._calc_entropy(bytes.fromhex(text_section['hash'])) if text_section['hash'] else 0
        # Đọc memory vùng .text
        from core.process_monitor import ProcessMonitor
        pm = ProcessMonitor()
        modules = pm.get_process_modules(pid)
        base_addr = modules[0]['base_address'] if modules else None
        if not base_addr:
            return {'success': False, 'error': 'Cannot get base address'}
        mem_data = pm.read_process_memory(pid, base_addr + text_section['virtual_address'], text_section['virtual_size'])
        if not mem_data:
            return {'success': False, 'error': 'Cannot read .text memory'}
        import hashlib
        mem_hash = hashlib.md5(mem_data).hexdigest()
        mem_entropy = self._calc_entropy(mem_data)
        return {
            'success': True,
            'file_hash': file_hash,
            'mem_hash': mem_hash,
            'file_entropy': file_entropy,
            'mem_entropy': mem_entropy,
            'size': file_size,
            'entropy_diff': abs(mem_entropy - file_entropy),
            'hash_match': file_hash == mem_hash
        }

    def check_unmapped_shellcode(self, pid: int) -> dict:
        """Kiểm tra unmapped executable memory nhỏ, entropy cao (dấu hiệu shellcode)"""
        from core.process_monitor import ProcessMonitor
        pm = ProcessMonitor()
        regions = pm.get_memory_regions(pid)
        shellcode_regions = []
        for r in regions:
            if r['is_executable'] and not r['is_mapped'] and r['size'] < 0x4000:
                data = pm.read_process_memory(pid, r['base_address'], min(r['size'], 0x2000))
                entropy = self._calc_entropy(data) if data else 0
                if entropy > 6.5:
                    shellcode_regions.append({'base': r['base_address'], 'size': r['size'], 'entropy': entropy})
        return {
            'success': True,
            'shellcode_regions': shellcode_regions,
            'count': len(shellcode_regions)
        }
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
    
    def get_comprehensive_analysis(self, exe_path: str, pid: int, deep_scan: bool = False) -> Dict:
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
            'section_check': self.check_section_integrity(exe_path, pid),
            'text_section_memory': self.check_text_section_memory(exe_path, pid),
            'unmapped_shellcode': self.check_unmapped_shellcode(pid)
        }
        # Nếu deep_scan, sẽ bổ sung kết quả deep scan ở đây (sẽ triển khai tiếp)
        if deep_scan:
            results['deep_scan'] = self.deep_scan_analysis(exe_path, pid)
        return results

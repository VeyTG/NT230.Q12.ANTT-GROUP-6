"""
Process Monitor Module
Quét và monitor các processes, đọc memory, enumerate modules
"""

import psutil
import win32api
import win32con
import win32process
import win32security
import ctypes
from ctypes import wintypes
from typing import List, Dict, Optional
import os


# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class ProcessMonitor:
    """Monitor processes và memory của chúng"""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.psapi = ctypes.windll.psapi
    
    def enumerate_processes(self) -> List[Dict]:
        """
        Liệt kê tất cả processes đang chạy
        Returns: List các dict chứa thông tin process
        """
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pinfo = proc.info
                if pinfo['exe']:  # Chỉ lấy process có exe path
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe_path': pinfo['exe'],
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else ''
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        return processes
    
    def get_process_modules(self, pid: int) -> List[Dict]:
        """
        Lấy danh sách modules (DLLs) được load trong process
        Args:
            pid: Process ID
        Returns: List các dict chứa thông tin module
        """
        modules = []
        
        try:
            # Mở process với quyền đọc
            h_process = self.kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not h_process:
                return modules
            
            # Enumerate modules
            module_handles = (wintypes.HMODULE * 1024)()
            cb_needed = wintypes.DWORD()
            
            if self.psapi.EnumProcessModules(
                h_process,
                ctypes.byref(module_handles),
                ctypes.sizeof(module_handles),
                ctypes.byref(cb_needed)
            ):
                module_count = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
                
                for i in range(module_count):
                    # Lấy tên module
                    module_name = ctypes.create_unicode_buffer(260)
                    self.psapi.GetModuleFileNameExW(
                        h_process,
                        module_handles[i],
                        module_name,
                        260
                    )
                    
                    # Lấy thông tin module
                    module_info = ctypes.create_string_buffer(24)  # MODULEINFO size
                    self.psapi.GetModuleInformation(
                        h_process,
                        module_handles[i],
                        module_info,
                        24
                    )
                    
                    # Parse MODULEINFO
                    base_address = ctypes.c_void_p.from_buffer(module_info, 0).value
                    size_of_image = ctypes.c_ulong.from_buffer(module_info, 8).value
                    entry_point = ctypes.c_void_p.from_buffer(module_info, 16).value
                    
                    modules.append({
                        'name': os.path.basename(module_name.value).lower(),
                        'path': module_name.value,
                        'base_address': base_address,
                        'size': size_of_image,
                        'entry_point': entry_point
                    })
            
            self.kernel32.CloseHandle(h_process)
            
        except Exception as e:
            pass
        
        return modules
    
    def read_process_memory(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """
        Đọc memory từ process
        Args:
            pid: Process ID
            address: Address cần đọc
            size: Số bytes cần đọc
        Returns: Bytes data hoặc None nếu lỗi
        """
        try:
            h_process = self.kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not h_process:
                return None
            
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            result = self.kernel32.ReadProcessMemory(
                h_process,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            self.kernel32.CloseHandle(h_process)
            
            if result:
                return buffer.raw[:bytes_read.value]
            
        except Exception as e:
            pass
        
        return None
    
    def get_memory_regions(self, pid: int) -> List[Dict]:
        """
        Lấy thông tin về các memory regions của process
        Returns: List các dict chứa thông tin memory region
        """
        regions = []
        
        try:
            h_process = self.kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not h_process:
                return regions
            
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            
            while self.kernel32.VirtualQueryEx(
                h_process,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ):
                # Kiểm tra xem region có executable không
                is_executable = (
                    mbi.Protect & PAGE_EXECUTE or
                    mbi.Protect & PAGE_EXECUTE_READ or
                    mbi.Protect & PAGE_EXECUTE_READWRITE or
                    mbi.Protect & PAGE_EXECUTE_WRITECOPY
                )
                
                # Kiểm tra xem có phải là mapped image không
                is_mapped = (mbi.Type == MEM_IMAGE)
                
                if mbi.State == MEM_COMMIT and is_executable:
                    regions.append({
                        'base_address': mbi.BaseAddress,
                        'size': mbi.RegionSize,
                        'protection': mbi.Protect,
                        'is_executable': is_executable,
                        'is_mapped': is_mapped,
                        'type': mbi.Type
                    })
                
                address += mbi.RegionSize
                
                # Tránh infinite loop
                if address >= 0x7FFFFFFF00000000:
                    break
            
            self.kernel32.CloseHandle(h_process)
            
        except Exception as e:
            pass
        
        return regions
    
    def get_process_entry_point(self, pid: int) -> Optional[int]:
        """
        Lấy entry point của process từ memory
        """
        modules = self.get_process_modules(pid)
        if modules:
            # Entry point của module đầu tiên (main executable)
            return modules[0].get('entry_point')
        return None
    
    def is_process_accessible(self, pid: int) -> bool:
        """
        Kiểm tra xem có thể access process không
        """
        try:
            h_process = self.kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if h_process:
                self.kernel32.CloseHandle(h_process)
                return True
            
        except:
            pass
        
        return False

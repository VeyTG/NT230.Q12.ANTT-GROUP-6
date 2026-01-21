"""
PE Analyzer Module
Phân tích PE file để lấy thông tin về Import Table, Sections, Entry Point
"""

import pefile
import hashlib
import os
from typing import List, Dict, Optional


class PEAnalyzer:
    """Phân tích PE file và trích xuất thông tin cần thiết"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.pe = None
        self.is_valid = False
        
        try:
            if os.path.exists(file_path):
                self.pe = pefile.PE(file_path, fast_load=True)
                self.pe.parse_data_directories()
                self.is_valid = True
        except Exception as e:
            self.is_valid = False
            self.error = str(e)
    
    def get_imported_dlls(self) -> List[str]:
        """
        Lấy danh sách các DLL được import từ Import Table
        Returns: List các tên DLL (lowercase để so sánh)
        """
        if not self.is_valid or not self.pe:
            return []
        
        imported_dlls = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    imported_dlls.append(dll_name)
        except Exception as e:
            pass
        
        return imported_dlls
    
    def get_entry_point(self) -> int:
        """
        Lấy Entry Point của PE file
        Returns: Virtual address của entry point
        """
        if not self.is_valid or not self.pe:
            return 0
        
        try:
            return self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except:
            return 0
    
    def get_image_base(self) -> int:
        """
        Lấy Image Base address
        Returns: Base address mặc định
        """
        if not self.is_valid or not self.pe:
            return 0
        
        try:
            return self.pe.OPTIONAL_HEADER.ImageBase
        except:
            return 0
    
    def get_sections_info(self) -> List[Dict]:
        """
        Lấy thông tin về các sections trong PE file
        Returns: List các dict chứa thông tin section
        """
        if not self.is_valid or not self.pe:
            return []
        
        sections = []
        try:
            for section in self.pe.sections:
                section_data = {
                    'name': section.Name.decode('utf-8').rstrip('\x00'),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics,
                    'hash': self._calculate_section_hash(section)
                }
                sections.append(section_data)
        except Exception as e:
            pass
        
        return sections
    
    def _calculate_section_hash(self, section) -> str:
        """
        Tính MD5 hash của section data
        """
        try:
            data = section.get_data()
            return hashlib.md5(data).hexdigest()
        except:
            return ""
    
    def get_pe_header_hash(self) -> str:
        """
        Tính hash của PE header để so sánh
        """
        if not self.is_valid or not self.pe:
            return ""
        
        try:
            header_data = self.pe.header
            return hashlib.md5(header_data).hexdigest()
        except:
            return ""
    
    def is_executable(self) -> bool:
        """
        Kiểm tra xem file có phải là executable không
        """
        if not self.is_valid or not self.pe:
            return False
        
        try:
            return (self.pe.OPTIONAL_HEADER.Subsystem == 
                    pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_CUI'] or
                    self.pe.OPTIONAL_HEADER.Subsystem == 
                    pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_GUI'])
        except:
            return False
    
    def get_file_info(self) -> Dict:
        """
        Lấy tổng hợp thông tin về PE file
        """
        if not self.is_valid:
            return {
                'valid': False,
                'file_path': self.file_path,
                'error': getattr(self, 'error', 'Unknown error')
            }
        
        return {
            'valid': True,
            'file_path': self.file_path,
            'image_base': hex(self.get_image_base()),
            'entry_point': hex(self.get_entry_point()),
            'imported_dlls': self.get_imported_dlls(),
            'sections': self.get_sections_info(),
            'is_executable': self.is_executable(),
            'pe_hash': self.get_pe_header_hash()
        }
    
    def close(self):
        """Đóng PE file"""
        if self.pe:
            try:
                self.pe.close()
            except:
                pass

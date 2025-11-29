# Core modules
from core.pe_analyzer import PEAnalyzer
from core.process_monitor import ProcessMonitor
from core.module_comparator import ModuleComparator
from core.detector import DetectionEngine, HollowingIndicator

# Utility modules
from utils.logger import setup_logger, get_logger
from utils.reporter import Reporter

__version__ = "1.0.0"
__all__ = [
    'PEAnalyzer',
    'ProcessMonitor',
    'ModuleComparator',
    'DetectionEngine',
    'HollowingIndicator',
    'setup_logger',
    'get_logger',
    'Reporter'
]

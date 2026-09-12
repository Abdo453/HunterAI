"""HunterAI Detectors Package"""
from core.detectors.xss_detector import XSSDetector
from core.detectors.sqli_detector import SQLiDetector

__all__ = ["XSSDetector", "SQLiDetector"]

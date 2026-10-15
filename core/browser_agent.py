"""
Backward-compatibility alias for BrowserAgent 2.0
"""
from core.system.browser_v2 import BrowserAgent, DOMAnnotator, HistoryManager, DOMAnnotation

__all__ = ["BrowserAgent", "DOMAnnotator", "HistoryManager", "DOMAnnotation"]

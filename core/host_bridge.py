"""
Backward-compatibility alias for HostBridge
"""
from core.system.host_bridge import HostBridge, HostGuard, FileManager, NetworkInspector

__all__ = ["HostBridge", "HostGuard", "FileManager", "NetworkInspector"]

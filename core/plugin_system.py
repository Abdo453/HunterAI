"""
Backward-compatibility alias for Plugin System
"""
from core.system.plugin_system import PluginLoader, PluginRegistry, PluginManifest, BasePlugin

__all__ = ["PluginLoader", "PluginRegistry", "PluginManifest", "BasePlugin"]

"""
HunterAI Extensible Plugin System (Phase 11)
=============================================
Enables modular extension of HunterAI through sandboxed plugins:
  1. PluginLoader: Dynamically discovers and loads plugins from `plugins/`
  2. Permission Enforcement: Enforces manifest-declared allowed_actions
  3. PluginRegistry: Central registry for execution dispatch and lifecycle
"""
from __future__ import annotations

import importlib.util
import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger("hunter_ai.plugin_system")


@dataclass
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    description: str
    allowed_actions: List[str]
    entry_file: str = "plugin.py"
    author: str = ""
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PluginManifest:
        return cls(
            plugin_id=str(data.get("plugin_id") or data.get("id")),
            name=str(data.get("name", "Unnamed Plugin")),
            version=str(data.get("version", "1.0.0")),
            description=str(data.get("description", "")),
            allowed_actions=list(data.get("allowed_actions", [])),
            entry_file=str(data.get("entry_file", "plugin.py")),
            author=str(data.get("author", "")),
            enabled=bool(data.get("enabled", True)),
        )


class BasePlugin:
    """Base class that all HunterAI plugins inherit from"""
    manifest: PluginManifest

    def initialize(self) -> None:
        pass

    def execute_action(self, action: str, **kwargs) -> Any:
        raise NotImplementedError

    def teardown(self) -> None:
        pass


class PluginRegistry:
    """
    Central registry storing active plugins and enforcing action permissions.
    """
    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._manifests: Dict[str, PluginManifest] = {}

    def register(self, plugin: BasePlugin, manifest: PluginManifest) -> None:
        if not manifest.enabled:
            logger.info("Skipping disabled plugin: %s", manifest.plugin_id)
            return
        self._plugins[manifest.plugin_id] = plugin
        self._manifests[manifest.plugin_id] = manifest
        plugin.initialize()
        logger.info("Registered plugin: id=%s name='%s' allowed_actions=%s", manifest.plugin_id, manifest.name, manifest.allowed_actions)

    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        return self._plugins.get(plugin_id)

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [asdict(m) for m in self._manifests.values()]

    def execute_action(self, plugin_id: str, action: str, **kwargs) -> Dict[str, Any]:
        """
        Executes an action on a registered plugin after verifying manifest permissions.
        """
        manifest = self._manifests.get(plugin_id)
        plugin = self._plugins.get(plugin_id)
        if not manifest or not plugin:
            return {"success": False, "error": f"Plugin '{plugin_id}' is not registered."}

        # Permission check
        if action not in manifest.allowed_actions:
            logger.warning("Plugin permission denied: action '%s' not in %s for plugin %s", action, manifest.allowed_actions, plugin_id)
            return {
                "success": False,
                "error": f"Permission denied: action '{action}' is not authorized in plugin manifest.",
                "allowed_actions": manifest.allowed_actions,
            }

        try:
            result = plugin.execute_action(action, **kwargs)
            return {"success": True, "action": action, "result": result}
        except Exception as e:
            logger.exception("Plugin execution error in %s.%s: %s", plugin_id, action, e)
            return {"success": False, "action": action, "error": str(e)}


class PluginLoader:
    """
    Discovers, validates, and loads plugins from the `plugins/` directory.
    """
    def __init__(self, plugins_dir: str | Path = "plugins", registry: Optional[PluginRegistry] = None):
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self.registry = registry or PluginRegistry()

    def discover_and_load_all(self) -> PluginRegistry:
        """Scans plugins/ directory for valid plugin bundles"""
        for item in self.plugins_dir.iterdir():
            if item.is_dir():
                manifest_file = item / "manifest.json"
                if manifest_file.exists():
                    try:
                        self._load_plugin_bundle(item, manifest_file)
                    except Exception as e:
                        logger.warning("Failed loading plugin bundle from %s: %s", item, e)
        return self.registry

    def _load_plugin_bundle(self, bundle_dir: Path, manifest_file: Path) -> None:
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        manifest = PluginManifest.from_dict(manifest_data)
        
        entry_path = bundle_dir / manifest.entry_file
        if not entry_path.exists():
            raise FileNotFoundError(f"Plugin entry file not found: {entry_path}")

        # Dynamic import
        module_name = f"hunter_ai_plugin_{manifest.plugin_id}"
        spec = importlib.util.spec_from_file_location(module_name, entry_path)
        if not spec or not spec.loader:
            raise ImportError(f"Could not build spec for plugin module {entry_path}")

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Find plugin class
        plugin_cls: Optional[Type[BasePlugin]] = None
        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                plugin_cls = attr
                break

        if not plugin_cls:
            raise ValueError(f"No BasePlugin subclass found in {entry_path}")

        instance = plugin_cls()
        instance.manifest = manifest
        self.registry.register(instance, manifest)

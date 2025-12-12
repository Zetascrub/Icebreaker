"""
Plugin system for custom analyzers.
"""
from __future__ import annotations
import os
import importlib.util
import inspect
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Type
from pathlib import Path


class AnalyzerPlugin(ABC):
    """Base class for analyzer plugins."""

    name: str = "base_plugin"
    description: str = "Base analyzer plugin"
    version: str = "1.0.0"
    author: str = "Unknown"

    @abstractmethod
    async def analyze(self, target: str, port: int, service: str, banner: str = "") -> List[Dict[str, Any]]:
        """
        Analyze a target and return findings.

        Args:
            target: Target IP or hostname
            port: Target port
            service: Detected service name
            banner: Service banner if available

        Returns:
            List of findings, each with keys:
                - title: Finding title
                - description: Finding description
                - severity: low, medium, high, critical
                - recommendation: How to fix
                - references: List of reference URLs
                - cvss_score: Optional CVSS score
                - cve_ids: Optional list of CVE IDs
        """
        pass

    def supports_service(self, service: str) -> bool:
        """
        Check if this plugin supports analyzing the given service.

        Args:
            service: Service name

        Returns:
            True if plugin can analyze this service
        """
        return True

    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author
        }


class PluginManager:
    """Manager for loading and executing analyzer plugins."""

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """
        Initialize plugin manager.

        Args:
            plugin_dirs: List of directories to search for plugins
        """
        self.plugins: Dict[str, AnalyzerPlugin] = {}
        self.plugin_dirs = plugin_dirs or self._get_default_plugin_dirs()

    def _get_default_plugin_dirs(self) -> List[str]:
        """Get default plugin directories."""
        dirs = []

        # Built-in plugins
        builtin_dir = Path(__file__).parent.parent / "plugins"
        dirs.append(str(builtin_dir))

        # User plugins
        if os.path.exists("/data"):
            dirs.append("/data/plugins")
        else:
            dirs.append("./plugins")

        return dirs

    def load_plugins(self):
        """Load all plugins from plugin directories."""
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                os.makedirs(plugin_dir, exist_ok=True)
                continue

            self._load_plugins_from_dir(plugin_dir)

    def _load_plugins_from_dir(self, plugin_dir: str):
        """Load plugins from a specific directory."""
        plugin_path = Path(plugin_dir)

        for file_path in plugin_path.glob("*.py"):
            if file_path.name.startswith("_"):
                continue

            try:
                self._load_plugin_file(file_path)
            except Exception as e:
                print(f"Error loading plugin {file_path}: {e}")

    def _load_plugin_file(self, file_path: Path):
        """Load a single plugin file."""
        module_name = file_path.stem
        spec = importlib.util.spec_from_file_location(module_name, file_path)

        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find all AnalyzerPlugin subclasses in the module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, AnalyzerPlugin) and
                    obj is not AnalyzerPlugin and
                    not inspect.isabstract(obj)):

                    # Instantiate the plugin
                    plugin = obj()
                    self.plugins[plugin.name] = plugin
                    print(f"Loaded plugin: {plugin.name} v{plugin.version}")

    def get_plugin(self, name: str) -> Optional[AnalyzerPlugin]:
        """Get a plugin by name."""
        return self.plugins.get(name)

    def get_all_plugins(self) -> List[AnalyzerPlugin]:
        """Get all loaded plugins."""
        return list(self.plugins.values())

    def get_plugins_for_service(self, service: str) -> List[AnalyzerPlugin]:
        """Get all plugins that support a specific service."""
        return [
            plugin for plugin in self.plugins.values()
            if plugin.supports_service(service)
        ]

    async def analyze_with_plugins(
        self,
        target: str,
        port: int,
        service: str,
        banner: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Run all applicable plugins on a target.

        Args:
            target: Target IP or hostname
            port: Target port
            service: Service name
            banner: Service banner

        Returns:
            Combined list of findings from all plugins
        """
        findings = []

        for plugin in self.get_plugins_for_service(service):
            try:
                plugin_findings = await plugin.analyze(target, port, service, banner)
                findings.extend(plugin_findings)
            except Exception as e:
                print(f"Error running plugin {plugin.name}: {e}")

        return findings

    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins with their metadata."""
        return [plugin.get_metadata() for plugin in self.plugins.values()]

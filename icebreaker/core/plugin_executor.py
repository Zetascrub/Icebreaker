"""
Plugin executor for running vulnerability checks with code execution.

This module provides safe execution of plugin code with:
- Variable injection (target, port, service, banner)
- Timeout handling
- Error capture
- Finding generation from plugin results
"""
from __future__ import annotations
import asyncio
import importlib.util
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from icebreaker.db.models import Plugin, Finding


class PluginExecutor:
    """
    Executes plugins against services during scans.

    Plugins are Python code that:
    1. Receive variables: target, port, service, banner, etc.
    2. Perform checks (e.g., SSH cipher enumeration, TLS version check)
    3. Return findings with title, description, severity, recommendation
    """

    def __init__(self, db: Session):
        self.db = db
        self.execution_stats = {
            'total_executed': 0,
            'successful': 0,
            'failed': 0,
            'findings_generated': 0
        }

    async def get_applicable_plugins(
        self,
        service: str,
        port: int
    ) -> List[Plugin]:
        """
        Get all enabled plugins that should run for this service/port combination.

        Args:
            service: Service name (e.g., "ssh", "http", "https")
            port: Port number (e.g., 22, 80, 443)

        Returns:
            List of Plugin objects that match the criteria
        """
        # Get all enabled plugins
        plugins = self.db.query(Plugin).filter(Plugin.enabled == True).all()

        applicable = []
        for plugin in plugins:
            # Check service match
            if plugin.target_services:
                if service.lower() not in [s.lower() for s in plugin.target_services]:
                    continue

            # Check port match (if plugin specifies ports)
            if plugin.target_ports:
                if port not in plugin.target_ports:
                    continue

            applicable.append(plugin)

        return applicable

    async def execute_plugin(
        self,
        plugin: Plugin,
        variables: Dict[str, Any],
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a single plugin with injected variables.

        Args:
            plugin: Plugin object from database
            variables: Dictionary of variables to inject (target, port, service, banner, etc.)
            timeout: Optional timeout override (default: plugin.timeout_seconds)

        Returns:
            Dictionary with:
                - success: bool
                - findings: List of finding dicts
                - error: str (if failed)
                - execution_time: float (seconds)
        """
        start_time = asyncio.get_event_loop().time()
        timeout_sec = timeout or plugin.timeout_seconds

        try:
            # Validate required variables
            if plugin.required_variables:
                missing = [v for v in plugin.required_variables if v not in variables]
                if missing:
                    return {
                        'success': False,
                        'findings': [],
                        'error': f"Missing required variables: {', '.join(missing)}",
                        'execution_time': 0
                    }

            # Get plugin code
            if plugin.code_type == "inline":
                code = plugin.code
                if not code:
                    return {
                        'success': False,
                        'findings': [],
                        'error': "No inline code provided",
                        'execution_time': 0
                    }
            elif plugin.code_type == "file":
                code_path = Path(plugin.code_file_path)
                if not code_path.exists():
                    return {
                        'success': False,
                        'findings': [],
                        'error': f"Code file not found: {plugin.code_file_path}",
                        'execution_time': 0
                    }
                code = code_path.read_text()
            else:
                return {
                    'success': False,
                    'findings': [],
                    'error': f"Invalid code_type: {plugin.code_type}",
                    'execution_time': 0
                }

            # Execute plugin code with timeout
            result = await asyncio.wait_for(
                self._execute_code(code, variables, plugin),
                timeout=timeout_sec
            )

            end_time = asyncio.get_event_loop().time()
            execution_time = end_time - start_time

            # Update plugin statistics
            plugin.last_executed = datetime.utcnow()
            plugin.execution_count += 1
            self.db.commit()

            self.execution_stats['total_executed'] += 1
            self.execution_stats['successful'] += 1
            self.execution_stats['findings_generated'] += len(result.get('findings', []))

            return {
                'success': True,
                'findings': result.get('findings', []),
                'error': None,
                'execution_time': execution_time
            }

        except asyncio.TimeoutError:
            end_time = asyncio.get_event_loop().time()
            self.execution_stats['total_executed'] += 1
            self.execution_stats['failed'] += 1

            return {
                'success': False,
                'findings': [],
                'error': f"Plugin execution timed out after {timeout_sec} seconds",
                'execution_time': end_time - start_time
            }

        except Exception as e:
            end_time = asyncio.get_event_loop().time()
            self.execution_stats['total_executed'] += 1
            self.execution_stats['failed'] += 1

            return {
                'success': False,
                'findings': [],
                'error': f"Plugin execution error: {str(e)}",
                'execution_time': end_time - start_time
            }

    async def _execute_code(
        self,
        code: str,
        variables: Dict[str, Any],
        plugin: Plugin
    ) -> Dict[str, Any]:
        """
        Execute plugin code in a controlled environment.

        Args:
            code: Python code to execute
            variables: Variables to inject into execution context
            plugin: Plugin object (for metadata)

        Returns:
            Dictionary with 'findings' list
        """
        # Create execution namespace with injected variables
        exec_globals = {
            '__builtins__': __builtins__,
            'asyncio': asyncio,
            # Injected variables
            **variables
        }

        exec_locals = {}

        # Execute the plugin code
        # The code is expected to define a function called 'check' that returns findings
        try:
            exec(code, exec_globals, exec_locals)
        except SyntaxError as e:
            raise Exception(f"Syntax error in plugin code: {e}")

        # Look for the 'check' function
        if 'check' not in exec_locals:
            raise Exception("Plugin code must define a 'check()' function")

        check_func = exec_locals['check']

        # Call the check function
        if asyncio.iscoroutinefunction(check_func):
            result = await check_func()
        else:
            # Run sync function in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, check_func)

        # Validate result format
        if not isinstance(result, dict):
            raise Exception("check() function must return a dictionary")

        if 'findings' not in result:
            result = {'findings': []}

        if not isinstance(result['findings'], list):
            raise Exception("check() function must return {'findings': [list]}")

        return result

    async def execute_plugins_for_service(
        self,
        scan_id: int,
        target: str,
        port: int,
        service: str,
        banner: str = "",
        extra_vars: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """
        Execute all applicable plugins for a service and create Finding objects.

        Args:
            scan_id: Scan ID to associate findings with
            target: Target IP/hostname
            port: Port number
            service: Service name (e.g., "ssh", "http")
            banner: Service banner if available
            extra_vars: Additional variables to inject into plugins

        Returns:
            List of Finding objects created by plugins
        """
        # Get applicable plugins
        plugins = await self.get_applicable_plugins(service, port)

        if not plugins:
            return []

        # Prepare base variables
        variables = {
            'target': target,
            'port': port,
            'service': service,
            'banner': banner,
            'scan_id': scan_id
        }

        if extra_vars:
            variables.update(extra_vars)

        findings = []

        # Execute each plugin
        for plugin in plugins:
            result = await self.execute_plugin(plugin, variables)

            if result['success'] and result['findings']:
                # Convert plugin findings to Finding objects
                for finding_data in result['findings']:
                    finding = self._create_finding_from_plugin(
                        scan_id=scan_id,
                        plugin=plugin,
                        finding_data=finding_data,
                        target=target,
                        port=port
                    )
                    findings.append(finding)

        return findings

    def _create_finding_from_plugin(
        self,
        scan_id: int,
        plugin: Plugin,
        finding_data: Dict[str, Any],
        target: str,
        port: int
    ) -> Finding:
        """
        Create a Finding object from plugin result data.

        Args:
            scan_id: Scan ID
            plugin: Plugin that generated the finding
            finding_data: Finding data from plugin (title, description, severity, etc.)
            target: Target IP/hostname
            port: Port number

        Returns:
            Finding object (not yet added to session)
        """
        # Generate unique finding_id
        finding_id = f"FIND-{uuid.uuid4().hex[:12].upper()}"

        # Extract fields from plugin result
        title = finding_data.get('title', f"Finding from {plugin.name}")
        description = finding_data.get('description', '')
        severity = finding_data.get('severity', plugin.severity).upper()
        recommendation = finding_data.get('recommendation', '')
        confidence = finding_data.get('confidence', 1.0)
        risk_score = finding_data.get('risk_score')

        # Validate severity
        if severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity = plugin.severity

        # Build details object
        details = {
            'plugin_id': plugin.plugin_id,
            'plugin_name': plugin.name,
            'plugin_version': plugin.version,
            'raw_output': finding_data.get('raw_output', ''),
            'references': finding_data.get('references', []),
            'cve_ids': finding_data.get('cve_ids', [])
        }

        # Create Finding object
        finding = Finding(
            scan_id=scan_id,
            finding_id=finding_id,
            title=title,
            severity=severity,
            target=target,
            port=port,
            confidence=confidence,
            risk_score=risk_score,
            recommendation=recommendation,
            details=details,
            tags=plugin.tags or [],
            template_id=plugin.template_id,
            status='new',
            false_positive=False,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )

        return finding

    def get_stats(self) -> Dict[str, int]:
        """Get execution statistics."""
        return self.execution_stats.copy()

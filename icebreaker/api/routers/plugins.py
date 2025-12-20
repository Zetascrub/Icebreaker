"""
Plugins API router - CRUD operations for vulnerability check plugins.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from icebreaker.db.database import get_db
from icebreaker.db.models import Plugin

router = APIRouter()


# Pydantic models
class PluginCreate(BaseModel):
    """Request model for creating a new plugin."""
    plugin_id: str
    name: str
    description: str
    author: Optional[str] = None
    version: str = "1.0.0"
    target_services: List[str] = []
    target_ports: List[int] = []
    code_type: str = "inline"
    code: Optional[str] = None
    code_file_path: Optional[str] = None
    template_id: Optional[int] = None
    enabled: bool = True
    severity: str = "INFO"
    tags: List[str] = []
    timeout_seconds: int = 30
    required_variables: List[str] = []


class PluginUpdate(BaseModel):
    """Request model for updating a plugin."""
    name: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    version: Optional[str] = None
    target_services: Optional[List[str]] = None
    target_ports: Optional[List[int]] = None
    code_type: Optional[str] = None
    code: Optional[str] = None
    code_file_path: Optional[str] = None
    template_id: Optional[int] = None
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    tags: Optional[List[str]] = None
    timeout_seconds: Optional[int] = None
    required_variables: Optional[List[str]] = None


@router.get("/plugins")
async def list_plugins(
    enabled_only: bool = False,
    service: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all plugins with optional filtering."""
    query = db.query(Plugin)

    if enabled_only:
        query = query.filter(Plugin.enabled == True)

    if service:
        # Filter plugins that target this service
        # This is a simple contains check on the JSON array
        plugins = query.all()
        plugins = [p for p in plugins if not p.target_services or service.lower() in [s.lower() for s in p.target_services]]
    else:
        plugins = query.all()

    return [{
        'id': p.id,
        'plugin_id': p.plugin_id,
        'name': p.name,
        'description': p.description,
        'author': p.author,
        'version': p.version,
        'target_services': p.target_services,
        'target_ports': p.target_ports,
        'code_type': p.code_type,
        'enabled': p.enabled,
        'severity': p.severity,
        'tags': p.tags,
        'timeout_seconds': p.timeout_seconds,
        'execution_count': p.execution_count,
        'last_executed': p.last_executed.isoformat() if p.last_executed else None,
        'created_at': p.created_at.isoformat(),
        'updated_at': p.updated_at.isoformat()
    } for p in plugins]


@router.get("/plugins/{plugin_id}")
async def get_plugin(plugin_id: int, db: Session = Depends(get_db)):
    """Get a single plugin by ID."""
    plugin = db.query(Plugin).filter(Plugin.id == plugin_id).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    return {
        'id': plugin.id,
        'plugin_id': plugin.plugin_id,
        'name': plugin.name,
        'description': plugin.description,
        'author': plugin.author,
        'version': plugin.version,
        'target_services': plugin.target_services,
        'target_ports': plugin.target_ports,
        'code_type': plugin.code_type,
        'code': plugin.code,
        'code_file_path': plugin.code_file_path,
        # 'template_id': removed - finding templates no longer exist
        'enabled': plugin.enabled,
        'severity': plugin.severity,
        'tags': plugin.tags,
        'timeout_seconds': plugin.timeout_seconds,
        'required_variables': plugin.required_variables,
        'execution_count': plugin.execution_count,
        'last_executed': plugin.last_executed.isoformat() if plugin.last_executed else None,
        'created_at': plugin.created_at.isoformat(),
        'updated_at': plugin.updated_at.isoformat()
    }


@router.post("/plugins")
async def create_plugin(plugin: PluginCreate, db: Session = Depends(get_db)):
    """Create a new plugin."""
    # Check if plugin_id already exists
    existing = db.query(Plugin).filter(Plugin.plugin_id == plugin.plugin_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Plugin with ID {plugin.plugin_id} already exists")

    # Validate code
    if plugin.code_type == "inline" and not plugin.code:
        raise HTTPException(status_code=400, detail="Inline plugins must have code")
    if plugin.code_type == "file" and not plugin.code_file_path:
        raise HTTPException(status_code=400, detail="File plugins must have code_file_path")

    # Create plugin
    new_plugin = Plugin(
        plugin_id=plugin.plugin_id,
        name=plugin.name,
        description=plugin.description,
        author=plugin.author,
        version=plugin.version,
        target_services=plugin.target_services,
        target_ports=plugin.target_ports,
        code_type=plugin.code_type,
        code=plugin.code,
        code_file_path=plugin.code_file_path,
        # template_id removed - finding templates no longer exist
        enabled=plugin.enabled,
        severity=plugin.severity,
        tags=plugin.tags,
        timeout_seconds=plugin.timeout_seconds,
        required_variables=plugin.required_variables,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    db.add(new_plugin)
    db.commit()
    db.refresh(new_plugin)

    return {
        'success': True,
        'plugin_id': new_plugin.id,
        'message': f"Plugin {new_plugin.plugin_id} created successfully"
    }


@router.put("/plugins/{plugin_id}")
async def update_plugin(plugin_id: int, plugin: PluginUpdate, db: Session = Depends(get_db)):
    """Update an existing plugin."""
    existing = db.query(Plugin).filter(Plugin.id == plugin_id).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Plugin not found")

    # Update fields if provided
    if plugin.name is not None:
        existing.name = plugin.name
    if plugin.description is not None:
        existing.description = plugin.description
    if plugin.author is not None:
        existing.author = plugin.author
    if plugin.version is not None:
        existing.version = plugin.version
    if plugin.target_services is not None:
        existing.target_services = plugin.target_services
    if plugin.target_ports is not None:
        existing.target_ports = plugin.target_ports
    if plugin.code_type is not None:
        existing.code_type = plugin.code_type
    if plugin.code is not None:
        existing.code = plugin.code
    if plugin.code_file_path is not None:
        existing.code_file_path = plugin.code_file_path
    # template_id removed - finding templates no longer exist
    if plugin.enabled is not None:
        existing.enabled = plugin.enabled
    if plugin.severity is not None:
        existing.severity = plugin.severity
    if plugin.tags is not None:
        existing.tags = plugin.tags
    if plugin.timeout_seconds is not None:
        existing.timeout_seconds = plugin.timeout_seconds
    if plugin.required_variables is not None:
        existing.required_variables = plugin.required_variables

    existing.updated_at = datetime.utcnow()

    db.commit()

    return {
        'success': True,
        'message': f"Plugin {existing.plugin_id} updated successfully"
    }


@router.delete("/plugins/{plugin_id}")
async def delete_plugin(plugin_id: int, db: Session = Depends(get_db)):
    """Delete a plugin."""
    plugin = db.query(Plugin).filter(Plugin.id == plugin_id).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    db.delete(plugin)
    db.commit()

    return {
        'success': True,
        'message': f"Plugin {plugin.plugin_id} deleted successfully"
    }


@router.post("/plugins/{plugin_id}/toggle")
async def toggle_plugin(plugin_id: int, db: Session = Depends(get_db)):
    """Enable or disable a plugin."""
    plugin = db.query(Plugin).filter(Plugin.id == plugin_id).first()
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")

    plugin.enabled = not plugin.enabled
    plugin.updated_at = datetime.utcnow()
    db.commit()

    return {
        'success': True,
        'enabled': plugin.enabled,
        'message': f"Plugin {'enabled' if plugin.enabled else 'disabled'}"
    }

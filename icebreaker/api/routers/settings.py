"""
Settings API router - Manage scan profiles and settings.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from icebreaker.db.database import get_db
from icebreaker.db.models import (
    ScanProfile, PortPreset, AIServiceConfig, ScanDefaults,
    SMTPConfig, CVEConfig, ScanRetentionPolicy
)

router = APIRouter()


class ScanProfileCreate(BaseModel):
    """Request model for creating a scan profile."""
    name: str
    description: str | None = None
    config: dict
    is_default: bool = False


class ScanProfileResponse(BaseModel):
    """Response model for scan profile."""
    id: int
    name: str
    description: str | None
    config: dict
    is_default: bool

    class Config:
        from_attributes = True


@router.get("/profiles", response_model=List[ScanProfileResponse])
async def list_profiles(db: Session = Depends(get_db)):
    """Get all scan profiles."""
    profiles = db.query(ScanProfile).all()
    return profiles


@router.post("/profiles", response_model=ScanProfileResponse)
async def create_profile(profile: ScanProfileCreate, db: Session = Depends(get_db)):
    """Create a new scan profile."""
    # Check if name already exists
    existing = db.query(ScanProfile).filter(ScanProfile.name == profile.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Profile with this name already exists")

    db_profile = ScanProfile(**profile.dict())
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)

    return db_profile


@router.delete("/profiles/{profile_id}")
async def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    """Delete a scan profile."""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    db.delete(profile)
    db.commit()

    return {"message": "Profile deleted successfully"}


# Pydantic models for new settings
class PortPresetCreate(BaseModel):
    """Request model for creating port preset."""
    name: str
    description: Optional[str] = None
    ports: str
    is_default: bool = False


class PortPresetResponse(BaseModel):
    """Response model for port preset."""
    id: int
    name: str
    description: Optional[str]
    ports: str
    is_default: bool
    created_at: datetime

    class Config:
        from_attributes = True


class AIServiceConfigCreate(BaseModel):
    """Request model for AI service configuration."""
    provider: str
    enabled: bool = True
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None
    config: dict = {}


class AIServiceConfigResponse(BaseModel):
    """Response model for AI service configuration."""
    id: int
    provider: str
    enabled: bool
    api_key: Optional[str]
    base_url: Optional[str]
    model: Optional[str]
    config: dict

    class Config:
        from_attributes = True


class ScanDefaultsUpdate(BaseModel):
    """Request model for updating scan defaults."""
    setting_name: str
    setting_value: str
    description: Optional[str] = None


class SMTPConfigUpdate(BaseModel):
    """Request model for SMTP configuration."""
    server: str
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    from_email: str
    use_tls: bool = True


class CVEConfigUpdate(BaseModel):
    """Request model for CVE configuration."""
    nvd_api_key: Optional[str] = None
    cache_duration_days: int = 7
    auto_lookup: bool = True


class RetentionPolicyUpdate(BaseModel):
    """Request model for retention policy."""
    retention_days: int = 90
    auto_cleanup: bool = False
    keep_critical_findings: bool = True


# Port Presets endpoints
@router.get("/port-presets", response_model=List[PortPresetResponse])
async def list_port_presets(db: Session = Depends(get_db)):
    """Get all port presets."""
    presets = db.query(PortPreset).all()
    return presets


@router.post("/port-presets", response_model=PortPresetResponse)
async def create_port_preset(preset: PortPresetCreate, db: Session = Depends(get_db)):
    """Create a new port preset."""
    existing = db.query(PortPreset).filter(PortPreset.name == preset.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Preset name already exists")

    db_preset = PortPreset(**preset.dict())
    db.add(db_preset)
    db.commit()
    db.refresh(db_preset)
    return db_preset


@router.put("/port-presets/{preset_id}", response_model=PortPresetResponse)
async def update_port_preset(
    preset_id: int,
    preset: PortPresetCreate,
    db: Session = Depends(get_db)
):
    """Update a port preset."""
    db_preset = db.query(PortPreset).filter(PortPreset.id == preset_id).first()
    if not db_preset:
        raise HTTPException(status_code=404, detail="Preset not found")

    for key, value in preset.dict().items():
        setattr(db_preset, key, value)

    db.commit()
    db.refresh(db_preset)
    return db_preset


@router.delete("/port-presets/{preset_id}")
async def delete_port_preset(preset_id: int, db: Session = Depends(get_db)):
    """Delete a port preset."""
    db_preset = db.query(PortPreset).filter(PortPreset.id == preset_id).first()
    if not db_preset:
        raise HTTPException(status_code=404, detail="Preset not found")

    db.delete(db_preset)
    db.commit()
    return {"message": "Preset deleted successfully"}


# AI Service Configuration endpoints
@router.get("/ai-services", response_model=List[AIServiceConfigResponse])
async def list_ai_services(db: Session = Depends(get_db)):
    """Get all AI service configurations."""
    services = db.query(AIServiceConfig).all()
    # Mask API keys in response
    for service in services:
        if service.api_key:
            service.api_key = "***" + service.api_key[-4:] if len(service.api_key) > 4 else "****"
    return services


@router.post("/ai-services", response_model=AIServiceConfigResponse)
async def create_ai_service(service: AIServiceConfigCreate, db: Session = Depends(get_db)):
    """Create or update AI service configuration."""
    existing = db.query(AIServiceConfig).filter(
        AIServiceConfig.provider == service.provider
    ).first()

    if existing:
        for key, value in service.dict().items():
            setattr(existing, key, value)
        db.commit()
        db.refresh(existing)
        if existing.api_key:
            existing.api_key = "***" + existing.api_key[-4:]
        return existing
    else:
        db_service = AIServiceConfig(**service.dict())
        db.add(db_service)
        db.commit()
        db.refresh(db_service)
        if db_service.api_key:
            db_service.api_key = "***" + db_service.api_key[-4:]
        return db_service


@router.delete("/ai-services/{provider}")
async def delete_ai_service(provider: str, db: Session = Depends(get_db)):
    """Delete AI service configuration."""
    db_service = db.query(AIServiceConfig).filter(
        AIServiceConfig.provider == provider
    ).first()
    if not db_service:
        raise HTTPException(status_code=404, detail="AI service not found")

    db.delete(db_service)
    db.commit()
    return {"message": "AI service deleted successfully"}


# Scan Defaults endpoints
@router.get("/scan-defaults")
async def get_scan_defaults(db: Session = Depends(get_db)):
    """Get all scan default settings."""
    defaults = db.query(ScanDefaults).all()
    return {d.setting_name: d.setting_value for d in defaults}


@router.put("/scan-defaults")
async def update_scan_defaults(
    settings: List[ScanDefaultsUpdate],
    db: Session = Depends(get_db)
):
    """Update scan default settings."""
    for setting in settings:
        existing = db.query(ScanDefaults).filter(
            ScanDefaults.setting_name == setting.setting_name
        ).first()

        if existing:
            existing.setting_value = setting.setting_value
            if setting.description:
                existing.description = setting.description
        else:
            db.add(ScanDefaults(**setting.dict()))

    db.commit()
    return {"message": "Settings updated successfully"}


# SMTP Configuration endpoints
@router.get("/smtp")
async def get_smtp_config(db: Session = Depends(get_db)):
    """Get SMTP configuration."""
    config = db.query(SMTPConfig).first()
    if config and config.password:
        config.password = "****"
    return config


@router.put("/smtp")
async def update_smtp_config(config: SMTPConfigUpdate, db: Session = Depends(get_db)):
    """Update SMTP configuration."""
    existing = db.query(SMTPConfig).first()

    if existing:
        for key, value in config.dict().items():
            if key == "password" and value == "****":
                continue
            setattr(existing, key, value)
    else:
        existing = SMTPConfig(**config.dict())
        db.add(existing)

    db.commit()
    db.refresh(existing)
    return {"message": "SMTP configuration updated successfully"}


# CVE Configuration endpoints
@router.get("/cve")
async def get_cve_config(db: Session = Depends(get_db)):
    """Get CVE configuration."""
    config = db.query(CVEConfig).first()
    if not config:
        config = CVEConfig()
    if config.nvd_api_key:
        config.nvd_api_key = "***" + config.nvd_api_key[-4:] if len(config.nvd_api_key) > 4 else "****"
    return config


@router.put("/cve")
async def update_cve_config(config: CVEConfigUpdate, db: Session = Depends(get_db)):
    """Update CVE configuration."""
    existing = db.query(CVEConfig).first()

    if existing:
        for key, value in config.dict().items():
            if key == "nvd_api_key" and value and value.startswith("***"):
                continue
            setattr(existing, key, value)
    else:
        existing = CVEConfig(**config.dict())
        db.add(existing)

    db.commit()
    db.refresh(existing)
    return {"message": "CVE configuration updated successfully"}


# Retention Policy endpoints
@router.get("/retention")
async def get_retention_policy(db: Session = Depends(get_db)):
    """Get scan retention policy."""
    policy = db.query(ScanRetentionPolicy).first()
    if not policy:
        policy = ScanRetentionPolicy()
    return policy


@router.put("/retention")
async def update_retention_policy(
    policy: RetentionPolicyUpdate,
    db: Session = Depends(get_db)
):
    """Update scan retention policy."""
    existing = db.query(ScanRetentionPolicy).first()

    if existing:
        for key, value in policy.dict().items():
            setattr(existing, key, value)
    else:
        existing = ScanRetentionPolicy(**policy.dict())
        db.add(existing)

    db.commit()
    db.refresh(existing)
    return {"message": "Retention policy updated successfully"}

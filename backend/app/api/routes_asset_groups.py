from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_admin, require_analyst_or_admin, check_user_group_access, get_user_allowed_group_ids
from app.services.asset_group_service import get_descendant_group_ids, is_descendant_of, compute_group_hierarchy_info
from app.services.parameter_service import apply_indicator_exclusion

router = APIRouter(prefix="/asset-groups", tags=["Grupos de Ativos & Tratamento"])

@router.get("", response_model=List[schemas.AssetGroupOut])
def list_asset_groups(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Lista todos os grupos de ativos com métricas agregadas e dados de hierarquia corporativa multinível."""
    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")
    if allowed_ids is not None:
        groups = db.query(models.AssetGroup).filter(models.AssetGroup.id.in_(allowed_ids)).order_by(models.AssetGroup.name.asc()).all()
    else:
        groups = db.query(models.AssetGroup).order_by(models.AssetGroup.name.asc()).all()
    result = []
    for g in groups:
        all_ids = get_descendant_group_ids(db, g.id, include_self=True)
        level, hierarchy_path = compute_group_hierarchy_info(g)

        total_scans = db.query(models.Scan).filter(models.Scan.asset_group_id.in_(all_ids)).count()
        total_hosts = db.query(models.Host).filter(models.Host.asset_group_id.in_(all_ids)).count()
        vuln_base = db.query(models.Vulnerability).filter(models.Vulnerability.asset_group_id.in_(all_ids))
        vuln_base = apply_indicator_exclusion(vuln_base, db)
        total_vulns = vuln_base.count()
        critical_count = vuln_base.filter(models.Vulnerability.severity == "Critical").count()
        high_count = vuln_base.filter(models.Vulnerability.severity == "High").count()

        out = schemas.AssetGroupOut.model_validate(g)
        out.parent_name = g.parent.name if g.parent else None
        out.subgroups_count = len(all_ids) - 1
        out.level = level
        out.hierarchy_path = hierarchy_path
        out.total_scans = total_scans
        out.total_hosts = total_hosts
        out.total_vulnerabilities = total_vulns
        out.critical_count = critical_count
        out.high_count = high_count
        result.append(out)
    return result

@router.post("", response_model=schemas.AssetGroupOut, status_code=status.HTTP_201_CREATED)
def create_asset_group(
    group_in: schemas.AssetGroupCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """Cadastra um novo grupo de ativos / subgrupo de tratamento (Requer Analista ou Administrador)."""
    existing = db.query(models.AssetGroup).filter(models.AssetGroup.name == group_in.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Já existe um grupo de ativos com este nome.")

    if group_in.parent_id:
        parent = db.query(models.AssetGroup).filter(models.AssetGroup.id == group_in.parent_id).first()
        if not parent:
            raise HTTPException(status_code=400, detail="Grupo superior informado não existe.")

    group = models.AssetGroup(**group_in.model_dump())
    db.add(group)
    try:
        db.commit()
        db.refresh(group)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Já existe um grupo de ativos com este nome.")

    level, hierarchy_path = compute_group_hierarchy_info(group)
    out = schemas.AssetGroupOut.model_validate(group)
    out.parent_name = group.parent.name if group.parent else None
    out.subgroups_count = 0
    out.level = level
    out.hierarchy_path = hierarchy_path
    return out

@router.get("/{group_id}", response_model=schemas.AssetGroupOut)
def get_asset_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Obtém detalhes de um grupo de ativos ou subgrupo."""
    g = db.query(models.AssetGroup).filter(models.AssetGroup.id == group_id).first()
    if not g:
        raise HTTPException(status_code=404, detail="Grupo de ativos não encontrado.")

    check_user_group_access(db, current_user, group_id, action="view")
    
    all_ids = get_descendant_group_ids(db, g.id, include_self=True)
    level, hierarchy_path = compute_group_hierarchy_info(g)

    total_scans = db.query(models.Scan).filter(models.Scan.asset_group_id.in_(all_ids)).count()
    total_hosts = db.query(models.Host).filter(models.Host.asset_group_id.in_(all_ids)).count()
    total_vulns = db.query(models.Vulnerability).filter(models.Vulnerability.asset_group_id.in_(all_ids)).count()
    critical_count = db.query(models.Vulnerability).filter(
        models.Vulnerability.asset_group_id.in_(all_ids), 
        models.Vulnerability.severity == "Critical"
    ).count()
    high_count = db.query(models.Vulnerability).filter(
        models.Vulnerability.asset_group_id.in_(all_ids), 
        models.Vulnerability.severity == "High"
    ).count()

    out = schemas.AssetGroupOut.model_validate(g)
    out.parent_name = g.parent.name if g.parent else None
    out.subgroups_count = len(all_ids) - 1
    out.level = level
    out.hierarchy_path = hierarchy_path
    out.total_scans = total_scans
    out.total_hosts = total_hosts
    out.total_vulnerabilities = total_vulns
    out.critical_count = critical_count
    out.high_count = high_count
    return out

@router.put("/{group_id}", response_model=schemas.AssetGroupOut)
def update_asset_group(
    group_id: int,
    group_update: schemas.AssetGroupUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """Atualiza as informações de um grupo de ativos ou seu grupo superior em qualquer nível de hierarquia (Requer Analista ou Administrador)."""
    group = db.query(models.AssetGroup).filter(models.AssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Grupo de ativos não encontrado.")

    if group_update.parent_id is not None:
        if group_update.parent_id == group_id:
            raise HTTPException(status_code=400, detail="Um grupo não pode ser subgrupo de si mesmo.")
        if group_update.parent_id > 0:
            parent = db.query(models.AssetGroup).filter(models.AssetGroup.id == group_update.parent_id).first()
            if not parent:
                raise HTTPException(status_code=400, detail="Grupo superior informado não existe.")
            if is_descendant_of(db, group_update.parent_id, group_id):
                raise HTTPException(status_code=400, detail="Referência circular: o grupo superior selecionado já é subgrupo deste grupo.")

    for field, val in group_update.model_dump(exclude_unset=True).items():
        if field == "parent_id" and val == 0:
            val = None
        setattr(group, field, val)

    try:
        db.commit()
        db.refresh(group)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Já existe um grupo de ativos com este nome.")

    all_ids = get_descendant_group_ids(db, group.id, include_self=True)
    level, hierarchy_path = compute_group_hierarchy_info(group)

    out = schemas.AssetGroupOut.model_validate(group)
    out.parent_name = group.parent.name if group.parent else None
    out.subgroups_count = len(all_ids) - 1
    out.level = level
    out.hierarchy_path = hierarchy_path
    out.total_scans = db.query(models.Scan).filter(models.Scan.asset_group_id.in_(all_ids)).count()
    out.total_hosts = db.query(models.Host).filter(models.Host.asset_group_id.in_(all_ids)).count()
    out.total_vulnerabilities = db.query(models.Vulnerability).filter(models.Vulnerability.asset_group_id.in_(all_ids)).count()
    out.critical_count = db.query(models.Vulnerability).filter(
        models.Vulnerability.asset_group_id.in_(all_ids), models.Vulnerability.severity == "Critical"
    ).count()
    out.high_count = db.query(models.Vulnerability).filter(
        models.Vulnerability.asset_group_id.in_(all_ids), models.Vulnerability.severity == "High"
    ).count()
    return out

@router.delete("/{group_id}")
def delete_asset_group(
    group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """Exclui um grupo de ativos e todos os seus scans/dados vinculados (Requer Administrador)."""
    group = db.query(models.AssetGroup).filter(models.AssetGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Grupo de ativos não encontrado.")

    db.delete(group)
    db.commit()
    return {"message": "Grupo de ativos e dados associados excluídos com sucesso."}

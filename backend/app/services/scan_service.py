from typing import List, Optional
from sqlalchemy.orm import Session
from app import models

def get_latest_scan_ids(db: Session, asset_group_id: Optional[int] = None) -> List[int]:
    """
    Retorna os IDs do scan mais recente para cada grupo de ativos aplicável.
    - Se asset_group_id for informado:
        - Se for um Grupo Superior (com subgrupos vinculados), retorna o scan mais recente do próprio grupo
          e o scan mais recente de CADA um de seus subgrupos (visão consolidada corporativa).
        - Se for um subgrupo ou grupo específico sem filhos, retorna apenas o scan mais recente dele.
    - Se não for informado, retorna o scan mais recente de CADA grupo de ativos existente.
    """
    if asset_group_id:
        from app.services.asset_group_service import get_descendant_group_ids
        target_group_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
        latest_ids = []
        for gid in target_group_ids:
            latest = db.query(models.Scan).filter(
                models.Scan.asset_group_id == gid
            ).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
            if latest:
                latest_ids.append(latest.id)
        return latest_ids

    groups = db.query(models.AssetGroup).all()
    latest_ids = []
    for g in groups:
        latest = db.query(models.Scan).filter(
            models.Scan.asset_group_id == g.id
        ).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
        if latest:
            latest_ids.append(latest.id)

    # Scans sem grupo vinculado (caso existam)
    unassigned = db.query(models.Scan).filter(
        models.Scan.asset_group_id == None
    ).order_by(models.Scan.scan_date.desc(), models.Scan.id.desc()).first()
    if unassigned and unassigned.id not in latest_ids:
        latest_ids.append(unassigned.id)

    return latest_ids

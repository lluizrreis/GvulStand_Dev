from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, check_user_group_access
from app.services.comparative_service import compare_scans

router = APIRouter(prefix="/comparative", tags=["Comparativo Antes vs Depois (PDCA ISO 9001)"])

@router.get("/diff", response_model=schemas.ComparativeReport)
def get_comparative_diff(
    baseline_scan_id: int = Query(..., description="ID do Scan Inicial / Antes"),
    retest_scan_id: int = Query(..., description="ID do Scan de Reteste / Pós-Tratativa"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Executa o comparativo detalhado entre dois scans (Antes vs Depois) calculando a taxa de remediação.
    """
    if baseline_scan_id == retest_scan_id:
        raise HTTPException(status_code=400, detail="Selecione dois scans diferentes para comparação.")

    scan1 = db.query(models.Scan).filter(models.Scan.id == baseline_scan_id).first()
    scan2 = db.query(models.Scan).filter(models.Scan.id == retest_scan_id).first()
    if scan1:
        check_user_group_access(db, current_user, scan1.asset_group_id, action="view")
    if scan2:
        check_user_group_access(db, current_user, scan2.asset_group_id, action="view")

    try:
        report = compare_scans(db, baseline_scan_id, retest_scan_id)
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao processar comparativo: {str(e)}")

@router.get("/scans-by-group/{asset_group_id}", response_model=List[schemas.ScanOut])
def get_scans_for_comparison(
    asset_group_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Retorna os scans disponíveis para um grupo de ativos ou grupo superior consolidado para permitir a seleção de Antes e Depois."""
    check_user_group_access(db, current_user, asset_group_id, action="view")
    from app.services.asset_group_service import get_descendant_group_ids
    group_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
    scans = db.query(models.Scan).filter(models.Scan.asset_group_id.in_(group_ids)).order_by(models.Scan.scan_date.asc(), models.Scan.id.asc()).all()
    result = []
    for s in scans:
        out = schemas.ScanOut.model_validate(s)
        out.asset_group_name = s.asset_group.name if s.asset_group else ""
        result.append(out)
    return result

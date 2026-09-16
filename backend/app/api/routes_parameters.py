import zoneinfo
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_admin
from app.services.parameter_service import (
    get_or_create_system_parameters,
    get_available_timezones,
    parse_ignored_ids,
    format_datetime_in_system_tz,
    get_timezone_offset_str,
)

router = APIRouter(prefix="/parameters", tags=["Parâmetros do Sistema"])

@router.get("", response_model=schemas.SystemParametersOut)
def get_parameters(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna os parâmetros pontuais configurados no sistema:
    - Fuso horário operacional
    - Prazos padrão de SLA (Críticas, Altas, Médias e Baixas)
    - IDs de vulnerabilidades ignoradas nos indicadores (Classificação de Falso-Positivo)
    """
    params = get_or_create_system_parameters(db)
    parsed_ids = parse_ignored_ids(params.ignored_vulnerability_ids)
    
    # Formatação do label do fuso horário
    tz_str = params.timezone or "America/Sao_Paulo"
    offset_str = get_timezone_offset_str(tz_str)
    tz_label = f"{tz_str} ({offset_str})"

    # Procura label mais descritivo na lista curada se disponível
    for tz_item in get_available_timezones():
        if tz_item["id"] == tz_str:
            tz_label = tz_item["label"]
            break

    return schemas.SystemParametersOut(
        id=params.id,
        timezone=tz_str,
        timezone_label=tz_label,
        sla_critical_days=params.sla_critical_days or 7,
        sla_high_days=params.sla_high_days or 15,
        sla_medium_days=params.sla_medium_days or 30,
        sla_low_days=params.sla_low_days or 60,
        ignored_vulnerability_ids=params.ignored_vulnerability_ids or "",
        ignored_ids_list=parsed_ids,
        ignored_vulnerabilities_count=len(parsed_ids),
        ignored_plugins_count=len(parsed_ids),
        updated_at=params.updated_at,
        updated_at_formatted=format_datetime_in_system_tz(params.updated_at, db),
        updated_by_username=params.updated_by_username or "Sistema"
    )

@router.put("", response_model=schemas.SystemParametersOut)
def update_parameters(
    payload: schemas.SystemParametersUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """
    Atualiza as parametrizações do sistema. Acesso restrito a Administradores.
    Valida o fuso horário, limites de SLA e limpa a lista de IDs de vulnerabilidades ignoradas.
    """
    # 1. Validação do Fuso Horário
    tz_input = (payload.timezone or "").strip()
    if not tz_input:
        raise HTTPException(status_code=400, detail="O fuso horário é obrigatório.")
    
    try:
        zoneinfo.ZoneInfo(tz_input)
    except Exception:
        raise HTTPException(
            status_code=400, 
            detail=f"Fuso horário inválido: '{tz_input}'. Selecione um fuso horário válido da lista."
        )

    # 2. Validação dos Prazos de SLA
    if payload.sla_critical_days < 1 or payload.sla_high_days < 1 or payload.sla_medium_days < 1 or payload.sla_low_days < 1:
        raise HTTPException(
            status_code=400,
            detail="Os prazos de SLA devem ser números inteiros positivos (mínimo de 1 dia)."
        )

    # 3. Limpeza dos IDs de Vulnerabilidades / Plugins
    cleaned_ids = parse_ignored_ids(payload.ignored_vulnerability_ids)
    formatted_ignored_str = ", ".join(cleaned_ids)

    # 4. Atualização no Banco de Dados
    params = get_or_create_system_parameters(db)
    params.timezone = tz_input
    params.sla_critical_days = payload.sla_critical_days
    params.sla_high_days = payload.sla_high_days
    params.sla_medium_days = payload.sla_medium_days
    params.sla_low_days = payload.sla_low_days
    params.ignored_vulnerability_ids = formatted_ignored_str
    params.updated_at = models.utc_now()
    params.updated_by_username = current_user.username

    db.commit()
    db.refresh(params)

    offset_str = get_timezone_offset_str(params.timezone)
    tz_label = f"{params.timezone} ({offset_str})"
    for tz_item in get_available_timezones():
        if tz_item["id"] == params.timezone:
            tz_label = tz_item["label"]
            break

    return schemas.SystemParametersOut(
        id=params.id,
        timezone=params.timezone,
        timezone_label=tz_label,
        sla_critical_days=params.sla_critical_days,
        sla_high_days=params.sla_high_days,
        sla_medium_days=params.sla_medium_days,
        sla_low_days=params.sla_low_days,
        ignored_vulnerability_ids=params.ignored_vulnerability_ids,
        ignored_ids_list=cleaned_ids,
        ignored_vulnerabilities_count=len(cleaned_ids),
        ignored_plugins_count=len(cleaned_ids),
        updated_at=params.updated_at,
        updated_at_formatted=format_datetime_in_system_tz(params.updated_at, db),
        updated_by_username=params.updated_by_username
    )

@router.get("/timezones", response_model=List[schemas.TimezoneOption])
def list_timezones(
    current_user: models.User = Depends(get_current_user)
):
    """
    Lista todos os fusos horários disponíveis para configuração no sistema,
    com ênfase nos fusos brasileiros e internacionais.
    """
    raw_tzs = get_available_timezones()
    return [
        schemas.TimezoneOption(
            id=t["id"],
            name=t["id"],
            label=t["label"],
            offset=t["offset"],
            offset_formatted=t["offset"],
            utc_offset_str=t["offset"],
            is_brazil=t.get("is_brazil", False)
        )
        for t in raw_tzs
    ]

@router.post("/preview-ignored", response_model=schemas.IgnoredVulnPreviewOut)
def preview_ignored_vulnerabilities(
    payload: schemas.IgnoredVulnPreviewRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Pré-visualiza o impacto dos IDs de vulnerabilidades/plugins fornecidos na base atual.
    Retorna o total de ocorrências encontradas, severidades e hosts impactados.
    """
    raw_text = payload.ignored_ids
    if raw_text is None:
        params = get_or_create_system_parameters(db)
        raw_text = params.ignored_vulnerability_ids

    ids = parse_ignored_ids(raw_text)
    if not ids:
        return schemas.IgnoredVulnPreviewOut(
            total_matching_rules=0,
            total_findings_affected=0,
            total_affected_hosts=0,
            items=[]
        )

    int_ids = [int(i) for i in ids if i.isdigit()]

    # Busca vulnerabilidades correspondentes aos IDs (plugin_id ou ID interno)
    query = db.query(
        models.Vulnerability.plugin_id,
        models.Vulnerability.plugin_name,
        models.Vulnerability.severity,
        models.Vulnerability.cve,
        models.Vulnerability.solution,
        func.count(models.Vulnerability.id).label("findings_count"),
        func.count(func.distinct(models.Vulnerability.host_id)).label("hosts_count")
    ).filter(
        (models.Vulnerability.plugin_id.in_(ids)) |
        (models.Vulnerability.id.in_(int_ids) if int_ids else False)
    ).group_by(
        models.Vulnerability.plugin_id,
        models.Vulnerability.plugin_name,
        models.Vulnerability.severity,
        models.Vulnerability.cve,
        models.Vulnerability.solution
    ).order_by(
        func.count(models.Vulnerability.id).desc()
    )

    rows = query.all()

    items = []
    total_findings = 0
    distinct_hosts_q = db.query(models.Vulnerability.host_id).filter(
        (models.Vulnerability.plugin_id.in_(ids)) |
        (models.Vulnerability.id.in_(int_ids) if int_ids else False)
    ).distinct()
    total_distinct_hosts = distinct_hosts_q.count()

    for r in rows:
        total_findings += r.findings_count
        items.append(schemas.IgnoredVulnPreviewItem(
            plugin_id=r.plugin_id,
            plugin_name=r.plugin_name,
            severity=r.severity,
            findings_count=r.findings_count,
            matching_findings_count=r.findings_count,
            affected_hosts_count=r.hosts_count,
            impacted_hosts_count=r.hosts_count,
            sample_cve=r.cve,
            sample_solution=r.solution
        ))

    return schemas.IgnoredVulnPreviewOut(
        total_matching_rules=len(ids),
        total_ignored_plugins=len(ids),
        total_findings_affected=total_findings,
        total_findings_impacted=total_findings,
        total_affected_hosts=total_distinct_hosts,
        total_unique_hosts_impacted=total_distinct_hosts,
        items=items
    )

@router.post("/apply-slas-to-all-groups")
def apply_slas_to_all_groups(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """
    Aplica os prazos de SLA configurados nos parâmetros globais a todos os
    Grupos de Ativos cadastrados no sistema.
    """
    params = get_or_create_system_parameters(db)
    crit = params.sla_critical_days or 7
    high = params.sla_high_days or 15
    med = params.sla_medium_days or 30
    low = params.sla_low_days or 60

    groups = db.query(models.AssetGroup).all()
    updated_count = len(groups)
    for g in groups:
        g.sla_critical_days = crit
        g.sla_high_days = high
        g.sla_medium_days = med
        g.sla_low_days = low
        g.updated_at = models.utc_now()

    db.commit()

    return {
        "message": f"Prazos de SLA atualizados com sucesso em {updated_count} Grupos de Ativos.",
        "updated_groups_count": updated_count,
        "slas_applied": {
            "sla_critical_days": crit,
            "sla_high_days": high,
            "sla_medium_days": med,
            "sla_low_days": low
        }
    }

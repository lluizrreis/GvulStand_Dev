import re
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, check_user_group_access, get_user_allowed_group_ids
from app.services.scan_service import get_latest_scan_ids
from app.services.parameter_service import (
    apply_indicator_exclusion,
    get_effective_slas,
    format_datetime_in_system_tz,
    get_system_timezone
)

router = APIRouter(prefix="/reports", tags=["Relatórios Executivos & Auditoria"])

ACTIONABLE_SEVERITIES = ["Critical", "High", "Medium", "Low"]

def analyze_os_eol(os_str: Optional[str]) -> Tuple[str, bool, str]:
    """
    Identifica se um Sistema Operacional atingiu o Fim da Vida Útil (End-of-Life / EOL)
    ou está próximo de perder suporte oficial do fabricante.
    """
    if not os_str or not os_str.strip():
        return "Sistema Operacional Não Identificado", False, "Suportado"
    
    clean_os = os_str.strip()
    lower = clean_os.lower()

    # Sistemas com EOL decretado (Fim da Vida Útil)
    if any(k in lower for k in [
        "server 2003", "server 2008", "server 2012", "windows xp", "windows vista",
        "windows 7", "windows 8", "windows 8.1"
    ]):
        return clean_os, True, "EOL (Fim da Vida Útil)"

    if "centos" in lower and any(v in lower for v in [" 5", " 6", " 7", " 8"]):
        return clean_os, True, "EOL (Fim da Vida Útil)"

    if "ubuntu" in lower and any(v in lower for v in ["12.04", "14.04", "16.04", "18.04"]):
        return clean_os, True, "EOL (Fim da Vida Útil)"

    if "debian" in lower and any(v in lower for v in [
        "debian 6", "debian 7", "debian 8", "debian 9", "debian 10",
        "squeeze", "wheezy", "jessie", "stretch", "buster"
    ]):
        return clean_os, True, "EOL (Fim da Vida Útil)"

    if "red hat" in lower or "rhel" in lower:
        if any(v in lower for v in ["rhel 5", "rhel 6", "release 5", "release 6", "enterprise linux 5", "enterprise linux 6"]):
            return clean_os, True, "EOL (Fim da Vida Útil)"

    # Sistemas próximos do EOL
    if "windows 10" in lower:
        return clean_os, False, "Próximo do EOL (Outubro/2025)"

    if "ubuntu" in lower and "20.04" in lower:
        return clean_os, False, "Próximo do EOL (Abril/2025)"

    return clean_os, False, "Suportado"


@router.get("/templates", response_model=List[schemas.ReportTemplateOut])
def list_report_templates(current_user: models.User = Depends(get_current_user)):
    """
    Retorna o catálogo de modelos de relatórios disponíveis no sistema.
    """
    return [
        schemas.ReportTemplateOut(
            id="executive_summary",
            name="Relatório Sumário de Gestão de Vulnerabilidades",
            status="available",
            description="Sumário executivo estratégico para Diretoria e C-Level: Metadados, Inventário com EOL, Termômetro de Risco, Matriz de Severidade, Top 5 Destaques e Indicadores de Remediação (SLA e MTTR).",
            icon="file-text",
            badge="Disponível • Principal"
        ),
        schemas.ReportTemplateOut(
            id="technical_inventory",
            name="Relatório Técnico Detalhado de Vulnerabilidades & Hosts",
            status="available",
            description="Dossiê completo ativo por ativo contendo lista exaustiva de CVEs, portas TCP/UDP, saídas completas de plugins Nessus e vetores de exploração para equipes de sustentação e infraestrutura.",
            icon="file-code",
            badge="Disponível • Dossiê Técnico"
        ),
        schemas.ReportTemplateOut(
            id="sla_audit",
            name="Relatório de Auditoria e Conformidade SLA (ISO 27001)",
            status="available",
            description="Auditoria formal de cumprimento de prazos de remediação estipulados na Política de Segurança (Controle 8.8 ISO/IEC 27001), trilha de auditoria e justificativas de risco aceito e métricas de eficiência ISO 9001 (PDCA).",
            icon="award",
            badge="Disponível • Auditoria & ISO"
        )
    ]


@router.get("/summary-data", response_model=schemas.ExecutiveSummaryReport)
def get_executive_summary_report(
    asset_group_id: Optional[str] = Query(None, description="ID do Grupo de Ativos"),
    scan_id: Optional[str] = Query(None, description="ID de um Scan específico de referência"),
    period: Optional[str] = Query(None, description="Período de Análise / Ciclo de Escaneamento"),
    team: Optional[str] = Query(None, description="Equipe Responsável Emissora"),
    emission_date: Optional[str] = Query(None, description="Data de Emissão informada"),
    title: Optional[str] = Query(None, description="Título customizado do relatório"),
    classification: Optional[str] = Query(None, description="Classificação da informação"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Gera todos os dados consolidados para o Relatório Sumário de Gestão de Vulnerabilidades
    conforme escopo executivo (Metadados, Inventário c/ EOL, Termômetro de Risco, Severidade, Top 5 e SLA/MTTR).
    """
    now = datetime.now()
    now_utc = datetime.now(timezone.utc)

    # Parsing seguro de IDs numéricos para evitar erros 422 quando strings vazias forem enviadas
    parsed_group_id: Optional[int] = None
    if asset_group_id and asset_group_id.strip() and asset_group_id.strip().isdigit():
        parsed_group_id = int(asset_group_id.strip())

    parsed_scan_id: Optional[int] = None
    if scan_id and scan_id.strip() and scan_id.strip().isdigit():
        parsed_scan_id = int(scan_id.strip())

    # Higienização de strings de entrada
    period_str = period.strip() if period and period.strip() else None
    team_str = team.strip() if team and team.strip() else "Equipe de Segurança da Informação / SOC"
    emission_date_str = emission_date.strip() if emission_date and emission_date.strip() else now.strftime("%d/%m/%Y %H:%M")
    title_str = title.strip() if title and title.strip() else "Relatório Sumário de Gestão de Vulnerabilidades"
    classif_str = classification.strip() if classification and classification.strip() else "CONFIDENCIAL // USO INTERNO"
    classif_str = re.sub(r"\s*-\s*TLP:(AMBER|RED|GREEN|CLEAR)", "", classif_str, flags=re.IGNORECASE).strip()

    # 1. Determinação do Escopo e Scans Ativos
    target_scan_ids: List[int] = []
    scope_name = "Todos os Grupos de Ativos (Visão Consolidada)"
    scope_group_id = None
    scope_notes = None

    if parsed_scan_id:
        single_scan = db.query(models.Scan).filter(models.Scan.id == parsed_scan_id).first()
        if not single_scan:
            raise HTTPException(status_code=404, detail="Scan selecionado não foi encontrado.")
        check_user_group_access(db, current_user, single_scan.asset_group_id, action="author")
        target_scan_ids = [single_scan.id]
        scope_group_id = single_scan.asset_group_id
        scope_name = single_scan.asset_group.name if single_scan.asset_group else f"Scan: {single_scan.scan_name}"
    elif parsed_group_id:
        target_group = db.query(models.AssetGroup).filter(models.AssetGroup.id == parsed_group_id).first()
        if not target_group:
            raise HTTPException(status_code=404, detail="Grupo de ativos informado não existe.")
        check_user_group_access(db, current_user, target_group.id, action="author")
        scope_name = target_group.name
        scope_group_id = target_group.id
        target_scan_ids = get_latest_scan_ids(db, parsed_group_id)
        if not target_scan_ids:
            scope_notes = f"Aviso de Escopo: Não foram localizados relatórios de varredura (.nessus) importados para o grupo '{scope_name}'. Para consolidar os indicadores, importe um scan ou selecione a visão consolidada de todos os grupos."
    else:
        allowed_author_ids = get_user_allowed_group_ids(db, current_user, action="author")
        if allowed_author_ids is not None:
            if not allowed_author_ids:
                raise HTTPException(status_code=403, detail="Acesso negado: Você não possui permissão de autoria em nenhum grupo de ativos.")
            target_scan_ids = []
            for gid in allowed_author_ids:
                target_scan_ids.extend(get_latest_scan_ids(db, gid))
            scope_name = "Grupos Autorizados"
            if not target_scan_ids:
                scope_notes = "Aviso de Escopo: Não foram localizadas varreduras (.nessus) importadas nos grupos autorizados."
        else:
            target_scan_ids = get_latest_scan_ids(db, None)
            if not target_scan_ids:
                scope_notes = "Aviso de Escopo: Não foram localizadas varreduras (.nessus) importadas no sistema. Importe um arquivo na aba 'Scans' para gerar indicadores reais."

    # Carregar objetos de scan selecionados
    selected_scans = db.query(models.Scan).filter(models.Scan.id.in_(target_scan_ids)).all() if target_scan_ids else []
    scan_names = [s.scan_name for s in selected_scans]

    # Período padrão caso não informado
    if not period_str:
        meses_pt = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
                    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
        if selected_scans:
            sorted_by_date = sorted(selected_scans, key=lambda s: s.scan_date, reverse=True)
            last_date = sorted_by_date[0].scan_date
            mes_nome = meses_pt[last_date.month - 1]
            period_str = f"Ciclo de Escaneamento de {mes_nome}/{last_date.year}"
        else:
            mes_nome = meses_pt[now.month - 1]
            period_str = f"Ciclo de Escaneamento de {mes_nome}/{now.year}"

    # Estrutura padrão de retorno caso não haja scans no escopo
    if not target_scan_ids or not selected_scans:
        empty_statement = (
            f"Nenhum ativo ou resultado de varredura foi encontrado para o escopo selecionado ('{scope_name}'). "
            f"Recomenda-se importar relatórios Nessus (.nessus) na aba 'Scans' para consolidar os indicadores executivos de postura e conformidade."
        )
        return schemas.ExecutiveSummaryReport(
            metadata=schemas.ReportMetadata(
                title=title_str,
                period=period_str,
                emission_date=emission_date_str,
                scope_name=scope_name,
                scope_group_id=scope_group_id,
                team=team_str,
                classification=classif_str,
                generated_by=current_user.full_name or current_user.username,
                scan_ids=[],
                scan_names=[],
                notes=scope_notes
            ),
            inventory=schemas.ReportInventory(
                total_discovered_hosts=0,
                active_hosts=0,
                inactive_hosts=0,
                active_percentage=100.0,
                os_distribution=[],
                eol_count=0,
                eol_percentage=0.0,
                eol_systems_list=[],
                attack_surface_exposure_pct=0.0
            ),
            risk_summary=schemas.ReportRiskSummary(
                organization_risk_score=0.0,
                risk_level="Baixo / Saudável",
                risk_trend_direction="baseline",
                risk_trend_percentage=0.0,
                risk_trend_text="Nenhum dado de varredura disponível no escopo selecionado.",
                previous_risk_score=None,
                total_occurrences=0,
                unique_vulnerabilities=0,
                repetition_ratio=0.0,
                attack_surface_exposure_pct=0.0,
                hosts_with_critical_or_exploits=0,
                critical_density=0.0,
                executive_summary_statement=empty_statement
            ),
            severity_distribution=schemas.ReportSeverityDistribution(
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                actionable_total=0,
                critical_percent=0.0,
                high_percent=0.0,
                medium_percent=0.0,
                low_percent=0.0,
                info_percent=0.0,
                exploitable_count=0,
                exploitable_percent=0.0
            ),
            highlights_top5=schemas.ReportHighlights(
                top_hosts=[],
                top_vulnerabilities=[]
            ),
            remediation_sla=schemas.ReportRemediationSLA(
                overall_mttr_days=0.0,
                mttr_by_severity={"Critical": 0.0, "High": 0.0, "Medium": 0.0, "Low": 0.0},
                sla_compliance_rate=100.0,
                sla_meeting_count=0,
                sla_not_meeting_count=0,
                sla_by_severity={
                    "Critical": {"meeting": 0, "not_meeting": 0, "rate": 100.0},
                    "High": {"meeting": 0, "not_meeting": 0, "rate": 100.0},
                    "Medium": {"meeting": 0, "not_meeting": 0, "rate": 100.0},
                    "Low": {"meeting": 0, "not_meeting": 0, "rate": 100.0}
                },
                recurring_count=0,
                new_count=0,
                remediated_count=0,
                recurring_percent=0.0,
                new_percent=0.0
            )
        )

    # 2. Consultas do Ambiente Atual (Hosts e Vulnerabilidades)
    hosts_q = db.query(models.Host).filter(models.Host.scan_id.in_(target_scan_ids)).all()
    vuln_query = db.query(models.Vulnerability).filter(models.Vulnerability.scan_id.in_(target_scan_ids))
    vulns_q = apply_indicator_exclusion(vuln_query, db).all()

    # Deduplicação de Hosts por IP
    unique_hosts_map: Dict[str, models.Host] = {}
    for h in hosts_q:
        if h.ip_address not in unique_hosts_map:
            unique_hosts_map[h.ip_address] = h
        else:
            # Mantém o com maior pontuação de risco
            if (h.risk_score or 0.0) > (unique_hosts_map[h.ip_address].risk_score or 0.0):
                unique_hosts_map[h.ip_address] = h

    total_discovered_hosts = len(unique_hosts_map)

    # Ativos vs Inativos (Ping failure / ICMP echo check falho vs responsivos)
    inactive_ips = set()
    for h in unique_hosts_map.values():
        if h.critical_count == 0 and h.high_count == 0 and h.medium_count == 0 and h.low_count == 0:
            # Verifica se possui erro de conectividade ping
            has_unreachable = db.query(models.Vulnerability.id).filter(
                models.Vulnerability.host_id == h.id,
                models.Vulnerability.plugin_id.in_(["1102", "10180"])
            ).first() is not None
            if has_unreachable:
                inactive_ips.add(h.ip_address)

    inactive_hosts_count = len(inactive_ips)
    active_hosts_count = max(0, total_discovered_hosts - inactive_hosts_count)
    active_percentage = round((active_hosts_count / max(1, total_discovered_hosts)) * 100, 1)

    # Distribuição de Sistemas Operacionais (SO) & Detecção de EOL
    os_counter: Dict[str, Dict[str, Any]] = {}
    eol_os_set = set()

    for h in unique_hosts_map.values():
        raw_os = h.os or "Não Identificado"
        norm_os, is_eol, eol_status = analyze_os_eol(raw_os)

        if norm_os not in os_counter:
            os_counter[norm_os] = {
                "count": 0,
                "is_eol": is_eol,
                "eol_status": eol_status
            }
        os_counter[norm_os]["count"] += 1
        if is_eol:
            eol_os_set.add(norm_os)

    os_distribution: List[schemas.ReportOSItem] = []
    total_eol_hosts = 0

    for os_name, data in sorted(os_counter.items(), key=lambda x: x[1]["count"], reverse=True):
        count = data["count"]
        pct = round((count / max(1, total_discovered_hosts)) * 100, 1)
        if data["is_eol"]:
            total_eol_hosts += count
        os_distribution.append(schemas.ReportOSItem(
            os_name=os_name,
            count=count,
            percentage=pct,
            is_eol=data["is_eol"],
            eol_status=data["eol_status"]
        ))

    eol_percentage = round((total_eol_hosts / max(1, total_discovered_hosts)) * 100, 1)

    # 3. Sumário Executivo de Riscos (O "Termômetro" de Segurança)
    crit_count = sum(1 for v in vulns_q if v.severity == "Critical")
    high_count = sum(1 for v in vulns_q if v.severity == "High")
    med_count = sum(1 for v in vulns_q if v.severity == "Medium")
    low_count = sum(1 for v in vulns_q if v.severity == "Low")
    info_count = sum(1 for v in vulns_q if v.severity == "Info")
    actionable_total = crit_count + high_count + med_count + low_count
    total_findings_all = actionable_total + info_count

    exploitable_count = sum(1 for v in vulns_q if v.exploit_available and v.severity in ACTIONABLE_SEVERITIES)
    exploitable_crit_count = sum(1 for v in vulns_q if v.exploit_available and v.severity == "Critical")

    # Risk Score Global da Organização (fórmula ponderada ISO 27001 por host)
    raw_risk = (crit_count * 10.0) + (high_count * 5.0) + (med_count * 2.0) + (low_count * 0.5) + (exploitable_crit_count * 5.0)
    organization_risk_score = round(raw_risk / max(1, total_discovered_hosts), 1)

    if organization_risk_score >= 120.0:
        risk_level = "Crítico (Ação Emergencial Requerida)"
    elif organization_risk_score >= 60.0:
        risk_level = "Alto (Risco Elevado)"
    elif organization_risk_score >= 20.0:
        risk_level = "Moderado (Atenção Gerencial)"
    else:
        risk_level = "Baixo (Ambiente Controlado)"

    # Contagem de Vulnerabilidades Únicas (plugins distintos) vs Ocorrências Totais
    unique_plugins = set(v.plugin_id for v in vulns_q if v.severity in ACTIONABLE_SEVERITIES)
    unique_vulns_count = len(unique_plugins)
    repetition_ratio = round(actionable_total / max(1, unique_vulns_count), 1)

    # Evolução do Risco (Tendência vs Ciclo Anterior)
    previous_scan_ids = []
    for s in selected_scans:
        prev = db.query(models.Scan).filter(
            models.Scan.asset_group_id == s.asset_group_id,
            models.Scan.id != s.id,
            models.Scan.scan_date < s.scan_date
        ).order_by(models.Scan.scan_date.desc()).first()
        if prev:
            previous_scan_ids.append(prev.id)

    previous_risk_score: Optional[float] = None
    risk_trend_direction = "baseline"
    risk_trend_percentage = 0.0
    risk_trend_text = "Linha de Base Inicial (Baseline) estabelecida neste ciclo."

    if previous_scan_ids:
        prev_scans = db.query(models.Scan).filter(models.Scan.id.in_(previous_scan_ids)).all()
        prev_crit = sum(s.critical_count for s in prev_scans)
        prev_high = sum(s.high_count for s in prev_scans)
        prev_med = sum(s.medium_count for s in prev_scans)
        prev_low = sum(s.low_count for s in prev_scans)
        prev_exp = sum(s.exploitable_critical_count for s in prev_scans)
        prev_hosts = db.query(models.Host.ip_address).filter(models.Host.scan_id.in_(previous_scan_ids)).distinct().count()
        
        prev_raw = (prev_crit * 10.0) + (prev_high * 5.0) + (prev_med * 2.0) + (prev_low * 0.5) + (prev_exp * 5.0)
        previous_risk_score = round(prev_raw / max(1, prev_hosts), 1)

        delta = organization_risk_score - previous_risk_score
        if previous_risk_score > 0:
            risk_trend_percentage = round((abs(delta) / previous_risk_score) * 100, 1)

        if delta < -0.5:
            risk_trend_direction = "down" # Redução de risco (positivo)
            risk_trend_text = f"Redução de {risk_trend_percentage}% no Risk Score em comparação ao ciclo anterior."
        elif delta > 0.5:
            risk_trend_direction = "up" # Aumento de risco
            risk_trend_text = f"Aumento de {risk_trend_percentage}% no Risk Score em comparação ao ciclo anterior."
        else:
            risk_trend_direction = "stable"
            risk_trend_text = "Nível de risco estável em relação ao ciclo anterior."

    # Indicadores Executivos Adicionais de Melhores Práticas
    hosts_with_critical_or_exploits = sum(
        1 for h in unique_hosts_map.values()
        if (h.critical_count or 0) > 0 or (h.exploitable_critical_count or 0) > 0
    )
    attack_surface_exposure_pct = round((hosts_with_critical_or_exploits / max(1, active_hosts_count)) * 100, 1)
    critical_density = round((crit_count + high_count) / max(1, active_hosts_count), 1)

    # 4. Distribuição por Severidade
    crit_pct = round((crit_count / max(1, total_findings_all)) * 100, 1)
    high_pct = round((high_count / max(1, total_findings_all)) * 100, 1)
    med_pct = round((med_count / max(1, total_findings_all)) * 100, 1)
    low_pct = round((low_count / max(1, total_findings_all)) * 100, 1)
    info_pct = round((info_count / max(1, total_findings_all)) * 100, 1)
    exploit_pct = round((exploitable_count / max(1, actionable_total)) * 100, 1)

    # 5. Destaques e Top 5 Críticos
    # Top 5 Hosts mais vulneráveis
    sorted_hosts = sorted(
        unique_hosts_map.values(),
        key=lambda h: ((h.risk_score or 0.0), h.critical_count, h.exploitable_critical_count, h.high_count),
        reverse=True
    )[:5]

    top_hosts: List[schemas.ReportTopHost] = []
    for rank, h in enumerate(sorted_hosts, start=1):
        grp_name = h.asset_group.name if h.asset_group else (h.scan.asset_group.name if h.scan and h.scan.asset_group else "")
        top_hosts.append(schemas.ReportTopHost(
            rank=rank,
            host_id=h.id,
            ip_address=h.ip_address,
            hostname=h.hostname or h.netbios_name or "N/A",
            asset_group_name=grp_name,
            os=h.os or "Não Identificado",
            critical_count=h.critical_count,
            high_count=h.high_count,
            exploitable_count=h.exploitable_critical_count,
            risk_score=round(h.risk_score or 0.0, 1)
        ))

    # Top 5 Vulnerabilidades Críticas e Altas Mais Frequentes
    vuln_grouping: Dict[str, Dict[str, Any]] = {}
    cve_regex = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    for v in vulns_q:
        if v.severity not in ["Critical", "High"]:
            continue
        pid = v.plugin_id
        if pid not in vuln_grouping:
            cves = [c.strip() for c in cve_regex.findall(v.cve or "")] if v.cve else []
            vuln_grouping[pid] = {
                "plugin_id": pid,
                "plugin_name": v.plugin_name,
                "cves": set(cves),
                "severity": v.severity,
                "cvss_v3": v.cvss_v3,
                "solution": v.solution,
                "affected_host_ips": set()
            }
        else:
            if v.cve:
                for c in cve_regex.findall(v.cve):
                    vuln_grouping[pid]["cves"].add(c.strip())
            if v.solution and len(v.solution) > len(vuln_grouping[pid]["solution"] or ""):
                vuln_grouping[pid]["solution"] = v.solution
        
        host_ip_str = v.host.ip_address if v.host else str(v.host_id)
        vuln_grouping[pid]["affected_host_ips"].add(host_ip_str)

    sorted_vulns = sorted(
        vuln_grouping.values(),
        key=lambda x: (
            len(x["affected_host_ips"]),
            1 if x["severity"] == "Critical" else 0,
            (x["cvss_v3"] or 0.0)
        ),
        reverse=True
    )[:5]

    top_vulnerabilities: List[schemas.ReportTopVuln] = []
    for rank, v in enumerate(sorted_vulns, start=1):
        cve_str = ", ".join(sorted(list(v["cves"]))) if v["cves"] else "N/A"
        aff_count = len(v["affected_host_ips"])
        aff_pct = round((aff_count / max(1, total_discovered_hosts)) * 100, 1)
        top_vulnerabilities.append(schemas.ReportTopVuln(
            rank=rank,
            plugin_id=v["plugin_id"],
            plugin_name=v["plugin_name"],
            cve=cve_str,
            severity=v["severity"],
            cvss_v3=v["cvss_v3"],
            affected_hosts_count=aff_count,
            affected_hosts_percent=aff_pct,
            solution=v["solution"] or "Aplicar os patches recomendados pelo fornecedor."
        ))

    # 6. Indicadores de Desempenho e Remediação (SLA e MTTR)
    group_slas = {g.id: g for g in db.query(models.AssetGroup).all()}

    sla_counts = {
        "Critical": {"meeting": 0, "not_meeting": 0},
        "High": {"meeting": 0, "not_meeting": 0},
        "Medium": {"meeting": 0, "not_meeting": 0},
        "Low": {"meeting": 0, "not_meeting": 0}
    }

    remediated_durations: Dict[str, List[float]] = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": []
    }

    total_meeting = 0
    total_not_meeting = 0

    for v in vulns_q:
        if v.severity not in sla_counts:
            continue
        sev = v.severity
        g = group_slas.get(v.asset_group_id)
        effective_slas = get_effective_slas(db, g)
        limit_days = effective_slas.get(sev, 60)

        ref_dt = v.first_found or v.created_at
        if ref_dt:
            cmp_now = now_utc if ref_dt.tzinfo is not None else now
            age_days = max(0, (cmp_now - ref_dt).days)
        else:
            age_days = 0

        if v.treatment_status == "Remediated" and v.treated_at and ref_dt:
            rem_days = max(0.5, (v.treated_at - ref_dt).total_seconds() / 86400.0)
            remediated_durations[sev].append(rem_days)

        if age_days <= limit_days or v.treatment_status == "Remediated":
            sla_counts[sev]["meeting"] += 1
            total_meeting += 1
        else:
            sla_counts[sev]["not_meeting"] += 1
            total_not_meeting += 1

    default_benchmarks = {
        "Critical": 4.5,
        "High": 8.0,
        "Medium": 18.0,
        "Low": 32.0
    }
    mttr_by_sev: Dict[str, float] = {}
    all_durations = []

    for s in ["Critical", "High", "Medium", "Low"]:
        d_list = remediated_durations[s]
        if d_list:
            avg = round(sum(d_list) / len(d_list), 1)
            mttr_by_sev[s] = avg
            all_durations.extend(d_list)
        else:
            mttr_by_sev[s] = default_benchmarks[s]
            all_durations.append(default_benchmarks[s])

    overall_mttr = round(sum(all_durations) / max(1, len(all_durations)), 1)
    sla_compliance_rate = round((total_meeting / max(1, total_meeting + total_not_meeting)) * 100, 1)

    sla_by_severity = {}
    for s in ["Critical", "High", "Medium", "Low"]:
        m = sla_counts[s]["meeting"]
        nm = sla_counts[s]["not_meeting"]
        rate = round((m / max(1, m + nm)) * 100, 1)
        sla_by_severity[s] = {
            "meeting": m,
            "not_meeting": nm,
            "rate": rate
        }

    # Vulnerabilidades Recorrentes vs. Novas
    recurring_count = 0
    new_count = actionable_total
    remediated_count = 0

    if previous_scan_ids:
        prev_query = db.query(models.Vulnerability, models.Host.ip_address)\
            .join(models.Host, models.Vulnerability.host_id == models.Host.id)\
            .filter(
                models.Vulnerability.scan_id.in_(previous_scan_ids),
                models.Vulnerability.severity.in_(ACTIONABLE_SEVERITIES)
            )
        prev_vulns = apply_indicator_exclusion(prev_query, db).all()

        prev_sigs = set((h_ip, v.plugin_id, v.port, v.protocol) for v, h_ip in prev_vulns)
        curr_sigs = set((v.host.ip_address if v.host else str(v.host_id), v.plugin_id, v.port, v.protocol) for v in vulns_q if v.severity in ACTIONABLE_SEVERITIES)

        recurring_sigs = curr_sigs.intersection(prev_sigs)
        new_sigs = curr_sigs.difference(prev_sigs)
        remediated_sigs = prev_sigs.difference(curr_sigs)

        recurring_count = len(recurring_sigs)
        new_count = len(new_sigs)
        remediated_count = len(remediated_sigs)

    recurring_percent = round((recurring_count / max(1, actionable_total)) * 100, 1)
    new_percent = round((new_count / max(1, actionable_total)) * 100, 1)

    # Síntese Executiva Estratégica (Executive Statement para Diretoria)
    executive_statement = (
        f"No ciclo avaliado referente a '{period_str}', foram auditados {active_hosts_count} ativos no escopo '{scope_name}', "
        f"totalizando {actionable_total} vulnerabilidades acionáveis ({crit_count} Críticas e {high_count} Altas). "
        f"O Índice de Exposição da Superfície de Ataque é de {attack_surface_exposure_pct}%, com {exploitable_count} vulnerabilidades ({exploit_pct}%) "
        f"apresentando código de exploração (exploit) público disponível. A taxa geral de conformidade aos SLAs é de {sla_compliance_rate}% "
        f"e o nível geral de risco corporativo é classificado como '{risk_level}'."
    )

    return schemas.ExecutiveSummaryReport(
        metadata=schemas.ReportMetadata(
            title=title_str,
            period=period_str,
            emission_date=emission_date_str,
            scope_name=scope_name,
            scope_group_id=scope_group_id,
            team=team_str,
            classification=classif_str,
            generated_by=current_user.full_name or current_user.username,
            scan_ids=[s.id for s in selected_scans],
            scan_names=scan_names,
            notes=scope_notes
        ),
        inventory=schemas.ReportInventory(
            total_discovered_hosts=total_discovered_hosts,
            active_hosts=active_hosts_count,
            inactive_hosts=inactive_hosts_count,
            active_percentage=active_percentage,
            os_distribution=os_distribution,
            eol_count=total_eol_hosts,
            eol_percentage=eol_percentage,
            eol_systems_list=sorted(list(eol_os_set)),
            attack_surface_exposure_pct=attack_surface_exposure_pct
        ),
        risk_summary=schemas.ReportRiskSummary(
            organization_risk_score=organization_risk_score,
            risk_level=risk_level,
            risk_trend_direction=risk_trend_direction,
            risk_trend_percentage=risk_trend_percentage,
            risk_trend_text=risk_trend_text,
            previous_risk_score=previous_risk_score,
            total_occurrences=actionable_total,
            unique_vulnerabilities=unique_vulns_count,
            repetition_ratio=repetition_ratio,
            attack_surface_exposure_pct=attack_surface_exposure_pct,
            hosts_with_critical_or_exploits=hosts_with_critical_or_exploits,
            critical_density=critical_density,
            executive_summary_statement=executive_statement
        ),
        severity_distribution=schemas.ReportSeverityDistribution(
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            info_count=info_count,
            actionable_total=actionable_total,
            critical_percent=crit_pct,
            high_percent=high_pct,
            medium_percent=med_pct,
            low_percent=low_pct,
            info_percent=info_pct,
            exploitable_count=exploitable_count,
            exploitable_percent=exploit_pct
        ),
        highlights_top5=schemas.ReportHighlights(
            top_hosts=top_hosts,
            top_vulnerabilities=top_vulnerabilities
        ),
        remediation_sla=schemas.ReportRemediationSLA(
            overall_mttr_days=overall_mttr,
            mttr_by_severity=mttr_by_sev,
            sla_compliance_rate=sla_compliance_rate,
            sla_meeting_count=total_meeting,
            sla_not_meeting_count=total_not_meeting,
            sla_by_severity=sla_by_severity,
            recurring_count=recurring_count,
            new_count=new_count,
            remediated_count=remediated_count,
            recurring_percent=recurring_percent,
            new_percent=new_percent
        )
    )


@router.get("/technical-data", response_model=schemas.TechnicalReportResponse)
def get_technical_report(
    asset_group_id: Optional[str] = Query(None, description="ID do Grupo de Ativos"),
    scan_id: Optional[str] = Query(None, description="ID de um Scan específico de referência"),
    period: Optional[str] = Query(None, description="Período de Análise / Ciclo de Escaneamento"),
    team: Optional[str] = Query(None, description="Equipe Responsável Emissora"),
    emission_date: Optional[str] = Query(None, description="Data de Emissão informada"),
    title: Optional[str] = Query(None, description="Título customizado do relatório"),
    classification: Optional[str] = Query(None, description="Classificação da informação"),
    severity_min: Optional[str] = Query(None, description="Filtro de severidade mínima (Critical, High, Medium, Low)"),
    search: Optional[str] = Query(None, description="Busca textual por IP ou hostname"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Gera o Dossiê Técnico Completo ativo por ativo contendo lista exaustiva de CVEs,
    portas TCP/UDP, saídas completas de plugins Nessus, vetores de exploração e soluções recomendadas.
    """
    now = datetime.now()

    # Parsing seguro de IDs numéricos
    parsed_group_id: Optional[int] = None
    if asset_group_id and asset_group_id.strip() and asset_group_id.strip().isdigit():
        parsed_group_id = int(asset_group_id.strip())

    parsed_scan_id: Optional[int] = None
    if scan_id and scan_id.strip() and scan_id.strip().isdigit():
        parsed_scan_id = int(scan_id.strip())

    # Higienização de strings de metadados
    period_str = period.strip() if period and period.strip() else None
    team_str = team.strip() if team and team.strip() else "Equipe de Segurança da Informação & Sustentação de TI"
    emission_date_str = emission_date.strip() if emission_date and emission_date.strip() else now.strftime("%d/%m/%Y %H:%M")
    title_str = title.strip() if title and title.strip() else "Relatório Técnico Detalhado de Vulnerabilidades & Hosts"
    classif_str = classification.strip() if classification and classification.strip() else "CONFIDENCIAL // USO INTERNO"
    classif_str = re.sub(r"\s*-\s*TLP:(AMBER|RED|GREEN|CLEAR)", "", classif_str, flags=re.IGNORECASE).strip()

    # 1. Determinação do Escopo e Scans Ativos
    target_scan_ids: List[int] = []
    scope_name = "Todos os Grupos de Ativos (Visão Consolidada)"
    scope_group_id = None
    scope_notes = None

    if parsed_scan_id:
        single_scan = db.query(models.Scan).filter(models.Scan.id == parsed_scan_id).first()
        if not single_scan:
            raise HTTPException(status_code=404, detail="Scan selecionado não foi encontrado.")
        check_user_group_access(db, current_user, single_scan.asset_group_id, action="author")
        target_scan_ids = [single_scan.id]
        scope_group_id = single_scan.asset_group_id
        scope_name = single_scan.asset_group.name if single_scan.asset_group else f"Scan: {single_scan.scan_name}"
    elif parsed_group_id:
        target_group = db.query(models.AssetGroup).filter(models.AssetGroup.id == parsed_group_id).first()
        if not target_group:
            raise HTTPException(status_code=404, detail="Grupo de ativos informado não existe.")
        check_user_group_access(db, current_user, target_group.id, action="author")
        scope_name = target_group.name
        scope_group_id = target_group.id
        target_scan_ids = get_latest_scan_ids(db, parsed_group_id)
        if not target_scan_ids:
            scope_notes = f"Aviso de Escopo: Não foram localizados relatórios de varredura (.nessus) para o grupo '{scope_name}'."
    else:
        allowed_author_ids = get_user_allowed_group_ids(db, current_user, action="author")
        if allowed_author_ids is not None:
            if not allowed_author_ids:
                raise HTTPException(status_code=403, detail="Acesso negado: Você não possui permissão de autoria em nenhum grupo de ativos.")
            target_scan_ids = []
            for gid in allowed_author_ids:
                target_scan_ids.extend(get_latest_scan_ids(db, gid))
            scope_name = "Grupos Autorizados"
            if not target_scan_ids:
                scope_notes = "Aviso de Escopo: Não foram localizadas varreduras (.nessus) nos grupos autorizados."
        else:
            target_scan_ids = get_latest_scan_ids(db, None)
            if not target_scan_ids:
                scope_notes = "Aviso de Escopo: Não foram localizadas varreduras (.nessus) importadas no sistema."

    selected_scans = db.query(models.Scan).filter(models.Scan.id.in_(target_scan_ids)).all() if target_scan_ids else []
    scan_names = [s.scan_name for s in selected_scans]

    # Período padrão caso não informado
    if not period_str:
        meses_pt = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
                    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
        if selected_scans:
            sorted_by_date = sorted(selected_scans, key=lambda s: s.scan_date, reverse=True)
            last_date = sorted_by_date[0].scan_date
            mes_nome = meses_pt[last_date.month - 1]
            period_str = f"Ciclo de Escaneamento de {mes_nome}/{last_date.year}"
        else:
            mes_nome = meses_pt[now.month - 1]
            period_str = f"Ciclo de Escaneamento de {mes_nome}/{now.year}"

    # Retorno caso escopo vazio
    if not target_scan_ids or not selected_scans:
        return schemas.TechnicalReportResponse(
            metadata=schemas.ReportMetadata(
                title=title_str,
                period=period_str,
                emission_date=emission_date_str,
                scope_name=scope_name,
                scope_group_id=scope_group_id,
                team=team_str,
                classification=classif_str,
                generated_by=current_user.full_name or current_user.username,
                scan_ids=[],
                scan_names=[],
                notes=scope_notes
            ),
            summary=schemas.TechnicalReportSummary(
                total_hosts=0,
                total_actionable_vulns=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                exploitable_count=0,
                avg_risk_score=0.0,
                max_risk_score=0.0,
                top_ports=[]
            ),
            hosts=[]
        )

    # 2. Resolução de Severidades Filtradas
    sev_filter_map = {
        "critical": ["Critical"],
        "high": ["Critical", "High"],
        "medium": ["Critical", "High", "Medium"],
        "low": ["Critical", "High", "Medium", "Low"],
    }
    target_severities = ACTIONABLE_SEVERITIES
    if severity_min and severity_min.strip().lower() in sev_filter_map:
        target_severities = sev_filter_map[severity_min.strip().lower()]

    # 3. Busca e deduplicação de Hosts
    hosts_q = db.query(models.Host).filter(models.Host.scan_id.in_(target_scan_ids)).all()
    unique_hosts_map: Dict[str, models.Host] = {}
    for h in hosts_q:
        if h.ip_address not in unique_hosts_map:
            unique_hosts_map[h.ip_address] = h
        else:
            if (h.risk_score or 0.0) > (unique_hosts_map[h.ip_address].risk_score or 0.0):
                unique_hosts_map[h.ip_address] = h

    # Filtro opcional de busca textual
    filtered_hosts = list(unique_hosts_map.values())
    if search and search.strip():
        term = search.strip().lower()
        filtered_hosts = [
            h for h in filtered_hosts
            if term in (h.ip_address or "").lower()
            or term in (h.hostname or "").lower()
            or term in (h.netbios_name or "").lower()
        ]

    host_ids = [h.id for h in filtered_hosts]

    # 4. Busca em lote de vulnerabilidades
    vulns_by_host: Dict[int, List[models.Vulnerability]] = {}
    if host_ids:
        vuln_query = db.query(models.Vulnerability).filter(
            models.Vulnerability.host_id.in_(host_ids),
            models.Vulnerability.severity.in_(target_severities)
        )
        vulns_q = apply_indicator_exclusion(vuln_query, db).all()
        for v in vulns_q:
            vulns_by_host.setdefault(v.host_id, []).append(v)

    SEV_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    port_counter: Dict[Tuple[int, str], int] = {}
    host_dossiers: List[schemas.TechnicalHostDossier] = []

    for h in filtered_hosts:
        h_raw_vulns = vulns_by_host.get(h.id, [])
        # Ordena vulnerabilidades: Severidade desc > CVSS desc > Nome asc
        h_sorted_vulns = sorted(
            h_raw_vulns,
            key=lambda v: (SEV_WEIGHT.get(v.severity, 0), v.cvss_v3 or 0.0, v.plugin_name),
            reverse=True
        )

        h_crit = 0
        h_high = 0
        h_med = 0
        h_low = 0
        h_exploits = 0
        vuln_items: List[schemas.TechnicalVulnerabilityItem] = []

        for v in h_sorted_vulns:
            if v.severity == "Critical":
                h_crit += 1
            elif v.severity == "High":
                h_high += 1
            elif v.severity == "Medium":
                h_med += 1
            elif v.severity == "Low":
                h_low += 1

            if v.exploit_available:
                h_exploits += 1

            if v.port and v.port > 0:
                p_key = (v.port, (v.protocol or "tcp").lower())
                port_counter[p_key] = port_counter.get(p_key, 0) + 1

            # Parsing de CVEs
            cve_list: List[str] = []
            if v.cve:
                cve_list = [c.strip() for c in re.split(r'[,;\s]+', v.cve) if c.strip().upper().startswith("CVE-")]

            vuln_items.append(
                schemas.TechnicalVulnerabilityItem(
                    id=v.id,
                    plugin_id=str(v.plugin_id),
                    plugin_name=v.plugin_name,
                    cve=v.cve,
                    cve_list=cve_list,
                    severity=v.severity,
                    cvss_v3=v.cvss_v3,
                    cvss_v2=v.cvss_v2,
                    port=v.port or 0,
                    protocol=(v.protocol or "tcp").lower(),
                    solution=v.solution,
                    synopsis=v.synopsis,
                    description=v.description,
                    plugin_output=v.plugin_output,
                    exploit_available=bool(v.exploit_available),
                    exploit_frameworks=v.exploit_frameworks,
                    treatment_status=v.treatment_status or "Open"
                )
            )

        host_dossiers.append(
            schemas.TechnicalHostDossier(
                host_id=h.id,
                ip_address=h.ip_address,
                hostname=h.hostname or None,
                netbios_name=h.netbios_name or None,
                asset_group_id=h.asset_group_id,
                asset_group_name=h.asset_group.name if h.asset_group else "Padrão",
                os=h.os or "Não identificado",
                critical_count=h_crit,
                high_count=h_high,
                medium_count=h_med,
                low_count=h_low,
                info_count=h.info_count or 0,
                exploits_count=h_exploits,
                risk_score=round(h.risk_score or 0.0, 1),
                total_actionable_vulns=len(vuln_items),
                vulnerabilities=vuln_items
            )
        )

    # Ordena os hosts por Risk Score desc, Críticas desc, Exploits desc, Altas desc
    host_dossiers.sort(
        key=lambda d: (d.risk_score, d.critical_count, d.exploits_count, d.high_count, d.total_actionable_vulns),
        reverse=True
    )

    # Estatísticas globais do relatório
    total_hosts = len(host_dossiers)
    total_actionable = sum(d.total_actionable_vulns for d in host_dossiers)
    tot_crit = sum(d.critical_count for d in host_dossiers)
    tot_high = sum(d.high_count for d in host_dossiers)
    tot_med = sum(d.medium_count for d in host_dossiers)
    tot_low = sum(d.low_count for d in host_dossiers)
    tot_exploits = sum(d.exploits_count for d in host_dossiers)
    avg_risk = round(sum(d.risk_score for d in host_dossiers) / max(1, total_hosts), 1)
    max_risk = max([d.risk_score for d in host_dossiers], default=0.0)

    # Top 10 portas com mais ocorrências
    sorted_ports = sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ports = [
        schemas.TechnicalReportPortStat(
            port=p[0],
            protocol=p[1],
            count=cnt
        )
        for p, cnt in sorted_ports
    ]

    return schemas.TechnicalReportResponse(
        metadata=schemas.ReportMetadata(
            title=title_str,
            period=period_str,
            emission_date=emission_date_str,
            scope_name=scope_name,
            scope_group_id=scope_group_id,
            team=team_str,
            classification=classif_str,
            generated_by=current_user.full_name or current_user.username,
            scan_ids=target_scan_ids,
            scan_names=scan_names,
            notes=scope_notes
        ),
        summary=schemas.TechnicalReportSummary(
            total_hosts=total_hosts,
            total_actionable_vulns=total_actionable,
            critical_count=tot_crit,
            high_count=tot_high,
            medium_count=tot_med,
            low_count=tot_low,
            exploitable_count=tot_exploits,
            avg_risk_score=avg_risk,
            max_risk_score=max_risk,
            top_ports=top_ports
        ),
        hosts=host_dossiers
    )


@router.get("/sla-audit-data", response_model=schemas.SlaAuditReportResponse)
def get_sla_audit_report(
    asset_group_id: Optional[str] = Query(None, description="ID do Grupo de Ativos"),
    scan_id: Optional[str] = Query(None, description="ID de um Scan específico de referência"),
    period: Optional[str] = Query(None, description="Período de Análise / Ciclo de Escaneamento"),
    team: Optional[str] = Query(None, description="Equipe Responsável Emissora"),
    emission_date: Optional[str] = Query(None, description="Data de Emissão informada"),
    title: Optional[str] = Query(None, description="Título customizado do relatório"),
    classification: Optional[str] = Query(None, description="Classificação da informação"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Gera o Relatório de Auditoria e Conformidade SLA (ISO 27001 & ISO 9001).
    Avalia a aderência formal aos SLAs (Controle 8.8 ISO/IEC 27001), gera a matriz de aging,
    calcula as métricas de eficácia e redução de risco do Ciclo PDCA (ISO 9001),
    e isola a trilha de auditoria completa de riscos aceitos ("Quem, Quando e Por Quê").
    """
    now = datetime.now()
    now_utc = datetime.now(timezone.utc)

    # 1. Parsing seguro de IDs e parâmetros
    parsed_group_id: Optional[int] = None
    if asset_group_id and asset_group_id.strip() and asset_group_id.strip().isdigit():
        parsed_group_id = int(asset_group_id.strip())

    parsed_scan_id: Optional[int] = None
    if scan_id and scan_id.strip() and scan_id.strip().isdigit():
        parsed_scan_id = int(scan_id.strip())

    period_str = period.strip() if period and period.strip() else None
    team_str = team.strip() if team and team.strip() else "Auditoria Interna de Segurança da Informação & Qualidade"
    emission_date_str = emission_date.strip() if emission_date and emission_date.strip() else now.strftime("%d/%m/%Y %H:%M")
    title_str = title.strip() if title and title.strip() else "Relatório de Auditoria e Conformidade SLA (ISO 27001)"
    classif_str = classification.strip() if classification and classification.strip() else "CONFIDENCIAL // USO RESTRITO"
    classif_str = re.sub(r"\s*-\s*TLP:(AMBER|RED|GREEN|CLEAR)", "", classif_str, flags=re.IGNORECASE).strip()

    # 2. Resolução de Escopo e Scans Ativos
    target_scan_ids: List[int] = []
    scope_name = "Todos os Grupos de Ativos (Visão Consolidada)"
    scope_group_id = None
    scope_notes = None

    if parsed_scan_id:
        single_scan = db.query(models.Scan).filter(models.Scan.id == parsed_scan_id).first()
        if not single_scan:
            raise HTTPException(status_code=404, detail="Scan selecionado não foi encontrado.")
        check_user_group_access(db, current_user, single_scan.asset_group_id, action="author")
        target_scan_ids = [single_scan.id]
        scope_group_id = single_scan.asset_group_id
        scope_name = single_scan.asset_group.name if single_scan.asset_group else f"Scan: {single_scan.scan_name}"
    elif parsed_group_id:
        target_group = db.query(models.AssetGroup).filter(models.AssetGroup.id == parsed_group_id).first()
        if not target_group:
            raise HTTPException(status_code=404, detail="Grupo de ativos informado não existe.")
        check_user_group_access(db, current_user, target_group.id, action="author")
        scope_name = target_group.name
        scope_group_id = target_group.id
        target_scan_ids = get_latest_scan_ids(db, parsed_group_id)
        if not target_scan_ids:
            scope_notes = f"Aviso de Escopo: Não foram localizados relatórios de varredura (.nessus) para o grupo '{scope_name}'."
    else:
        allowed_author_ids = get_user_allowed_group_ids(db, current_user, action="author")
        if allowed_author_ids is not None:
            if not allowed_author_ids:
                raise HTTPException(status_code=403, detail="Acesso negado: Você não possui permissão de autoria em nenhum grupo de ativos.")
            target_scan_ids = []
            for gid in allowed_author_ids:
                target_scan_ids.extend(get_latest_scan_ids(db, gid))
            scope_name = "Grupos Autorizados"
            if not target_scan_ids:
                scope_notes = "Aviso de Escopo: Não foram localizadas varreduras (.nessus) nos grupos autorizados."
        else:
            target_scan_ids = get_latest_scan_ids(db, None)
            if not target_scan_ids:
                scope_notes = "Aviso de Escopo: Não foram localizadas varreduras (.nessus) importadas no sistema."

    selected_scans = db.query(models.Scan).filter(models.Scan.id.in_(target_scan_ids)).all() if target_scan_ids else []
    scan_names = [s.scan_name for s in selected_scans]

    if not period_str:
        meses_pt = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
                    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
        if selected_scans:
            sorted_by_date = sorted(selected_scans, key=lambda s: s.scan_date, reverse=True)
            last_date = sorted_by_date[0].scan_date
            mes_nome = meses_pt[last_date.month - 1]
            period_str = f"Ciclo de Auditoria de {mes_nome}/{last_date.year}"
        else:
            mes_nome = meses_pt[now.month - 1]
            period_str = f"Ciclo de Auditoria de {mes_nome}/{now.year}"

    # Carregar Grupos de Ativos e Políticas de SLA
    all_groups = db.query(models.AssetGroup).all()
    group_slas = {g.id: g for g in all_groups}
    
    # Se o escopo for um grupo específico, inclui apenas ele; caso contrário, os grupos relevantes
    if parsed_group_id and parsed_group_id in group_slas:
        scoped_groups = [group_slas[parsed_group_id]]
    elif selected_scans:
        used_gids = set(s.asset_group_id for s in selected_scans if s.asset_group_id)
        scoped_groups = [group_slas[gid] for gid in used_gids if gid in group_slas]
        if not scoped_groups:
            scoped_groups = all_groups
    else:
        scoped_groups = all_groups

    sla_limits_by_group: List[schemas.SlaGroupLimits] = [
        schemas.SlaGroupLimits(
            group_id=g.id,
            group_name=g.name,
            sla_critical_days=g.sla_critical_days,
            sla_high_days=g.sla_high_days,
            sla_medium_days=g.sla_medium_days,
            sla_low_days=g.sla_low_days
        )
        for g in scoped_groups
    ]

    # Vulnerabilidades acionáveis no escopo
    vulns_q: List[models.Vulnerability] = []
    if target_scan_ids:
        vuln_query = db.query(models.Vulnerability).filter(
            models.Vulnerability.scan_id.in_(target_scan_ids),
            models.Vulnerability.severity.in_(ACTIONABLE_SEVERITIES)
        )
        vulns_q = apply_indicator_exclusion(vuln_query, db).all()

    total_actionable = len(vulns_q)

    # 3. SEÇÃO 1: AUDITORIA FORMAL DE ADERÊNCIA AOS PRAZOS (SLA) & MATRIZ DE AGING
    # Faixas de envelhecimento: 0-30d, 31-60d, 61-90d, >90d
    bucket_defs = [
        {"key": "0-30", "label": "0-30 dias", "min": 0, "max": 30},
        {"key": "31-60", "label": "31-60 dias", "min": 31, "max": 60},
        {"key": "61-90", "label": "61-90 dias", "min": 61, "max": 90},
        {"key": ">90", "label": "> 90 dias (Passivos Críticos)", "min": 91, "max": 999999}
    ]

    bucket_stats = {
        b["key"]: {
            "total": 0, "within_sla": 0, "breached": 0,
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0,
            "Critical_breached": 0, "High_breached": 0, "Medium_breached": 0, "Low_breached": 0
        }
        for b in bucket_defs
    }

    sev_stats = {
        "Critical": {"total": 0, "within": 0, "breached": 0, "ages": []},
        "High": {"total": 0, "within": 0, "breached": 0, "ages": []},
        "Medium": {"total": 0, "within": 0, "breached": 0, "ages": []},
        "Low": {"total": 0, "within": 0, "breached": 0, "ages": []}
    }

    total_within_sla = 0
    total_breached_sla = 0
    crit_passives_over_90 = 0
    high_passives_over_90 = 0

    for v in vulns_q:
        sev = v.severity
        if sev not in sev_stats:
            continue

        g = group_slas.get(v.asset_group_id)
        effective_slas = get_effective_slas(db, g)
        limit_days = effective_slas.get(sev, 60)

        ref_dt = v.first_found or v.created_at
        if ref_dt:
            cmp_now = now_utc if ref_dt.tzinfo is not None else now
            age_days = max(0, (cmp_now - ref_dt).days)
        else:
            age_days = 0

        # Avaliação de conformidade frente ao SLA estipulado
        if v.treatment_status == "Remediated" and v.treated_at and ref_dt:
            rem_duration = max(0, (v.treated_at - ref_dt).days)
            is_compliant = rem_duration <= limit_days
        else:
            is_compliant = age_days <= limit_days

        # Contagem geral
        if is_compliant:
            total_within_sla += 1
            sev_stats[sev]["within"] += 1
        else:
            total_breached_sla += 1
            sev_stats[sev]["breached"] += 1

        sev_stats[sev]["total"] += 1
        sev_stats[sev]["ages"].append(age_days)

        # Classificação na Matriz de Aging
        for b in bucket_defs:
            if b["min"] <= age_days <= b["max"]:
                b_stat = bucket_stats[b["key"]]
                b_stat["total"] += 1
                b_stat[sev] += 1
                if is_compliant:
                    b_stat["within_sla"] += 1
                else:
                    b_stat["breached"] += 1
                    b_stat[f"{sev}_breached"] += 1
                break

        # Detecção de passivos críticos > 90 dias
        if age_days > 90 and v.treatment_status != "Remediated":
            if sev == "Critical":
                crit_passives_over_90 += 1
            elif sev == "High":
                high_passives_over_90 += 1

    overall_sla_compliance = round((total_within_sla / max(1, total_actionable)) * 100.0, 1) if total_actionable > 0 else 100.0

    # Montagem da Matriz de Aging em schemas
    aging_matrix: List[schemas.SlaAgingBucket] = []
    for b in bucket_defs:
        s = bucket_stats[b["key"]]
        aging_matrix.append(schemas.SlaAgingBucket(
            range_label=b["label"],
            total_count=s["total"],
            within_sla_count=s["within_sla"],
            breached_sla_count=s["breached"],
            critical_count=s["Critical"],
            high_count=s["High"],
            medium_count=s["Medium"],
            low_count=s["Low"],
            critical_breached_count=s["Critical_breached"],
            high_breached_count=s["High_breached"],
            medium_breached_count=s["Medium_breached"],
            low_breached_count=s["Low_breached"]
        ))

    # Conformidade por Severidade
    severity_compliance: List[schemas.SlaSeverityCompliance] = []
    default_limits = {"Critical": 7, "High": 15, "Medium": 30, "Low": 60}
    for s_name in ["Critical", "High", "Medium", "Low"]:
        st = sev_stats[s_name]
        tot = st["total"]
        within = st["within"]
        breached = st["breached"]
        comp_rate = round((within / max(1, tot)) * 100.0, 1) if tot > 0 else 100.0
        avg_age = round(sum(st["ages"]) / max(1, len(st["ages"])), 1) if st["ages"] else 0.0
        max_age = max(st["ages"]) if st["ages"] else 0
        limit_ref = default_limits[s_name]
        if scoped_groups:
            if s_name == "Critical":
                limit_ref = scoped_groups[0].sla_critical_days
            elif s_name == "High":
                limit_ref = scoped_groups[0].sla_high_days
            elif s_name == "Medium":
                limit_ref = scoped_groups[0].sla_medium_days
            else:
                limit_ref = scoped_groups[0].sla_low_days

        severity_compliance.append(schemas.SlaSeverityCompliance(
            severity=s_name,
            sla_limit_days=limit_ref,
            total_count=tot,
            within_sla_count=within,
            breached_sla_count=breached,
            compliance_rate_percent=comp_rate,
            avg_age_days=avg_age,
            max_age_days=max_age
        ))

    sla_adherence_section = schemas.SlaAuditAdherence(
        sla_limits_by_group=sla_limits_by_group,
        overall_compliance_rate_percent=overall_sla_compliance,
        total_actionable=total_actionable,
        total_within_sla=total_within_sla,
        total_breached_sla=total_breached_sla,
        critical_passives_over_90_days=crit_passives_over_90,
        high_passives_over_90_days=high_passives_over_90,
        aging_matrix=aging_matrix,
        severity_compliance=severity_compliance
    )

    # 4. SEÇÃO 2: MÉTRICAS DE EFICIÊNCIA ISO 9001 (CICLO PDCA)
    # A) Taxa de Eficácia de Remediação: (Total Remediated / Total Acionáveis) * 100
    total_remediated = sum(1 for v in vulns_q if v.treatment_status == "Remediated")
    if total_remediated > 0 and total_actionable > 0:
        rem_efficiency_rate: Optional[float] = round((total_remediated / total_actionable) * 100.0, 1)
        rem_efficiency_display = f"{rem_efficiency_rate}%"
    else:
        rem_efficiency_rate = None
        rem_efficiency_display = "-" # Sem dados de remediações concluídas, usa hífen sem distorção

    # B) Comparativo Baseline vs Reteste: Taxa de Resolução e Redução Líquida de Risco
    previous_scan_ids = []
    for s in selected_scans:
        prev = db.query(models.Scan).filter(
            models.Scan.asset_group_id == s.asset_group_id,
            models.Scan.id != s.id,
            models.Scan.scan_date < s.scan_date
        ).order_by(models.Scan.scan_date.desc()).first()
        if prev and prev.id not in previous_scan_ids:
            previous_scan_ids.append(prev.id)

    has_retest_data = False
    resolution_rate_percent: Optional[float] = None
    resolution_rate_display = "Baseline Inicial"
    net_risk_reduction_percent: Optional[float] = None
    net_risk_reduction_display = "Baseline Inicial Estabelecido"
    baseline_scan_name = None
    retest_scan_name = None
    baseline_vulns_count = 0
    retest_vulns_count = total_actionable
    retest_remediated_count = 0
    retest_persisting_count = 0
    retest_new_count = total_actionable
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None

    if previous_scan_ids and selected_scans:
        prev_scans = db.query(models.Scan).filter(models.Scan.id.in_(previous_scan_ids)).all()
        prev_vulns = db.query(models.Vulnerability, models.Host.ip_address)\
            .join(models.Host, models.Vulnerability.host_id == models.Host.id)\
            .filter(
                models.Vulnerability.scan_id.in_(previous_scan_ids),
                models.Vulnerability.severity.in_(ACTIONABLE_SEVERITIES)
            ).all()

        prev_sigs = set((h_ip, v.plugin_id, v.port, v.protocol) for v, h_ip in prev_vulns)
        curr_sigs = set((v.host.ip_address if v.host else str(v.host_id), v.plugin_id, v.port, v.protocol) for v in vulns_q if v.severity in ACTIONABLE_SEVERITIES)

        remediated_sigs = prev_sigs.difference(curr_sigs)
        persisting_sigs = curr_sigs.intersection(prev_sigs)
        new_sigs = curr_sigs.difference(prev_sigs)

        has_retest_data = True
        baseline_vulns_count = len(prev_sigs)
        retest_vulns_count = len(curr_sigs)
        retest_remediated_count = len(remediated_sigs)
        retest_persisting_count = len(persisting_sigs)
        retest_new_count = len(new_sigs)

        # Taxa de Resolução: (Vulnerabilidades Remediadas no Reteste / Total de Vulnerabilidades no Baseline) * 100
        if baseline_vulns_count > 0:
            resolution_rate_percent = round((retest_remediated_count / baseline_vulns_count) * 100.0, 1)
            resolution_rate_display = f"{resolution_rate_percent}%"
        else:
            resolution_rate_percent = 0.0
            resolution_rate_display = "0.0%"

        # Redução Líquida de Risco: ((Risco Antes - Risco Depois) / Risco Antes) * 100
        risk_before = sum((s.critical_count * 10.0) + (s.high_count * 5.0) + (s.medium_count * 2.0) + (s.low_count * 0.5) for s in prev_scans)
        risk_after = sum((s.critical_count * 10.0) + (s.high_count * 5.0) + (s.medium_count * 2.0) + (s.low_count * 0.5) for s in selected_scans)

        if risk_before > 0:
            net_risk_reduction_percent = round(((risk_before - risk_after) / risk_before) * 100.0, 1)
            if net_risk_reduction_percent >= 0:
                net_risk_reduction_display = f"{net_risk_reduction_percent}% de Redução Líquida"
            else:
                net_risk_reduction_display = f"+{abs(net_risk_reduction_percent)}% (Aumento de Exposição)"
        else:
            net_risk_reduction_percent = 0.0
            net_risk_reduction_display = "0.0%"

        baseline_scan_name = ", ".join(s.scan_name for s in prev_scans[:2])
        retest_scan_name = ", ".join(s.scan_name for s in selected_scans[:2])
        pdca_statement = (
            f"Avaliação comparativa contínua: {retest_remediated_count} vulnerabilidades detectadas no baseline "
            f"foram remediadas com sucesso no reteste ({resolution_rate_display} de resolução), "
            f"proporcionando {net_risk_reduction_display} no inventário de risco."
        )
    else:
        risk_after = sum((s.critical_count * 10.0) + (s.high_count * 5.0) + (s.medium_count * 2.0) + (s.low_count * 0.5) for s in selected_scans) if selected_scans else 0.0
        pdca_statement = (
            "Linha de Base Inicial (Baseline) estabelecida neste ciclo. As métricas comparativas evolutivas de "
            "Taxa de Resolução e Redução Líquida de Risco serão consolidadas automaticamente no próximo escaneamento de reteste."
        )

    iso9001_pdca_section = schemas.Iso9001PdcaMetrics(
        remediation_efficiency_rate_percent=rem_efficiency_rate,
        remediation_efficiency_display=rem_efficiency_display,
        total_remediated=total_remediated,
        total_actionable=total_actionable,
        has_retest_data=has_retest_data,
        resolution_rate_percent=resolution_rate_percent,
        resolution_rate_display=resolution_rate_display,
        baseline_scan_name=baseline_scan_name,
        retest_scan_name=retest_scan_name,
        baseline_vulns_count=baseline_vulns_count,
        retest_vulns_count=retest_vulns_count,
        retest_remediated_count=retest_remediated_count,
        retest_persisting_count=retest_persisting_count,
        retest_new_count=retest_new_count,
        net_risk_reduction_percent=net_risk_reduction_percent,
        net_risk_reduction_display=net_risk_reduction_display,
        risk_before=risk_before,
        risk_after=risk_after,
        pdca_status_statement=pdca_statement
    )

    # 5. SEÇÃO 3: TRILHA DE AUDITORIA E RISCOS ACEITOS ("QUEM, QUANDO E POR QUÊ")
    accepted_vulns = [v for v in vulns_q if v.treatment_status == "Accepted_Risk"]
    accepted_items: List[schemas.AcceptedRiskAuditItem] = []

    for v in accepted_vulns:
        treated_at_formatted = format_datetime_in_system_tz(v.treated_at, db) if v.treated_at else "Data/Hora não registrada"
        h_ip = v.host.ip_address if v.host else f"Host ID: {v.host_id}"
        h_name = v.host.hostname or v.host.netbios_name if v.host else None
        grp_name = v.asset_group.name if v.asset_group else (v.scan.asset_group.name if v.scan and v.scan.asset_group else "Padrão")
        notes = v.treatment_notes.strip() if v.treatment_notes and v.treatment_notes.strip() else "Justificativa técnica ou de negócio não informada no registro de aceitação."

        accepted_items.append(schemas.AcceptedRiskAuditItem(
            id=v.id,
            plugin_id=v.plugin_id,
            plugin_name=v.plugin_name,
            severity=v.severity,
            host_ip=h_ip,
            hostname=h_name,
            asset_group_name=grp_name,
            treated_by_username=v.treated_by_username or "Usuário não identificado",
            treated_at=v.treated_at,
            treated_at_formatted=treated_at_formatted,
            treatment_notes=notes,
            cve=v.cve,
            cvss_v3=v.cvss_v3,
            port=v.port or 0,
            protocol=v.protocol or "tcp"
        ))

    # Ordenar por severidade (Critical -> High -> Medium -> Low) e data mais recente
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    accepted_items.sort(key=lambda x: (sev_order.get(x.severity, 4), -(x.treated_at.timestamp() if x.treated_at else 0)))

    tot_accepted = len(accepted_items)
    crit_accepted = sum(1 for x in accepted_items if x.severity == "Critical")
    high_accepted = sum(1 for x in accepted_items if x.severity == "High")
    med_accepted = sum(1 for x in accepted_items if x.severity == "Medium")
    low_accepted = sum(1 for x in accepted_items if x.severity == "Low")
    accepted_ratio = round((tot_accepted / max(1, total_actionable)) * 100.0, 1) if total_actionable > 0 else 0.0

    accepted_risks_section = schemas.AcceptedRiskSummary(
        total_accepted_risks=tot_accepted,
        critical_accepted=crit_accepted,
        high_accepted=high_accepted,
        medium_accepted=med_accepted,
        low_accepted=low_accepted,
        accepted_risk_ratio_percent=accepted_ratio,
        items=accepted_items
    )

    # 6. SEÇÃO 4: PARECER FORMAL DO AUDITOR E ACCOUNTABILITY
    # Avaliação de conformidade ISO/IEC 27001 Controle 8.8 (Gestão de vulnerabilidades técnicas)
    if crit_passives_over_90 > 0:
        ctrl_8_8_status = "Não Conforme (Passivos Críticos Vencidos > 90 Dias)"
        findings_text = (
            f"Auditoria identificou a existência de {crit_passives_over_90} vulnerabilidade(s) crítica(s) e "
            f"{high_passives_over_90} alta(s) com tempo de exposição superior a 90 dias, violando o tempo máximo "
            f"de resposta estabelecido na Política de Segurança da Informação e as diretrizes do Controle 8.8 da ISO/IEC 27001."
        )
    elif overall_sla_compliance >= 90.0:
        ctrl_8_8_status = "Conforme (Aderente à Política de Segurança)"
        findings_text = (
            f"O parque auditado demonstrou elevado nível de governança e aderência aos SLAs, com "
            f"{overall_sla_compliance}% de conformidade aos prazos estipulados e ausência de passivos críticos superiores a 90 dias."
        )
    else:
        ctrl_8_8_status = "Conforme com Observações (Necessidade de Plano de Ação)"
        findings_text = (
            f"A taxa de conformidade aos SLAs atingiu {overall_sla_compliance}%, com {total_breached_sla} vulnerabilidade(s) "
            f"fora do prazo limite estipulado. Não foram registrados passivos críticos com idade superior a 90 dias."
        )

    # Status PDCA ISO 9001
    if has_retest_data and net_risk_reduction_percent and net_risk_reduction_percent > 0:
        pdca_status = "Eficaz (Melhoria Contínua Evidenciada)"
    elif has_retest_data and resolution_rate_percent and resolution_rate_percent > 0:
        pdca_status = "Parcialmente Eficaz (Reteste Ativo com Resolução Parcial)"
    else:
        pdca_status = "Em Ciclo de Implementação / Baseline"

    # Recomendações formais de auditoria
    recommendations: List[str] = []
    if crit_passives_over_90 > 0:
        recommendations.append(
            f"INSTAURAR PLANO DE AÇÃO IMEDIATO: Remediação prioritária e em regime de força-tarefa para os {crit_passives_over_90} passivos críticos que ultrapassaram 90 dias de exposição."
        )
    if total_breached_sla > 0:
        recommendations.append(
            f"REVISÃO DE CAPACIDADE DE SUSTENTAÇÃO: Adequar a cadência de aplicação de patches para mitigar os {total_breached_sla} itens atualmente fora do prazo de SLA."
        )
    if tot_accepted > 0:
        recommendations.append(
            f"GOVERNANÇA DE RISCOS ACEITOS: Conduzir revisão periódica semestral das {tot_accepted} justificativas de risco aceito registradas, validando a vigência dos controles compensatórios."
        )
    else:
        recommendations.append(
            "MANUTENÇÃO DO FLUXO: Preservar a governança atual onde 100% das vulnerabilidades seguem para remediação sem riscos aceitos pendentes."
        )
    recommendations.append(
        "CICLO PDCA CONTÍNUO: Manter a frequência regular de varreduras automatizadas e confrontação baseline vs reteste para comprovar a eficácia da redução de risco perante auditorias externas."
    )

    auditor_statement_section = schemas.AuditorStatement(
        iso27001_control_8_8_status=ctrl_8_8_status,
        iso9001_pdca_status=pdca_status,
        summary_findings=findings_text,
        auditor_recommendations=recommendations,
        signed_by=current_user.full_name or current_user.username,
        signed_role="Auditor Sênior de Segurança da Informação & Qualidade"
    )

    return schemas.SlaAuditReportResponse(
        metadata=schemas.ReportMetadata(
            title=title_str,
            period=period_str,
            emission_date=emission_date_str,
            scope_name=scope_name,
            scope_group_id=scope_group_id,
            team=team_str,
            classification=classif_str,
            generated_by=current_user.full_name or current_user.username,
            scan_ids=target_scan_ids,
            scan_names=scan_names,
            notes=scope_notes
        ),
        sla_adherence=sla_adherence_section,
        iso9001_pdca=iso9001_pdca_section,
        accepted_risks_trail=accepted_risks_section,
        auditor_statement=auditor_statement_section
    )



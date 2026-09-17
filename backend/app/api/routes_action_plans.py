from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_, and_, literal
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_analyst_or_admin, check_user_group_access, get_user_allowed_group_ids

router = APIRouter(prefix="/action-plans", tags=["Gerenciador de Planos de Ação"])

def utc_now():
    return datetime.now(timezone.utc)

def format_task_out(t: models.ActionTask, now_utc: datetime) -> schemas.ActionTaskOut:
    out = schemas.ActionTaskOut.model_validate(t)
    out.assigned_user_name = (t.assigned_user.full_name or t.assigned_user.username) if t.assigned_user else None
    
    # Overdue check: past due date and not completed/done
    is_od = False
    if t.due_date and t.status != "DONE":
        due = t.due_date.replace(tzinfo=timezone.utc) if t.due_date.tzinfo is None else t.due_date
        is_od = due < now_utc
    out.is_overdue = is_od

    links_out = []
    for link in t.vulnerability_links:
        v = link.vulnerability
        links_out.append(schemas.ActionTaskVulnerabilityOut(
            id=link.id,
            action_task_id=link.action_task_id,
            vulnerability_id=link.vulnerability_id,
            plugin_id=v.plugin_id if v else None,
            plugin_name=v.plugin_name if v else None,
            severity=v.severity if v else None,
            cve=v.cve if v else None,
            host_ip=v.host.ip_address if (v and v.host) else None,
            host_name=v.host.hostname if (v and v.host) else None
        ))
    out.vulnerability_links = links_out
    out.vulnerabilities_count = len(links_out)
    return out

def format_plan_out(p: models.ActionPlan, now_utc: datetime) -> schemas.ActionPlanOut:
    out = schemas.ActionPlanOut.model_validate(p)
    
    # Resolve asset group name and complete hierarchy path
    group = p.asset_group
    if not group and p.target_host and p.target_host.asset_group:
        group = p.target_host.asset_group

    if group:
        from app.services.asset_group_service import compute_group_hierarchy_info
        level, hierarchy_path = compute_group_hierarchy_info(group)
        out.asset_group_name = hierarchy_path
        if not out.asset_group_id:
            out.asset_group_id = group.id
    else:
        out.asset_group_name = None

    out.target_host_ip = p.target_host.ip_address if p.target_host else None
    out.target_host_name = p.target_host.hostname if p.target_host else None
    out.owner_user_name = (p.owner_user.full_name or p.owner_user.username) if p.owner_user else None

    # Tasks stats and formatting
    tasks = p.tasks or []
    out.total_tasks = len(tasks)
    out.completed_tasks = sum(1 for t in tasks if t.status == "DONE")
    out.progress_percent = round((out.completed_tasks / out.total_tasks) * 100.0, 1) if out.total_tasks > 0 else 0.0

    # Overdue check
    is_od = False
    if p.due_date and p.status not in ["COMPLETED", "CANCELLED"]:
        due = p.due_date.replace(tzinfo=timezone.utc) if p.due_date.tzinfo is None else p.due_date
        is_od = due < now_utc
    out.is_overdue = is_od

    out.tasks = [format_task_out(t, now_utc) for t in tasks]
    return out


def build_action_plan_group_filter(db: Session, current_user: models.User, asset_group_id: Optional[int]):
    """
    Constrói a cláusula de filtro para planos de ação respeitando:
    1. Hierarquia multinível completa de Grupos de Ativos (grupos superiores cobrem
       todos os seus subgrupos descendentes de 2º, 3º e demais níveis).
    2. Vínculo de grupo direto (plan.asset_group_id), grupo do host alvo
       (target_host.asset_group_id) ou grupo de vulnerabilidades vinculadas.
    3. Controle de acesso granular RBAC do usuário.
    """
    from app.services.asset_group_service import get_descendant_group_ids

    allowed_ids = get_user_allowed_group_ids(db, current_user, action="view")

    def make_group_match_clause(group_ids: List[int]):
        return or_(
            models.ActionPlan.asset_group_id.in_(group_ids),
            models.ActionPlan.target_host.has(models.Host.asset_group_id.in_(group_ids)),
            models.ActionPlan.tasks.any(
                models.ActionTask.vulnerability_links.any(
                    models.ActionTaskVulnerabilityLink.vulnerability.has(
                        models.Vulnerability.asset_group_id.in_(group_ids)
                    )
                )
            )
        )

    if allowed_ids is not None:
        if asset_group_id:
            check_user_group_access(db, current_user, asset_group_id, action="view")
            descendant_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
            target_ids = list(set(descendant_ids).intersection(set(allowed_ids)))
            if not target_ids:
                return literal(False)
            return make_group_match_clause(target_ids)
        else:
            if not allowed_ids:
                return literal(False)
            return or_(
                make_group_match_clause(allowed_ids),
                and_(
                    models.ActionPlan.asset_group_id == None,
                    or_(
                        models.ActionPlan.target_host_id == None,
                        models.ActionPlan.target_host.has(models.Host.asset_group_id.in_(allowed_ids))
                    )
                )
            )
    elif asset_group_id:
        target_ids = get_descendant_group_ids(db, asset_group_id, include_self=True)
        return make_group_match_clause(target_ids)

    return None


@router.get("", response_model=List[schemas.ActionPlanOut])
def list_action_plans(
    asset_group_id: Optional[int] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    scope_type: Optional[str] = None,
    owner_user_id: Optional[int] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Lista planos de ação cadastrados com suporte a filtros, hierarquia multinível de grupos e RBAC.
    """
    query = db.query(models.ActionPlan)

    # Hierarchical group filter and RBAC
    group_filter = build_action_plan_group_filter(db, current_user, asset_group_id)
    if group_filter is not None:
        query = query.filter(group_filter)

    if status:
        query = query.filter(models.ActionPlan.status == status.upper())
    if priority:
        query = query.filter(models.ActionPlan.priority == priority.upper())
    if scope_type:
        query = query.filter(models.ActionPlan.scope_type == scope_type.upper())
    if owner_user_id:
        query = query.filter(models.ActionPlan.owner_user_id == owner_user_id)

    if search:
        st = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.ActionPlan.title.ilike(st),
                models.ActionPlan.description.ilike(st),
                models.ActionPlan.created_by_username.ilike(st)
            )
        )

    plans = query.order_by(models.ActionPlan.updated_at.desc(), models.ActionPlan.id.desc()).all()
    now_utc = utc_now()
    return [format_plan_out(p, now_utc) for p in plans]


@router.get("/stats", response_model=schemas.ActionPlanStatsOut)
def get_action_plans_stats(
    asset_group_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna métricas executivas consolidadas dos Planos de Ação e suas Etapas respeitando a hierarquia de grupos.
    """
    query = db.query(models.ActionPlan)
    group_filter = build_action_plan_group_filter(db, current_user, asset_group_id)
    if group_filter is not None:
        query = query.filter(group_filter)

    plans = query.all()
    now_utc = utc_now()

    total_plans = len(plans)
    planned = 0
    in_progress = 0
    completed = 0
    blocked = 0
    overdue = 0
    total_tasks = 0
    completed_tasks = 0

    for p in plans:
        st = (p.status or "").upper()
        if st == "PLANNED" or st == "DRAFT":
            planned += 1
        elif st == "IN_PROGRESS":
            in_progress += 1
        elif st == "COMPLETED":
            completed += 1
        elif st == "BLOCKED":
            blocked += 1

        if p.due_date and st not in ["COMPLETED", "CANCELLED"]:
            due = p.due_date.replace(tzinfo=timezone.utc) if p.due_date.tzinfo is None else p.due_date
            if due < now_utc:
                overdue += 1

        tasks = p.tasks or []
        total_tasks += len(tasks)
        completed_tasks += sum(1 for t in tasks if t.status == "DONE")

    overall_pct = round((completed_tasks / total_tasks) * 100.0, 1) if total_tasks > 0 else 0.0

    return schemas.ActionPlanStatsOut(
        total_plans=total_plans,
        planned_count=planned,
        in_progress_count=in_progress,
        completed_count=completed,
        blocked_count=blocked,
        overdue_count=overdue,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        overall_progress_percent=overall_pct
    )


@router.get("/assignees", response_model=List[schemas.ActionPlanAssigneeOut])
def get_action_plan_assignees(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Retorna lista de usuários do GvulStand habilitados para atribuição de tarefas e planos.
    """
    users = db.query(models.User).filter(models.User.is_active == True).order_by(models.User.username).all()
    return [
        schemas.ActionPlanAssigneeOut(
            id=u.id,
            username=u.username,
            full_name=u.full_name or u.username,
            role=u.role
        )
        for u in users
    ]


@router.get("/{plan_id}", response_model=schemas.ActionPlanOut)
def get_action_plan_details(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Obtém os detalhes completos de um plano de ação, suas etapas e vínculos com vulnerabilidades.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")
    check_gid = p.asset_group_id or (p.target_host.asset_group_id if p.target_host else None)
    if check_gid:
        check_user_group_access(db, current_user, check_gid, action="view")
    return format_plan_out(p, utc_now())


@router.post("", response_model=schemas.ActionPlanOut)
def create_action_plan(
    data: schemas.ActionPlanCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Cria um novo Plano de Ação (GvulStand Action Plans).
    Suporta escopos por Host, por Vulnerabilidade (Plugin), por Grupo ou Customizado.
    """
    if data.asset_group_id:
        check_user_group_access(db, current_user, data.asset_group_id, action="treat")

    # Validate target host if provided by ID or IP
    target_host = None
    if data.target_host_id:
        target_host = db.query(models.Host).filter(models.Host.id == data.target_host_id).first()
    if not target_host and data.target_host_ip:
        target_host = db.query(models.Host).filter(models.Host.ip_address == data.target_host_ip.strip()).order_by(models.Host.id.desc()).first()

    if target_host:
        data.target_host_id = target_host.id
        if not data.asset_group_id and target_host.asset_group_id:
            data.asset_group_id = target_host.asset_group_id
    else:
        data.target_host_id = None

    plan = models.ActionPlan(
        title=data.title.strip(),
        description=data.description.strip() if data.description else None,
        asset_group_id=data.asset_group_id,
        scope_type=data.scope_type.upper(),
        target_host_id=data.target_host_id,
        target_plugin_id=data.target_plugin_id.strip() if data.target_plugin_id else None,
        priority=data.priority.upper(),
        status=data.status.upper(),
        created_by_username=current_user.username,
        owner_user_id=data.owner_user_id or current_user.id,
        due_date=data.due_date
    )
    db.add(plan)
    db.flush()

    # Create initial tasks if provided
    if data.initial_tasks:
        for idx, t_data in enumerate(data.initial_tasks):
            task = models.ActionTask(
                action_plan_id=plan.id,
                title=t_data.title.strip(),
                description=t_data.description.strip() if t_data.description else None,
                order_index=t_data.order_index or idx,
                status=t_data.status.upper(),
                assigned_user_id=t_data.assigned_user_id or plan.owner_user_id,
                start_date=t_data.start_date,
                due_date=t_data.due_date or plan.due_date
            )
            db.add(task)
            db.flush()
            if t_data.vulnerability_ids:
                for vid in t_data.vulnerability_ids:
                    link = models.ActionTaskVulnerabilityLink(
                        action_task_id=task.id,
                        vulnerability_id=vid
                    )
                    db.add(link)

    # Auto-link vulnerabilities according to scope
    if data.auto_link_vulnerabilities:
        matching_vulns = []
        if plan.scope_type == "HOST" and plan.target_host_id:
            matching_vulns = db.query(models.Vulnerability).filter(
                models.Vulnerability.host_id == plan.target_host_id,
                ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"])
            ).all()
        elif plan.scope_type == "VULNERABILITY" and plan.target_plugin_id:
            vq = db.query(models.Vulnerability).filter(
                models.Vulnerability.plugin_id == plan.target_plugin_id,
                ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"])
            )
            if plan.asset_group_id:
                from app.services.asset_group_service import get_descendant_group_ids
                target_gids = get_descendant_group_ids(db, plan.asset_group_id, include_self=True)
                vq = vq.filter(models.Vulnerability.asset_group_id.in_(target_gids))
            matching_vulns = vq.all()
        elif plan.scope_type == "GROUP" and plan.asset_group_id:
            from app.services.asset_group_service import get_descendant_group_ids
            target_gids = get_descendant_group_ids(db, plan.asset_group_id, include_self=True)
            matching_vulns = db.query(models.Vulnerability).filter(
                models.Vulnerability.asset_group_id.in_(target_gids),
                models.Vulnerability.severity.in_(["Critical", "critical", "High", "high"]),
                ~models.Vulnerability.severity.in_(["Info", "info", "None", "none"])
            ).limit(200).all()

        if matching_vulns:
            # Create a remediation task linking them if no tasks exist
            if not data.initial_tasks:
                task = models.ActionTask(
                    action_plan_id=plan.id,
                    title=f"Remediação de Vulnerabilidades ({len(matching_vulns)} apontamentos)",
                    description=f"Execução das tratativas de correção para os achados identificados no escopo {plan.scope_type}.",
                    order_index=0,
                    status="TODO",
                    assigned_user_id=plan.owner_user_id,
                    due_date=plan.due_date
                )
                db.add(task)
                db.flush()
                for v in matching_vulns:
                    link = models.ActionTaskVulnerabilityLink(
                        action_task_id=task.id,
                        vulnerability_id=v.id
                    )
                    db.add(link)

    db.commit()
    db.refresh(plan)
    return format_plan_out(plan, utc_now())


@router.put("/{plan_id}", response_model=schemas.ActionPlanOut)
def update_action_plan(
    plan_id: int,
    data: schemas.ActionPlanUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Atualiza metadados, prazos, prioridade ou status de um plano de ação.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")
    if p.asset_group_id:
        check_user_group_access(db, current_user, p.asset_group_id, action="treat")

    if data.title is not None:
        p.title = data.title.strip()
    if data.description is not None:
        p.description = data.description.strip() if data.description else None
    if data.asset_group_id is not None:
        p.asset_group_id = data.asset_group_id
    if data.scope_type is not None:
        p.scope_type = data.scope_type.upper()
    if data.target_host_id is not None or data.target_host_ip is not None:
        target_h = None
        if data.target_host_id:
            target_h = db.query(models.Host).filter(models.Host.id == data.target_host_id).first()
        if not target_h and data.target_host_ip:
            target_h = db.query(models.Host).filter(models.Host.ip_address == data.target_host_ip.strip()).order_by(models.Host.id.desc()).first()
        p.target_host_id = target_h.id if target_h else None
    if data.target_plugin_id is not None:
        p.target_plugin_id = data.target_plugin_id
    if data.priority is not None:
        p.priority = data.priority.upper()
    if data.status is not None:
        p.status = data.status.upper()
    if data.owner_user_id is not None:
        p.owner_user_id = data.owner_user_id
    if data.due_date is not None:
        p.due_date = data.due_date

    p.updated_at = utc_now()
    db.commit()
    db.refresh(p)
    return format_plan_out(p, utc_now())


@router.delete("/{plan_id}")
def delete_action_plan(
    plan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Exclui um plano de ação e todas as suas etapas associadas.
    Permitido para Administradores ou o Analista criador do plano.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")

    if current_user.role != "admin" and p.created_by_username != current_user.username:
        raise HTTPException(status_code=403, detail="Apenas administradores ou o usuário criador podem excluir este plano de ação.")

    db.delete(p)
    db.commit()
    return {"message": f"Plano de Ação #{plan_id} removido com sucesso."}


@router.post("/{plan_id}/tasks", response_model=schemas.ActionTaskOut)
def add_action_task(
    plan_id: int,
    data: schemas.ActionTaskCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Adiciona uma nova etapa/tarefa a um plano de ação existente.
    """
    p = db.query(models.ActionPlan).filter(models.ActionPlan.id == plan_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Plano de Ação não encontrado.")
    if p.asset_group_id:
        check_user_group_access(db, current_user, p.asset_group_id, action="treat")

    # Order index calculation
    max_order = db.query(func.coalesce(func.max(models.ActionTask.order_index), 0)).filter(
        models.ActionTask.action_plan_id == plan_id
    ).scalar()

    task = models.ActionTask(
        action_plan_id=plan_id,
        title=data.title.strip(),
        description=data.description.strip() if data.description else None,
        order_index=data.order_index if data.order_index != 0 else (max_order + 1),
        status=data.status.upper(),
        assigned_user_id=data.assigned_user_id or p.owner_user_id,
        start_date=data.start_date,
        due_date=data.due_date or p.due_date
    )
    db.add(task)
    db.flush()

    if data.vulnerability_ids:
        for vid in data.vulnerability_ids:
            link = models.ActionTaskVulnerabilityLink(
                action_task_id=task.id,
                vulnerability_id=vid
            )
            db.add(link)

    p.updated_at = utc_now()
    db.commit()
    db.refresh(task)
    return format_task_out(task, utc_now())


# Separate Task operations router or direct endpoints
@router.put("/tasks/{task_id}", response_model=schemas.ActionTaskOut)
def update_action_task(
    task_id: int,
    data: schemas.ActionTaskUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Atualiza uma etapa/tarefa: status (TODO, DOING, REVIEW, DONE, BLOCKED), prazos e responsável.
    Permitido para Administradores, Analistas ou o Responsável direto pela tarefa.
    """
    t = db.query(models.ActionTask).filter(models.ActionTask.id == task_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada.")

    # Permissions check: Admin, Analyst with group access, or Task Assignee
    is_admin = current_user.role == "admin"
    is_assignee = t.assigned_user_id == current_user.id
    is_analyst = current_user.role == "analyst"

    if not (is_admin or is_assignee or is_analyst):
        raise HTTPException(status_code=403, detail="Sem permissão para atualizar esta tarefa.")

    now = utc_now()

    if data.title is not None and (is_admin or is_analyst):
        t.title = data.title.strip()
    if data.description is not None and (is_admin or is_analyst):
        t.description = data.description.strip() if data.description else None
    if data.order_index is not None and (is_admin or is_analyst):
        t.order_index = data.order_index
    if data.assigned_user_id is not None and (is_admin or is_analyst):
        t.assigned_user_id = data.assigned_user_id
    if data.start_date is not None and (is_admin or is_analyst):
        t.start_date = data.start_date
    if data.due_date is not None and (is_admin or is_analyst):
        t.due_date = data.due_date

    # Status update
    if data.status is not None:
        new_status = data.status.upper()
        if new_status != t.status:
            t.status = new_status
            if new_status == "DONE":
                t.completed_at = now
            else:
                t.completed_at = None

    # Sync linked vulnerabilities treatment (ISO 27001)
    if data.sync_vuln_treatment or (data.status and data.status.upper() == "DONE"):
        for link in t.vulnerability_links:
            v = link.vulnerability
            if v and v.treatment_status != "Remediated":
                target_status = "Remediated" if t.status == "DONE" else "In_Remediation"
                v.treatment_status = target_status
                v.treated_by_username = current_user.username
                v.treated_at = now
                hist = models.VulnerabilityTreatmentHistory(
                    vulnerability_id=v.id,
                    treatment_status=target_status,
                    treatment_notes=f"Tratativa sincronizada via Plano de Ação #{t.action_plan_id} (Etapa: {t.title}).",
                    changed_by_username=current_user.username,
                    changed_at=now
                )
                db.add(hist)

    if data.vulnerability_ids is not None and (is_admin or is_analyst):
        db.query(models.ActionTaskVulnerabilityLink).filter(
            models.ActionTaskVulnerabilityLink.action_task_id == t.id
        ).delete()
        for vid in data.vulnerability_ids:
            db.add(models.ActionTaskVulnerabilityLink(
                action_task_id=t.id,
                vulnerability_id=vid
            ))

    t.updated_at = now
    if t.action_plan:
        t.action_plan.updated_at = now

        # Auto-update plan status to COMPLETED if all tasks are DONE
        all_tasks = t.action_plan.tasks or []
        if all_tasks and all(tk.status == "DONE" for tk in all_tasks):
            t.action_plan.status = "COMPLETED"
        elif t.action_plan.status == "PLANNED" and t.status in ["DOING", "REVIEW", "DONE"]:
            t.action_plan.status = "IN_PROGRESS"

    db.commit()
    db.refresh(t)
    return format_task_out(t, now)


@router.delete("/tasks/{task_id}")
def delete_action_task(
    task_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_analyst_or_admin)
):
    """
    Remove uma etapa/tarefa de um plano de ação.
    """
    t = db.query(models.ActionTask).filter(models.ActionTask.id == task_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada.")

    plan = t.action_plan
    db.delete(t)
    if plan:
        plan.updated_at = utc_now()
    db.commit()
    return {"message": f"Tarefa #{task_id} removida com sucesso."}

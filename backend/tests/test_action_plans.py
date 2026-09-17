import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app import models

client = TestClient(app)

def get_admin_token():
    res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert res.status_code == 200
    return res.json()["access_token"]

def test_action_plans_lifecycle_and_features():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test Assignees Endpoint
    res_assignees = client.get("/api/action-plans/assignees", headers=headers)
    assert res_assignees.status_code == 200
    assignees = res_assignees.json()
    assert isinstance(assignees, list)
    assert len(assignees) >= 1
    assert any(u["username"] == "Admin" for u in assignees)

    # 2. Test Stats Initial
    res_stats_init = client.get("/api/action-plans/stats", headers=headers)
    assert res_stats_init.status_code == 200
    stats_init = res_stats_init.json()
    assert "total_plans" in stats_init
    assert "overall_progress_percent" in stats_init

    # Find a host and vulnerability in DB for linking
    db = SessionLocal()
    host = db.query(models.Host).first()
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.severity != "Info").first()
    db.close()

    host_id = host.id if host else None
    vuln_id = vuln.id if vuln else None
    plugin_id = vuln.plugin_id if vuln else "104743"

    # 3. Create Action Plan (Scope: HOST with auto-link vulnerabilities)
    due_date = (datetime.now(timezone.utc) + timedelta(days=15)).isoformat()
    create_payload = {
        "title": "Plano de Remediação ISO 27001 - Host Principal",
        "description": "Remediação das vulnerabilidades críticas e altas identificadas no ativo de produção.",
        "scope_type": "HOST",
        "target_host_id": host_id,
        "priority": "HIGH",
        "status": "PLANNED",
        "due_date": due_date,
        "auto_link_vulnerabilities": True,
        "initial_tasks": [
            {
                "title": "Homologar patch em ambiente de staging",
                "description": "Validação de compatibilidade e impacto em serviços.",
                "status": "TODO",
                "order_index": 1,
                "vulnerability_ids": [vuln_id] if vuln_id else []
            }
        ]
    }

    res_create = client.post("/api/action-plans", json=create_payload, headers=headers)
    assert res_create.status_code == 200
    plan = res_create.json()
    plan_id = plan["id"]
    assert plan["title"] == create_payload["title"]
    assert plan["priority"] == "HIGH"
    assert plan["status"] == "PLANNED"
    assert plan["scope_type"] == "HOST"
    assert len(plan["tasks"]) >= 1
    assert plan["owner_user_name"] is not None

    task_1 = plan["tasks"][0]
    task_1_id = task_1["id"]
    assert task_1["status"] == "TODO"

    # 4. Test Compatibility with /api/v1/action-plans
    res_v1 = client.get(f"/api/v1/action-plans/{plan_id}", headers=headers)
    assert res_v1.status_code == 200
    assert res_v1.json()["id"] == plan_id

    # 5. Add a second task to the plan
    add_task_payload = {
        "title": "Aplicar correção em produção e reiniciar serviço",
        "description": "Execução na janela de manutenção com rollback planejado.",
        "status": "TODO",
        "order_index": 2,
        "due_date": due_date,
        "vulnerability_ids": [vuln_id] if vuln_id else []
    }
    res_add_task = client.post(f"/api/action-plans/{plan_id}/tasks", json=add_task_payload, headers=headers)
    assert res_add_task.status_code == 200
    task_2 = res_add_task.json()
    task_2_id = task_2["id"]
    assert task_2["order_index"] == 2
    assert task_2["title"] == add_task_payload["title"]

    # 6. List Action Plans with filters
    res_list = client.get(f"/api/action-plans?status=PLANNED&priority=HIGH&search=ISO 27001", headers=headers)
    assert res_list.status_code == 200
    plans_list = res_list.json()
    assert len(plans_list) >= 1
    assert any(p["id"] == plan_id for p in plans_list)

    # 7. Update Task 1 to DONE with sync_vuln_treatment
    res_update_t1 = client.put(
        f"/api/action-plans/tasks/{task_1_id}",
        json={"status": "DONE", "sync_vuln_treatment": True},
        headers=headers
    )
    assert res_update_t1.status_code == 200
    updated_t1 = res_update_t1.json()
    assert updated_t1["status"] == "DONE"
    assert updated_t1["completed_at"] is not None

    # Verify plan progress recalculated
    res_plan_progress = client.get(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_plan_progress.status_code == 200
    p_prog = res_plan_progress.json()
    assert p_prog["completed_tasks"] >= 1
    assert p_prog["progress_percent"] > 0

    # If vuln was linked, verify treatment history and status
    if vuln_id:
        db = SessionLocal()
        v_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
        assert v_check.treatment_status == "Remediated"
        hist = db.query(models.VulnerabilityTreatmentHistory).filter(
            models.VulnerabilityTreatmentHistory.vulnerability_id == vuln_id
        ).order_by(models.VulnerabilityTreatmentHistory.id.desc()).first()
        assert hist is not None
        assert "Plano de Ação" in hist.treatment_notes
        db.close()

    # 8. Update Task 2 to DONE -> Should auto-complete Plan
    res_update_t2 = client.put(
        f"/api/action-plans/tasks/{task_2_id}",
        json={"status": "DONE"},
        headers=headers
    )
    assert res_update_t2.status_code == 200

    res_plan_completed = client.get(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_plan_completed.status_code == 200
    assert res_plan_completed.json()["status"] == "COMPLETED"
    assert res_plan_completed.json()["progress_percent"] == 100.0

    # 9. Update Plan Metadata
    res_update_plan = client.put(
        f"/api/action-plans/{plan_id}",
        json={"title": "Plano de Remediação ISO 27001 - Concluído com Sucesso", "priority": "CRITICAL"},
        headers=headers
    )
    assert res_update_plan.status_code == 200
    assert res_update_plan.json()["title"] == "Plano de Remediação ISO 27001 - Concluído com Sucesso"
    assert res_update_plan.json()["priority"] == "CRITICAL"

    # 10. Delete Task
    res_del_task = client.delete(f"/api/action-plans/tasks/{task_2_id}", headers=headers)
    assert res_del_task.status_code == 200

    # 11. Delete Plan
    res_del_plan = client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_del_plan.status_code == 200

    # Verify 404 on deleted plan
    res_404 = client.get(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_404.status_code == 404

def test_action_plan_creation_from_host_ip_and_plugin():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    host = db.query(models.Host).first()
    db.close()

    host_ip = host.ip_address if host else "192.168.1.100"

    # 1. Create plan by host IP
    res_host = client.post("/api/action-plans", json={
        "title": f"Plano de Ação para Host {host_ip}",
        "scope_type": "HOST",
        "target_host_ip": host_ip,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_host.status_code == 200
    plan_host = res_host.json()
    assert plan_host["title"] == f"Plano de Ação para Host {host_ip}"
    if host:
        assert plan_host["target_host_id"] is not None
        assert plan_host["target_host_ip"] == host.ip_address

    # 2. Create plan by Plugin ID
    res_plugin = client.post("/api/action-plans", json={
        "title": "Plano de Remediação Plugin 104743",
        "scope_type": "VULNERABILITY",
        "target_plugin_id": "104743",
        "priority": "CRITICAL",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_plugin.status_code == 200
    plan_plugin = res_plugin.json()
    assert plan_plugin["target_plugin_id"] == "104743"

    # Cleanup
    client.delete(f"/api/action-plans/{plan_host['id']}", headers=headers)
    client.delete(f"/api/action-plans/{plan_plugin['id']}", headers=headers)

def test_action_plans_hierarchical_asset_group_filtering():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create 3-level asset group hierarchy
    ts = int(datetime.now().timestamp())
    res_root = client.post("/api/asset-groups", json={
        "name": f"Corporativo Matriz {ts}",
        "description": "Nível 1"
    }, headers=headers)
    assert res_root.status_code in [200, 201]
    root_gid = res_root.json()["id"]

    res_child = client.post("/api/asset-groups", json={
        "name": f"TI Regional {ts}",
        "description": "Nível 2",
        "parent_id": root_gid
    }, headers=headers)
    assert res_child.status_code in [200, 201]
    child_gid = res_child.json()["id"]

    res_subchild = client.post("/api/asset-groups", json={
        "name": f"Cluster Web {ts}",
        "description": "Nível 3",
        "parent_id": child_gid
    }, headers=headers)
    assert res_subchild.status_code in [200, 201]
    subchild_gid = res_subchild.json()["id"]

    # 2. Create Action Plan directly assigned to Level 3 (subchild)
    res_create = client.post("/api/action-plans", json={
        "title": "Plano Específico Subgrupo Nível 3",
        "description": "Tratativa técnica em servidor do cluster web",
        "scope_type": "GROUP",
        "asset_group_id": subchild_gid,
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_create.status_code == 200
    plan = res_create.json()
    plan_id = plan["id"]
    assert f"Corporativo Matriz {ts} > TI Regional {ts} > Cluster Web {ts}" in plan["asset_group_name"]

    # 3. Filter by Level 1 (Root/Superior) -> MUST return the plan
    res_list_root = client.get(f"/api/action-plans?asset_group_id={root_gid}", headers=headers)
    assert res_list_root.status_code == 200
    plans_root = res_list_root.json()
    assert any(p["id"] == plan_id for p in plans_root)

    # 4. Check Stats for Level 1 (Root/Superior) -> MUST count the plan
    res_stats_root = client.get(f"/api/action-plans/stats?asset_group_id={root_gid}", headers=headers)
    assert res_stats_root.status_code == 200
    stats_root = res_stats_root.json()
    assert stats_root["total_plans"] >= 1
    assert stats_root["planned_count"] >= 1

    # 5. Filter by Level 2 (Child) -> MUST return the plan
    res_list_child = client.get(f"/api/action-plans?asset_group_id={child_gid}", headers=headers)
    assert res_list_child.status_code == 200
    plans_child = res_list_child.json()
    assert any(p["id"] == plan_id for p in plans_child)

    # 6. Check Stats for Level 2 (Child) -> MUST count the plan
    res_stats_child = client.get(f"/api/action-plans/stats?asset_group_id={child_gid}", headers=headers)
    assert res_stats_child.status_code == 200
    assert res_stats_child.json()["total_plans"] >= 1

    # 7. Filter by Level 3 (Direct) -> MUST return the plan
    res_list_subchild = client.get(f"/api/action-plans?asset_group_id={subchild_gid}", headers=headers)
    assert res_list_subchild.status_code == 200
    assert any(p["id"] == plan_id for p in res_list_subchild.json())

    # 8. Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    client.delete(f"/api/asset-groups/{subchild_gid}", headers=headers)
    client.delete(f"/api/asset-groups/{child_gid}", headers=headers)
    client.delete(f"/api/asset-groups/{root_gid}", headers=headers)



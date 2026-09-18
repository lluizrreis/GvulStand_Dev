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
    vuln = db.query(models.Vulnerability).filter(~models.Vulnerability.severity.in_(["Info", "info"])).first()
    host = vuln.host if vuln else db.query(models.Host).first()
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
    vuln = db.query(models.Vulnerability).filter(~models.Vulnerability.severity.in_(["Info", "info"])).first()
    host = vuln.host if vuln else None
    db.close()

    host_ip = host.ip_address if host else "10.233.20.4"

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


def test_action_plans_tags_and_multitagging():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create tag via POST /api/action-plans/tags
    res_tag = client.post("/api/action-plans/tags", json={"name": "SOX_TEST", "color": "#6366f1"}, headers=headers)
    assert res_tag.status_code == 200
    tag_data = res_tag.json()
    assert tag_data["name"] == "SOX_TEST"
    assert tag_data["color"] == "#6366f1"

    # 2. Get tags list
    res_tags_list = client.get("/api/action-plans/tags", headers=headers)
    assert res_tags_list.status_code == 200
    tags_all = res_tags_list.json()
    assert any(t["name"] == "SOX_TEST" for t in tags_all)

    # 3. Create plan with tags
    res_plan = client.post("/api/action-plans", json={
        "title": "Plano com Multi-Tagging SOX e PCI",
        "scope_type": "CUSTOM",
        "priority": "MEDIUM",
        "status": "PLANNED",
        "tags": ["SOX_TEST", "PCI_TEST"]
    }, headers=headers)
    assert res_plan.status_code == 200
    plan = res_plan.json()
    plan_id = plan["id"]
    assert "SOX_TEST" in plan["tags"]
    assert "PCI_TEST" in plan["tags"]

    # 4. Filter by tag
    res_filt = client.get("/api/action-plans?tag=SOX_TEST", headers=headers)
    assert res_filt.status_code == 200
    assert any(p["id"] == plan_id for p in res_filt.json())

    res_filt_none = client.get("/api/action-plans?tag=NONEXISTENT_TAG_XYZ", headers=headers)
    assert res_filt_none.status_code == 200
    assert not any(p["id"] == plan_id for p in res_filt_none.json())

    # 5. Update tags on plan
    res_update = client.put(f"/api/action-plans/{plan_id}", json={
        "tags": ["PCI_TEST"]
    }, headers=headers)
    assert res_update.status_code == 200
    assert "PCI_TEST" in res_update.json()["tags"]
    assert "SOX_TEST" not in res_update.json()["tags"]

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)


def test_action_plans_matrix_scope_and_preview():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Preview impact with unmatched / non-existent hosts
    preview_payload = {
        "scope_type": "MATRIX_NN",
        "scope_host_ips": ["192.0.2.1", "192.0.2.2"],
        "scope_plugin_ids": ["104743", "104410"]
    }
    res_preview = client.post("/api/action-plans/preview-impact", json=preview_payload, headers=headers)
    assert res_preview.status_code == 200
    preview = res_preview.json()
    assert "total_vulnerabilities" in preview
    assert "severity_distribution" in preview
    assert preview["is_relational_valid"] is False
    assert len(preview["unmatched_hosts"]) > 0

    # 2. Reject Matrix Plan with non-existent/unmatched hosts (HTTP 422)
    invalid_create_payload = {
        "title": "Plano Escopo Matricial N:N Invalido",
        "scope_type": "MATRIX_NN",
        "priority": "HIGH",
        "status": "PLANNED",
        "scope_host_ips": ["192.0.2.1"],
        "scope_plugin_ids": ["104743"]
    }
    res_inv = client.post("/api/action-plans", json=invalid_create_payload, headers=headers)
    assert res_inv.status_code == 422
    assert "não relacional" in res_inv.json()["detail"].lower() or "inválido" in res_inv.json()["detail"].lower()

    # 3. Create Valid Matrix Plan with existing hosts and associated plugin
    db = SessionLocal()
    real_vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.plugin_id == "104743",
        ~models.Vulnerability.severity.in_(["Info", "info"])
    ).limit(2).all()
    real_host_ips = list(dict.fromkeys([v.host.ip_address for v in real_vulns if v.host]))
    db.close()
    assert len(real_host_ips) >= 1

    valid_matrix_payload = {
        "title": "Plano Escopo Matricial N:N Válido",
        "scope_type": "MATRIX_NN",
        "priority": "HIGH",
        "status": "PLANNED",
        "scope_host_ips": real_host_ips,
        "scope_plugin_ids": ["104743"]
    }
    res_create = client.post("/api/action-plans", json=valid_matrix_payload, headers=headers)
    assert res_create.status_code == 200
    plan = res_create.json()
    plan_id = plan["id"]
    assert plan["scope_type"] == "MATRIX_NN"
    assert "104743" in plan["scope_plugin_ids"]

    # 4. Reject Update Matrix Plan with non-existent / orphan host (HTTP 422)
    res_update_inv = client.put(f"/api/action-plans/{plan_id}", json={
        "scope_host_ips": real_host_ips + ["192.0.2.99"]
    }, headers=headers)
    assert res_update_inv.status_code == 422

    # Cleanup
    client.delete(f"/api/action-plans/{plan_id}", headers=headers)


def test_action_plans_precedence_and_orphans():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Setup test host and vulnerability in DB
    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    if not group:
        group = models.AssetGroup(name="Grupo Precedencia Test")
        db.add(group)
        db.commit()
        db.refresh(group)

    test_ip = f"172.16.99.{int(datetime.now().timestamp()) % 240 + 5}"
    scan = db.query(models.Scan).first()
    if not scan:
        scan = models.Scan(
            asset_group_id=group.id,
            filename="prec_test_scan.csv",
            scan_name="Precedence Test Scan",
            uploaded_by="Admin"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

    host = models.Host(
        scan_id=scan.id,
        ip_address=test_ip,
        hostname=f"srv-prec-{test_ip}",
        asset_group_id=group.id,
        risk_score=10.0
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    test_plugin = f"PLUG_{int(datetime.now().timestamp()) % 90000}"
    vuln = models.Vulnerability(
        scan_id=scan.id,
        asset_group_id=group.id,
        host_id=host.id,
        plugin_id=test_plugin,
        plugin_name="Vulnerabilidade de Teste Precedencia",
        severity="High",
        treatment_status="Open"
    )
    db.add(vuln)
    db.commit()
    host_id = host.id
    vuln_id = vuln.id
    db.close()

    # 1. Broad Plan (scope: VULNERABILITY)
    res_broad = client.post("/api/action-plans", json={
        "title": f"Plano Geral Plugin {test_plugin}",
        "scope_type": "VULNERABILITY",
        "target_plugin_id": test_plugin,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_broad.status_code == 200
    broad_plan_id = res_broad.json()["id"]

    # Check that vulnerability was linked and status is In_Action_Plan
    db = SessionLocal()
    v1 = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    assert v1.treatment_status == "In_Action_Plan"
    db.close()

    # Verify active action plan in vuln details
    res_v_detail = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert res_v_detail.status_code == 200
    assert res_v_detail.json()["active_action_plan_id"] == broad_plan_id

    # 2. Host Plan (scope: HOST) - Higher precedence than broad vulnerability
    res_host_plan = client.post("/api/action-plans", json={
        "title": f"Plano Específico Host {test_ip}",
        "scope_type": "HOST",
        "target_host_id": host_id,
        "priority": "CRITICAL",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_host_plan.status_code == 200
    host_plan_id = res_host_plan.json()["id"]

    # Precedence rule: Vulnerability should now be associated with host_plan_id
    res_v_detail2 = client.get(f"/api/vulnerabilities/{vuln_id}", headers=headers)
    assert res_v_detail2.status_code == 200
    assert res_v_detail2.json()["active_action_plan_id"] == host_plan_id

    # Check treatment history for precedence transfer notes
    res_hist = client.get(f"/api/vulnerabilities/{vuln_id}/treatment-history", headers=headers)
    assert res_hist.status_code == 200
    hist_entries = res_hist.json()
    assert any("precedência" in (h.get("treatment_notes") or "").lower() for h in hist_entries)

    # 3. Test orphan filter and endpoint
    res_unassigned = client.get("/api/action-plans/unassigned-vulns", headers=headers)
    assert res_unassigned.status_code == 200
    assert isinstance(res_unassigned.json(), list)

    # 4. Delete host plan -> findings should revert to Open (orphan)
    res_del_host = client.delete(f"/api/action-plans/{host_plan_id}", headers=headers)
    assert res_del_host.status_code == 200

    db = SessionLocal()
    v_reverted = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    assert v_reverted.treatment_status == "Open"
    db.close()

    # Cleanup
    client.delete(f"/api/action-plans/{broad_plan_id}", headers=headers)
    db = SessionLocal()
    db.query(models.VulnerabilityTreatmentHistory).filter(
        models.VulnerabilityTreatmentHistory.vulnerability_id == vuln_id
    ).delete()
    db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).delete()
    db.query(models.Host).filter(models.Host.id == host_id).delete()
    db.commit()
    db.close()


def test_action_plan_rejection_for_non_existent_or_empty_host():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Non-existent IP
    res_non_existent = client.post("/api/action-plans", json={
        "title": "Plano Host Inexistente",
        "scope_type": "HOST",
        "target_host_ip": "198.51.100.254",
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_non_existent.status_code == 422
    assert "não foi encontrado" in res_non_existent.json()["detail"].lower()

    # 2. Host with no actionable vulnerabilities
    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    scan = db.query(models.Scan).first()
    dummy_ip = f"192.0.2.{int(datetime.now().timestamp()) % 200 + 10}"
    h_empty = models.Host(
        scan_id=scan.id if scan else None,
        ip_address=dummy_ip,
        hostname=f"srv-empty-{dummy_ip}",
        asset_group_id=group.id if group else None,
        risk_score=0.0
    )
    db.add(h_empty)
    db.commit()
    db.refresh(h_empty)
    db.close()

    res_empty_host = client.post("/api/action-plans", json={
        "title": "Plano Host Sem Vulnerabilidades",
        "scope_type": "HOST",
        "target_host_ip": dummy_ip,
        "priority": "MEDIUM",
        "status": "PLANNED"
    }, headers=headers)
    assert res_empty_host.status_code == 422
    assert "não possui vulnerabilidades" in res_empty_host.json()["detail"].lower()

    # Cleanup dummy host
    db = SessionLocal()
    db.query(models.Host).filter(models.Host.id == h_empty.id).delete()
    db.commit()
    db.close()


def test_action_plan_rejection_for_non_existent_plugin():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/action-plans", json={
        "title": "Plano Plugin Fantasma",
        "scope_type": "VULNERABILITY",
        "target_plugin_id": "9999999999",
        "priority": "LOW",
        "status": "PLANNED"
    }, headers=headers)
    assert res.status_code == 422
    assert "não possui vulnerabilidades" in res.json()["detail"].lower()


def test_action_plan_matrix_strict_bipartite_validation():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    scan = db.query(models.Scan).first()
    ts = int(datetime.now().timestamp())

    ip_a = f"198.18.1.{ts % 200 + 1}"
    ip_b = f"198.18.2.{ts % 200 + 2}"

    h_a = models.Host(scan_id=scan.id, ip_address=ip_a, hostname=f"srv-a-{ip_a}", asset_group_id=group.id, risk_score=10.0)
    h_b = models.Host(scan_id=scan.id, ip_address=ip_b, hostname=f"srv-b-{ip_b}", asset_group_id=group.id, risk_score=10.0)
    db.add(h_a)
    db.add(h_b)
    db.commit()
    db.refresh(h_a)
    db.refresh(h_b)

    plug_a = f"PLUG_A_{ts % 90000}"
    plug_b = f"PLUG_B_{ts % 90000}"

    # h_a has plug_a only, h_b has plug_b only
    v_a = models.Vulnerability(scan_id=scan.id, asset_group_id=group.id, host_id=h_a.id, plugin_id=plug_a, plugin_name="Vuln A", severity="High", treatment_status="Open")
    v_b = models.Vulnerability(scan_id=scan.id, asset_group_id=group.id, host_id=h_b.id, plugin_id=plug_b, plugin_name="Vuln B", severity="High", treatment_status="Open")
    db.add(v_a)
    db.add(v_b)
    db.commit()
    db.refresh(v_a)
    db.refresh(v_b)
    va_id = v_a.id
    vb_id = v_b.id
    ha_id = h_a.id
    hb_id = h_b.id
    db.close()

    # Case 1: Orphan Host (provide [ip_a, ip_b] but only [plug_a] -> ip_b has NO vulnerability from the list!)
    res_orphan_host = client.post("/api/action-plans", json={
        "title": "Plano Matriz com Host Orfao",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip_a, ip_b],
        "scope_plugin_ids": [plug_a],
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_orphan_host.status_code == 422
    err_detail_1 = res_orphan_host.json()["detail"]
    assert "não relacional" in err_detail_1.lower()
    assert ip_b in err_detail_1

    # Case 2: Orphan Plugin (provide [ip_a] but [plug_a, plug_b] -> plug_b affects NO host in the list!)
    res_orphan_plugin = client.post("/api/action-plans", json={
        "title": "Plano Matriz com Plugin Orfao",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip_a],
        "scope_plugin_ids": [plug_a, plug_b],
        "priority": "HIGH",
        "status": "PLANNED"
    }, headers=headers)
    assert res_orphan_plugin.status_code == 422
    err_detail_2 = res_orphan_plugin.json()["detail"]
    assert "não relacional" in err_detail_2.lower()
    assert plug_b in err_detail_2

    # Case 3: Valid Bipartite Plan (provide [ip_a, ip_b] and [plug_a, plug_b] -> every host has >= 1 vuln, every plugin affects >= 1 host!)
    res_valid = client.post("/api/action-plans", json={
        "title": "Plano Matriz Bipartido Valido",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [ip_a, ip_b],
        "scope_plugin_ids": [plug_a, plug_b],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_valid.status_code == 200
    valid_plan_id = res_valid.json()["id"]

    # Clean up
    client.delete(f"/api/action-plans/{valid_plan_id}", headers=headers)
    db = SessionLocal()
    db.query(models.VulnerabilityTreatmentHistory).filter(models.VulnerabilityTreatmentHistory.vulnerability_id.in_([va_id, vb_id])).delete()
    db.query(models.Vulnerability).filter(models.Vulnerability.id.in_([va_id, vb_id])).delete()
    db.query(models.Host).filter(models.Host.id.in_([ha_id, hb_id])).delete()
    db.commit()
    db.close()


def test_action_plan_deletion_reverts_vulnerabilities_to_open_and_logs():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    group = db.query(models.AssetGroup).first()
    scan = db.query(models.Scan).first()
    ts = int(datetime.now().timestamp())

    del_ip = f"198.18.5.{ts % 200 + 5}"
    del_plug = f"PLUG_DEL_{ts % 90000}"

    h = models.Host(scan_id=scan.id, ip_address=del_ip, hostname=f"srv-del-{del_ip}", asset_group_id=group.id, risk_score=10.0)
    db.add(h)
    db.commit()
    db.refresh(h)

    v = models.Vulnerability(
        scan_id=scan.id,
        asset_group_id=group.id,
        host_id=h.id,
        plugin_id=del_plug,
        plugin_name="Vuln Para Exclusao",
        severity="High",
        treatment_status="Open"
    )
    db.add(v)
    db.commit()
    db.refresh(v)
    v_id = v.id
    h_id = h.id
    db.close()

    # 1. Create Action Plan linking this vulnerability
    plan_title = f"Plano de Ação para Teste de Exclusão {ts}"
    res_create = client.post("/api/action-plans", json={
        "title": plan_title,
        "scope_type": "HOST",
        "target_host_id": h_id,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }, headers=headers)
    assert res_create.status_code == 200
    plan_id = res_create.json()["id"]

    # Verify vulnerability transitioned to In_Action_Plan
    db = SessionLocal()
    v_check = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
    assert v_check.treatment_status == "In_Action_Plan"
    db.close()

    # 2. Delete the Action Plan
    res_del = client.delete(f"/api/action-plans/{plan_id}", headers=headers)
    assert res_del.status_code == 200

    # 3. Verify vulnerability transitioned back to Open with explicit deletion audit log
    db = SessionLocal()
    v_after_del = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
    assert v_after_del.treatment_status == "Open"
    assert "exclusão do Plano de Ação" in v_after_del.treatment_notes
    assert plan_title in v_after_del.treatment_notes
    assert str(plan_id) in v_after_del.treatment_notes

    # Check VulnerabilityTreatmentHistory
    history = db.query(models.VulnerabilityTreatmentHistory).filter(
        models.VulnerabilityTreatmentHistory.vulnerability_id == v_id
    ).order_by(models.VulnerabilityTreatmentHistory.id.desc()).first()

    assert history is not None
    assert history.treatment_status == "Open"
    assert "exclusão do Plano de Ação" in history.treatment_notes
    assert plan_title in history.treatment_notes
    assert str(plan_id) in history.treatment_notes
    assert history.changed_by_username == "Admin"

    # Cleanup test host and vuln
    db.query(models.VulnerabilityTreatmentHistory).filter(models.VulnerabilityTreatmentHistory.vulnerability_id == v_id).delete()
    db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).delete()
    db.query(models.Host).filter(models.Host.id == h_id).delete()
    db.commit()
    db.close()


def test_action_plan_wizard_endpoints_and_hosts_without_plugin():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test wizard hosts endpoint
    res_hosts = client.get("/api/action-plans/wizard/hosts", headers=headers)
    assert res_hosts.status_code == 200
    hosts_data = res_hosts.json()
    assert isinstance(hosts_data, list)
    assert len(hosts_data) > 0
    first_h = hosts_data[0]
    assert "ip" in first_h
    assert "vuln_count" in first_h
    assert "critical_count" in first_h

    # 2. Test wizard vulnerabilities endpoint
    res_vulns = client.get(f"/api/action-plans/wizard/vulnerabilities?host_ips={first_h['ip']}", headers=headers)
    assert res_vulns.status_code == 200
    vulns_data = res_vulns.json()
    assert isinstance(vulns_data, list)
    assert len(vulns_data) > 0
    first_v = vulns_data[0]
    assert "plugin_id" in first_v
    assert "plugin_name" in first_v
    assert "affected_hosts_count" in first_v

    # 3. Test creating a plan with host(s) but no plugin specified (all vulns of the host enter the plan)
    plan_payload = {
        "title": f"Plano Wizard Todos os Itens {first_h['ip']}",
        "scope_type": "MATRIX_NN",
        "scope_host_ips": [first_h["ip"]],
        "scope_plugin_ids": [],
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }
    res_create = client.post("/api/action-plans", json=plan_payload, headers=headers)
    assert res_create.status_code == 200
    created = res_create.json()
    assert created["title"] == plan_payload["title"]
    assert len(created["scope_host_ips"]) == 1
    # Check that plugins were automatically populated
    assert len(created["scope_plugin_ids"]) > 0

    # Cleanup
    client.delete(f"/api/action-plans/{created['id']}", headers=headers)


def test_action_plan_wizard_multiple_plugins_selection():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch candidate hosts
    res_hosts = client.get("/api/action-plans/wizard/hosts", headers=headers)
    assert res_hosts.status_code == 200
    hosts_data = res_hosts.json()
    assert len(hosts_data) > 0
    target_host = hosts_data[0]
    target_ip = target_host["ip"]
    group_id = target_host.get("asset_group_id")

    # Fetch candidate vulnerabilities for this host
    res_vulns = client.get(f"/api/action-plans/wizard/vulnerabilities?host_ips={target_ip}", headers=headers)
    assert res_vulns.status_code == 200
    vulns_data = res_vulns.json()
    assert len(vulns_data) >= 1

    selected_plugins = [v["plugin_id"] for v in vulns_data[:2]]

    # 1. Test creating plan with host and multiple plugins
    plan_payload_multi = {
        "title": f"Plano Wizard Multi Plugins {target_ip}",
        "scope_type": "MATRIX_NN",
        "asset_group_id": group_id,
        "scope_host_ips": [target_ip],
        "scope_plugin_ids": selected_plugins,
        "priority": "HIGH",
        "status": "PLANNED",
        "auto_link_vulnerabilities": True
    }
    res_create = client.post("/api/action-plans", json=plan_payload_multi, headers=headers)
    assert res_create.status_code == 200
    created_multi = res_create.json()
    assert set(created_multi["scope_plugin_ids"]) == set(selected_plugins)
    assert created_multi["scope_host_ips"] == [target_ip]

    client.delete(f"/api/action-plans/{created_multi['id']}", headers=headers)

    # 2. Test creating plan with 0 hosts and multiple plugins (auto-resolves hosts from asset group)
    if group_id and len(selected_plugins) > 0:
        plan_payload_auto_hosts = {
            "title": f"Plano Wizard Multi Plugins Auto Hosts Group {group_id}",
            "scope_type": "MATRIX_NN",
            "asset_group_id": group_id,
            "scope_host_ips": [],
            "scope_plugin_ids": selected_plugins,
            "priority": "HIGH",
            "status": "PLANNED",
            "auto_link_vulnerabilities": True
        }
        res_auto = client.post("/api/action-plans", json=plan_payload_auto_hosts, headers=headers)
        assert res_auto.status_code == 200
        created_auto = res_auto.json()
        assert len(created_auto["scope_host_ips"]) > 0
        assert set(created_auto["scope_plugin_ids"]) == set(selected_plugins)

        client.delete(f"/api/action-plans/{created_auto['id']}", headers=headers)





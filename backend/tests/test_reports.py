import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, SessionLocal
from app import models

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    init_db()
    yield

def get_auth_token():
    resp = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert resp.status_code == 200
    return resp.json()["access_token"]

def test_get_report_templates():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/reports/templates", headers=headers)
    assert resp.status_code == 200
    templates = resp.json()
    assert len(templates) >= 3
    assert templates[0]["id"] == "executive_summary"
    assert templates[0]["status"] == "available"
    assert "Relatório Sumário de Gestão de Vulnerabilidades" in templates[0]["name"]
    
    # Check technical report template is now available
    tech_template = next(t for t in templates if t["id"] == "technical_inventory")
    assert tech_template["status"] == "available"
    assert "Relatório Técnico Detalhado" in tech_template["name"]


def test_get_executive_summary_empty():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/reports/summary-data", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "metadata" in data
    assert "inventory" in data
    assert "risk_summary" in data
    assert "severity_distribution" in data
    assert "highlights_top5" in data
    assert "remediation_sla" in data
    assert data["inventory"]["total_discovered_hosts"] >= 0

def test_get_executive_summary_with_scan_and_custom_params():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create asset group
    group_name = f"Grupo Relatorio {uuid.uuid4().hex[:8]}"
    grp_resp = client.post("/api/asset-groups", json={
        "name": group_name,
        "description": "Teste de Relatorio",
        "sla_critical_days": 5,
        "sla_high_days": 10,
        "sla_medium_days": 20,
        "sla_low_days": 40
    }, headers=headers)
    assert grp_resp.status_code == 201
    group_id = grp_resp.json()["id"]

    # Upload CSV scan with multiple OS and severities
    csv_content = (
        "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed\n"
        "100464;CVE-2017-0144;9.3;Critical;SRV-WIN-LEGACY;tcp;445;EternalBlue SMB;SMB vulneravel;Desc;Patch MS17-010;;output;uuid1;Active;10.0.0.10;srv1.corp;SRV1;Windows Server 2008 R2;;Windows;9.3;;;;9.8;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/01 10:30:00;;;;;true;Critical;Critical;Critical;;;remote;1.0;;;;false;true;true;false;false;false;true;false;false;false;true;false;false;\n"
        "156057;CVE-2021-44228;10.0;Critical;APP-LINUX-01;tcp;8080;Apache Log4j RCE;Log4j falha;Desc;Atualizar Log4j;;output;uuid2;Active;10.0.0.20;srv2.corp;SRV2;Ubuntu Linux 22.04 LTS;;CGI abuses;10.0;;;;10.0;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/01 10:30:00;;;;;true;Critical;Critical;Critical;;;remote;1.0;;;;false;true;false;false;false;false;true;false;false;false;true;false;false;\n"
        "136365;CVE-2020-0601;8.1;High;SRV-WIN-2019;tcp;445;CurveBall;CryptoAPI;Desc;Patch Jan 2020;;output;uuid3;Active;10.0.0.30;srv3.corp;SRV3;Windows Server 2019;;Windows;8.1;;;;8.1;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/01 10:30:00;;;;;true;High;High;High;;;remote;1.0;;;;false;false;false;false;false;false;false;false;false;false;true;false;false;\n"
    )

    upload_resp = client.post(
        "/api/scans/upload",
        data={
            "asset_group_id": group_id,
            "scan_name": "Scan Baseline Relatório Teste",
            "scan_type": "baseline",
            "notes": "Teste de emissão executiva"
        },
        files={"file": ("scan_relatorio.csv", csv_content.encode("utf-8"), "text/csv")},
        headers=headers
    )
    assert upload_resp.status_code == 201
    scan_id = upload_resp.json()["id"]

    # Request Executive Summary Report with custom parameters
    report_resp = client.get(
        f"/api/reports/summary-data?asset_group_id={group_id}&scan_id={scan_id}&period=Ciclo+de+Setembro/2026&team=SOC+Enterprise&emission_date=10/09/2026+15:00&title=Relatorio+Auditoria+Geral",
        headers=headers
    )
    assert report_resp.status_code == 200
    report = report_resp.json()

    # 1. Metadados
    meta = report["metadata"]
    assert meta["title"] == "Relatorio Auditoria Geral"
    assert meta["period"] == "Ciclo de Setembro/2026"
    assert meta["team"] == "SOC Enterprise"
    assert meta["emission_date"] == "10/09/2026 15:00"
    assert meta["scope_name"] == group_name
    assert scan_id in meta["scan_ids"]

    # 2. Inventario e SO com EOL
    inv = report["inventory"]
    assert inv["total_discovered_hosts"] == 3
    assert inv["active_hosts"] == 3
    assert inv["eol_count"] >= 1 # Windows Server 2008 R2 is EOL
    assert inv["eol_percentage"] > 0
    assert any(item["is_eol"] for item in inv["os_distribution"])

    # 3. Termometro de Risco
    risk = report["risk_summary"]
    assert risk["organization_risk_score"] > 0
    assert risk["total_occurrences"] == 3
    assert risk["unique_vulnerabilities"] == 3

    # 4. Severidade
    sev = report["severity_distribution"]
    assert sev["critical_count"] == 2
    assert sev["high_count"] == 1
    assert sev["actionable_total"] == 3
    assert sev["exploitable_count"] >= 1

    # 5. Top 5
    highlights = report["highlights_top5"]
    assert len(highlights["top_hosts"]) <= 5
    assert len(highlights["top_hosts"]) == 3
    assert len(highlights["top_vulnerabilities"]) <= 5
    assert len(highlights["top_vulnerabilities"]) == 3
    for tv in highlights["top_vulnerabilities"]:
        assert tv["severity"] in ["Critical", "High"]

    # 6. SLA e Remediacao
    sla = report["remediation_sla"]
    assert sla["overall_mttr_days"] > 0
    assert "Critical" in sla["mttr_by_severity"]
    assert sla["sla_compliance_rate"] >= 0
    assert sla["new_count"] == 3

    # 7. Novos Indicadores Executivos
    assert risk["attack_surface_exposure_pct"] > 0
    assert risk["hosts_with_critical_or_exploits"] >= 1
    assert risk["critical_density"] > 0
    assert len(risk["executive_summary_statement"]) > 20
    assert inv["attack_surface_exposure_pct"] > 0


def test_get_executive_summary_empty_query_strings():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}
    # Passing empty string query params must NOT crash with 422
    resp = client.get("/api/reports/summary-data?asset_group_id=&scan_id=&period=&team=&emission_date=", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["metadata"]["period"] != ""
    assert data["metadata"]["emission_date"] != ""
    assert "executive_summary_statement" in data["risk_summary"]


def test_get_technical_report_empty():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/reports/technical-data", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "metadata" in data
    assert "summary" in data
    assert "hosts" in data
    assert isinstance(data["hosts"], list)


def test_get_technical_report_with_data():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create asset group
    group_name = f"Grupo Dossiê {uuid.uuid4().hex[:8]}"
    grp_resp = client.post("/api/asset-groups", json={
        "name": group_name,
        "description": "Teste de Dossiê Técnico"
    }, headers=headers)
    assert grp_resp.status_code == 201
    group_id = grp_resp.json()["id"]

    # Upload CSV scan with vulnerabilities and hosts
    csv_content = (
        "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed\n"
        "100464;CVE-2017-0144;9.3;Critical;SRV-WIN-01;tcp;445;MS17-010 EternalBlue;SMB vulneravel;Desc;Aplicar patch MS17-010;;output nessus smb;uuid1;Active;192.168.1.100;srv01.corp;SRV01;Windows Server 2016;;Windows;9.3;;;;9.8;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/01 10:30:00;;;;;true;Critical;Critical;Critical;;;remote;1.0;;;;false;true;true;false;false;false;true;false;false;false;true;false;false;\n"
        "156057;CVE-2021-44228;10.0;Critical;SRV-WIN-01;tcp;8080;Apache Log4j RCE;Log4j falha;Desc;Atualizar Log4j;;output log4j;uuid1;Active;192.168.1.100;srv01.corp;SRV01;Windows Server 2016;;Windows;10.0;;;;10.0;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/01 10:30:00;;;;;true;Critical;Critical;Critical;;;remote;1.0;;;;false;true;false;false;false;false;true;false;false;false;true;false;false;\n"
        "51192;;5.0;Medium;SRV-LINUX-02;tcp;22;SSL Certificate Cannot Be Trusted;Certificado autoassinado;Desc;Instalar certificado confiavel;;output ssl;uuid2;Active;192.168.1.200;srv02.corp;SRV02;Ubuntu Linux 22.04 LTS;;Linux;5.0;;;;5.0;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/01 10:30:00;;;;;true;Medium;Medium;Medium;;;remote;1.0;;;;false;false;false;false;false;false;false;false;false;false;true;false;false;\n"
    )

    upload_resp = client.post(
        "/api/scans/upload",
        data={
            "asset_group_id": group_id,
            "scan_name": "Scan Dossiê Técnico Teste",
            "scan_type": "baseline",
            "notes": "Teste de emissão técnica"
        },
        files={"file": ("scan_tech.csv", csv_content.encode("utf-8"), "text/csv")},
        headers=headers
    )
    assert upload_resp.status_code == 201
    scan_id = upload_resp.json()["id"]

    # Request Technical Report
    tech_resp = client.get(
        f"/api/reports/technical-data?asset_group_id={group_id}&scan_id={scan_id}&period=Ciclo+Setembro/2026&team=Infra+Ops&title=Dossie+Tecnico+Teste",
        headers=headers
    )
    assert tech_resp.status_code == 200
    report = tech_resp.json()

    # Verify metadata
    assert report["metadata"]["title"] == "Dossie Tecnico Teste"
    assert report["metadata"]["team"] == "Infra Ops"
    assert report["metadata"]["period"] == "Ciclo Setembro/2026"

    # Verify summary
    summary = report["summary"]
    assert summary["total_hosts"] == 2
    assert summary["total_actionable_vulns"] == 3
    assert summary["critical_count"] == 2
    assert summary["medium_count"] == 1
    assert summary["exploitable_count"] == 2
    assert len(summary["top_ports"]) >= 2

    # Verify hosts dossiers
    hosts = report["hosts"]
    assert len(hosts) == 2

    # First host should have higher risk score (192.168.1.100 has 2 Criticals + exploits)
    h1 = hosts[0]
    assert h1["ip_address"] == "192.168.1.100"
    assert h1["hostname"] == "srv01.corp"
    assert h1["os"] == "Windows Server 2016"
    assert h1["critical_count"] == 2
    assert h1["exploits_count"] == 2
    assert h1["risk_score"] > 0
    assert len(h1["vulnerabilities"]) == 2

    # Verify vulnerability item fields
    v1 = h1["vulnerabilities"][0]
    assert v1["plugin_id"] in ["100464", "156057"]
    assert v1["plugin_name"] != ""
    assert v1["port"] in [445, 8080]
    assert v1["protocol"] == "tcp"
    assert v1["solution"] != ""
    assert v1["exploit_available"] is True
    assert len(v1["cve_list"]) >= 1

    # Second host
    h2 = hosts[1]
    assert h2["ip_address"] == "192.168.1.200"
    assert h2["medium_count"] == 1
    assert h2["critical_count"] == 0
    assert len(h2["vulnerabilities"]) == 1


def test_sla_audit_report_template_and_empty():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Verify template is available
    resp = client.get("/api/reports/templates", headers=headers)
    assert resp.status_code == 200
    templates = resp.json()
    sla_tpl = next(t for t in templates if t["id"] == "sla_audit")
    assert sla_tpl["status"] == "available"
    assert "Auditoria" in sla_tpl["name"]
    assert "Auditoria & ISO" in sla_tpl["badge"]

    # Verify endpoint works on empty/default scope
    resp_sla = client.get("/api/reports/sla-audit-data", headers=headers)
    assert resp_sla.status_code == 200
    data = resp_sla.json()
    assert "metadata" in data
    assert "sla_adherence" in data
    assert "iso9001_pdca" in data
    assert "accepted_risks_trail" in data
    assert "auditor_statement" in data
    assert len(data["sla_adherence"]["aging_matrix"]) == 4


def test_sla_audit_report_full_with_aging_pdca_and_accepted_risks():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create dedicated asset group with specific SLAs
    grp_resp = client.post("/api/asset-groups", json={
        "name": f"Grupo SLA ISO {uuid.uuid4().hex[:8]}",
        "description": "Grupo para auditoria ISO 27001",
        "sla_critical_days": 7,
        "sla_high_days": 15,
        "sla_medium_days": 30,
        "sla_low_days": 60
    }, headers=headers)
    assert grp_resp.status_code == 201
    group_id = grp_resp.json()["id"]

    # Baseline scan with 3 vulnerabilities
    csv_baseline = (
        "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed\n"
        "100464;CVE-2017-0144;9.3;Critical;SRV-WIN-01;tcp;445;EternalBlue SMB;SMB vuln;Desc;Patch MS17-010;;out;u1;Active;192.168.10.5;srv1.lan;SRV1;Windows 2016;;Windows;9.3;;;;9.8;;;;general-purpose;;;;2026/08/01 10:00:00;2026/08/01 10:30:00;;;;;true;Critical;Critical;Critical;;;remote;1.0;;;;false;true;true;false;false;false;true;false;false;false;true;false;false;\n"
        "156057;CVE-2021-44228;10.0;Critical;SRV-APP-01;tcp;8080;Apache Log4j RCE;Log4j vuln;Desc;Atualizar Log4j;;out;u2;Active;192.168.10.15;app1.lan;APP1;Linux;;CGI abuses;10.0;;;;10.0;;;;general-purpose;;;;2026/08/15 10:00:00;2026/08/15 10:30:00;;;;;true;Critical;Critical;Critical;;;remote;1.0;;;;false;true;false;false;false;false;true;false;false;false;true;false;false;\n"
        "136365;CVE-2020-0601;8.1;High;SRV-WIN-01;tcp;445;CurveBall;CryptoAPI;Desc;Patch Jan 2020;;out;u3;Active;192.168.10.5;srv1.lan;SRV1;Windows 2016;;Windows;8.1;;;;8.1;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/01 10:30:00;;;;;true;High;High;High;;;remote;1.0;;;;false;false;false;false;false;false;false;false;false;false;true;false;false;\n"
    )

    up1 = client.post(
        "/api/scans/upload",
        data={
            "asset_group_id": group_id,
            "scan_name": "Scan Baseline Auditoria SLA",
            "scan_type": "baseline",
            "notes": "Baseline inicial"
        },
        files={"file": ("baseline.csv", csv_baseline.encode("utf-8"), "text/csv")},
        headers=headers
    )
    assert up1.status_code == 201
    scan1_id = up1.json()["id"]

    # Retrieve one vulnerability and mark as Accepted_Risk with justification notes
    db = SessionLocal()
    vuln_accepted = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id == scan1_id,
        models.Vulnerability.plugin_id == "100464"
    ).first()
    assert vuln_accepted is not None
    vuln_accepted.treatment_status = "Accepted_Risk"
    vuln_accepted.treated_by_username = "auditor_master"
    vuln_accepted.treated_at = models.utc_now()
    vuln_accepted.treatment_notes = "Risco residual aceito formalmente pelo CISO via RDM-2026-8812 devido à desativação programada do host."
    
    # Mark second vulnerability as Remediated
    vuln_rem = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id == scan1_id,
        models.Vulnerability.plugin_id == "156057"
    ).first()
    if vuln_rem:
        vuln_rem.treatment_status = "Remediated"
        vuln_rem.treated_by_username = "analista_sec"
        vuln_rem.treated_at = models.utc_now()
        vuln_rem.treatment_notes = "Log4j atualizado para v2.17.1 em ambiente produtivo."

    db.commit()
    db.close()

    # Upload Retest scan (eliminates Log4j, persisting EternalBlue and CurveBall)
    csv_retest = (
        "Plugin ID;CVE;CVSS;Risk;Host;Protocol;Port;Name;Synopsis;Description;Solution;See Also;Plugin Output;Asset UUID;Vulnerability State;IP Address;FQDN;NetBios;OS;MAC Address;Plugin Family;CVSS Base Score;CVSS Temporal Score;CVSS Temporal Vector;CVSS Vector;CVSS3 Base Score;CVSS3 Temporal Score;CVSS3 Temporal Vector;CVSS3 Vector;System Type;Host Start;Host End;Vulnerability Priority Rating (VPR);First Found;Last Found;Host Scan Schedule ID;Host Scan ID;Indexed At;Last Authenticated Results Date;Last Unauthenticated Results Date;Tracked;Risk Factor;Severity;Original Severity;Modification;Plugin Family ID;Plugin Type;Plugin Version;Service;Plugin Modification Date;Plugin Publication Date;Checks for Malware;Exploit Available;Exploited by Malware;Exploited by Nessus;CANVAS;D2 Elliot;Metasploit;Core Exploits;ExploitHub;Default Account;Patch Available;In The News;Unsupported By Vendor;Last Fixed\n"
        "100464;CVE-2017-0144;9.3;Critical;SRV-WIN-01;tcp;445;EternalBlue SMB;SMB vuln;Desc;Patch MS17-010;;out;u1;Active;192.168.10.5;srv1.lan;SRV1;Windows 2016;;Windows;9.3;;;;9.8;;;;general-purpose;;;;2026/08/01 10:00:00;2026/09/10 10:30:00;;;;;true;Critical;Critical;Critical;;;remote;1.0;;;;false;true;true;false;false;false;true;false;false;false;true;false;false;\n"
        "136365;CVE-2020-0601;8.1;High;SRV-WIN-01;tcp;445;CurveBall;CryptoAPI;Desc;Patch Jan 2020;;out;u3;Active;192.168.10.5;srv1.lan;SRV1;Windows 2016;;Windows;8.1;;;;8.1;;;;general-purpose;;;;2026/09/01 10:00:00;2026/09/10 10:30:00;;;;;true;High;High;High;;;remote;1.0;;;;false;false;false;false;false;false;false;false;false;false;true;false;false;\n"
    )

    up2 = client.post(
        "/api/scans/upload",
        data={
            "asset_group_id": group_id,
            "scan_name": "Scan Reteste Auditoria SLA",
            "scan_type": "retest",
            "notes": "Reteste com mitigação de Log4j"
        },
        files={"file": ("retest.csv", csv_retest.encode("utf-8"), "text/csv")},
        headers=headers
    )
    assert up2.status_code == 201
    scan2_id = up2.json()["id"]

    # Mark the accepted risk in the retest scan as well so it is audited in the latest scan
    db = SessionLocal()
    vuln_retest_acc = db.query(models.Vulnerability).filter(
        models.Vulnerability.scan_id == scan2_id,
        models.Vulnerability.plugin_id == "100464"
    ).first()
    if vuln_retest_acc:
        vuln_retest_acc.treatment_status = "Accepted_Risk"
        vuln_retest_acc.treated_by_username = "auditor_master"
        vuln_retest_acc.treated_at = models.utc_now()
        vuln_retest_acc.treatment_notes = "Risco residual aceito formalmente pelo CISO via RDM-2026-8812."
        db.commit()
    db.close()

    # Query SLA Audit Report for this asset group
    res_audit = client.get(
        f"/api/reports/sla-audit-data?asset_group_id={group_id}&title=Auditoria+Formal+ISO+27001",
        headers=headers
    )
    assert res_audit.status_code == 200
    report = res_audit.json()

    # 1. Metadados
    assert report["metadata"]["title"] == "Auditoria Formal ISO 27001"
    assert report["metadata"]["scope_group_id"] == group_id

    # 2. Seção 1: SLA Adherence & Aging Matrix
    sla_sec = report["sla_adherence"]
    assert sla_sec["total_actionable"] >= 2
    assert len(sla_sec["aging_matrix"]) == 4
    ranges = [b["range_label"] for b in sla_sec["aging_matrix"]]
    assert "0-30 dias" in ranges
    assert "31-60 dias" in ranges
    assert "> 90 dias (Passivos Críticos)" in ranges
    assert len(sla_sec["severity_compliance"]) == 4

    # 3. Seção 2: ISO 9001 PDCA Metrics
    pdca_sec = report["iso9001_pdca"]
    assert pdca_sec["has_retest_data"] is True
    assert pdca_sec["resolution_rate_percent"] is not None
    assert pdca_sec["resolution_rate_percent"] > 0 # Log4j was remediated in retest!
    assert pdca_sec["net_risk_reduction_percent"] is not None
    assert pdca_sec["net_risk_reduction_percent"] > 0 # Risk was reduced!

    # 4. Seção 3: Trilha de Auditoria e Riscos Aceitos ("Quem, Quando e Por Quê")
    acc_sec = report["accepted_risks_trail"]
    assert acc_sec["total_accepted_risks"] >= 1
    item = next(i for i in acc_sec["items"] if i["plugin_id"] == "100464")
    assert item["treated_by_username"] == "auditor_master" # Quem
    assert "UTC" in item["treated_at_formatted"] # Quando
    assert "RDM-2026-8812" in item["treatment_notes"] # Por Quê
    assert item["severity"] == "Critical"

    # 5. Seção 4: Parecer Formal do Auditor
    auditor_sec = report["auditor_statement"]
    assert auditor_sec["iso27001_control_8_8_status"] != ""
    assert auditor_sec["iso9001_pdca_status"] != ""
    assert len(auditor_sec["auditor_recommendations"]) >= 3
    assert auditor_sec["signed_role"] == "Auditor Sênior de Segurança da Informação & Qualidade"




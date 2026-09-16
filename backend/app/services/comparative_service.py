from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app import models, schemas
from app.services.parameter_service import apply_indicator_exclusion

ACTIONABLE_SEVERITIES = ["Critical", "High", "Medium", "Low"]

def compare_scans(db: Session, baseline_scan_id: int, retest_scan_id: int) -> schemas.ComparativeReport:
    """
    Compares baseline scan (Before) and retest scan (After) for vulnerability treatment tracking (ISO 9001 PDCA).
    Excludes informational/none findings so only actionable vulnerabilities (Critical, High, Medium, Low)
    are counted and displayed in the comparative report.
    """
    baseline_scan = db.query(models.Scan).filter(models.Scan.id == baseline_scan_id).first()
    retest_scan = db.query(models.Scan).filter(models.Scan.id == retest_scan_id).first()

    if not baseline_scan or not retest_scan:
        raise ValueError("Um ou ambos os scans informados não foram encontrados.")

    asset_group = db.query(models.AssetGroup).filter(models.AssetGroup.id == baseline_scan.asset_group_id).first()
    asset_group_name = asset_group.name if asset_group else "Grupo Desconhecido"

    # Query only actionable vulnerabilities for baseline scan (Critical, High, Medium, Low)
    baseline_query = db.query(models.Vulnerability, models.Host.ip_address, models.Host.hostname)\
        .join(models.Host, models.Vulnerability.host_id == models.Host.id)\
        .filter(
            models.Vulnerability.scan_id == baseline_scan_id,
            models.Vulnerability.severity.in_(ACTIONABLE_SEVERITIES)
        )
    baseline_vulns = apply_indicator_exclusion(baseline_query, db).all()

    # Query only actionable vulnerabilities for retest scan (Critical, High, Medium, Low)
    retest_query = db.query(models.Vulnerability, models.Host.ip_address, models.Host.hostname)\
        .join(models.Host, models.Vulnerability.host_id == models.Host.id)\
        .filter(
            models.Vulnerability.scan_id == retest_scan_id,
            models.Vulnerability.severity.in_(ACTIONABLE_SEVERITIES)
        )
    retest_vulns = apply_indicator_exclusion(retest_query, db).all()

    # Build lookup dictionaries by signature: (host_ip, plugin_id, port, protocol)
    baseline_map: Dict[tuple, Any] = {}
    for v, host_ip, host_name in baseline_vulns:
        sig = (host_ip, v.plugin_id, v.port, v.protocol)
        baseline_map[sig] = (v, host_ip, host_name)

    retest_map: Dict[tuple, Any] = {}
    for v, host_ip, host_name in retest_vulns:
        sig = (host_ip, v.plugin_id, v.port, v.protocol)
        retest_map[sig] = (v, host_ip, host_name)

    remediated_items: List[schemas.DiffItem] = []
    persisting_items: List[schemas.DiffItem] = []
    new_items: List[schemas.DiffItem] = []

    # 1. Check Baseline items against Retest
    import re
    cve_regex = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    for sig, (v, host_ip, host_name) in baseline_map.items():
        cves = [c.strip() for c in cve_regex.findall(v.cve or "")] if v.cve else []
        if sig in retest_map:
            # Still present in retest -> Persisting
            persisting_items.append(schemas.DiffItem(
                plugin_id=v.plugin_id,
                plugin_name=v.plugin_name,
                cve=v.cve,
                cve_list=cves,
                cve_count=len(cves),
                severity=v.severity,
                cvss_v3=v.cvss_v3,
                host_ip=host_ip,
                host_name=host_name,
                port=v.port,
                protocol=v.protocol,
                status="PERSISTING",
                exploit_available=v.exploit_available,
                solution=v.solution
            ))
        else:
            # Present in baseline, absent in retest -> Remediated (Fixed)
            remediated_items.append(schemas.DiffItem(
                plugin_id=v.plugin_id,
                plugin_name=v.plugin_name,
                cve=v.cve,
                cve_list=cves,
                cve_count=len(cves),
                severity=v.severity,
                cvss_v3=v.cvss_v3,
                host_ip=host_ip,
                host_name=host_name,
                port=v.port,
                protocol=v.protocol,
                status="REMEDIATED",
                exploit_available=v.exploit_available,
                solution=v.solution
            ))

    # 2. Check Retest items for New findings (Regressions)
    for sig, (v, host_ip, host_name) in retest_map.items():
        if sig not in baseline_map:
            cves = [c.strip() for c in cve_regex.findall(v.cve or "")] if v.cve else []
            new_items.append(schemas.DiffItem(
                plugin_id=v.plugin_id,
                plugin_name=v.plugin_name,
                cve=v.cve,
                cve_list=cves,
                cve_count=len(cves),
                severity=v.severity,
                cvss_v3=v.cvss_v3,
                host_ip=host_ip,
                host_name=host_name,
                port=v.port,
                protocol=v.protocol,
                status="NEW",
                exploit_available=v.exploit_available,
                solution=v.solution
            ))

    total_before = len(baseline_vulns)
    total_after = len(retest_vulns)
    remediated_count = len(remediated_items)
    persisting_count = len(persisting_items)
    new_count = len(new_items)

    remediation_rate = round((remediated_count / total_before * 100.0), 1) if total_before > 0 else 0.0

    # Risk calculation before and after
    def calc_risk(scan: models.Scan) -> float:
        return (scan.critical_count * 10.0) + (scan.high_count * 5.0) + (scan.medium_count * 2.0) + (scan.low_count * 0.5)

    risk_before = calc_risk(baseline_scan)
    risk_after = calc_risk(retest_scan)
    risk_reduction = round(((risk_before - risk_after) / risk_before * 100.0), 1) if risk_before > 0 else 0.0

    return schemas.ComparativeReport(
        asset_group_id=baseline_scan.asset_group_id,
        asset_group_name=asset_group_name,
        baseline_scan=schemas.ScanOut.model_validate(baseline_scan),
        retest_scan=schemas.ScanOut.model_validate(retest_scan),
        remediation_rate_percent=remediation_rate,
        risk_reduction_percent=risk_reduction,
        total_before=total_before,
        total_after=total_after,
        remediated_count=remediated_count,
        persisting_count=persisting_count,
        new_count=new_count,
        severity_before={
            "Critical": baseline_scan.critical_count,
            "High": baseline_scan.high_count,
            "Medium": baseline_scan.medium_count,
            "Low": baseline_scan.low_count,
            "Info": 0
        },
        severity_after={
            "Critical": retest_scan.critical_count,
            "High": retest_scan.high_count,
            "Medium": retest_scan.medium_count,
            "Low": retest_scan.low_count,
            "Info": 0
        },
        critical_before=baseline_scan.critical_count,
        critical_after=retest_scan.critical_count,
        exploitable_before=baseline_scan.exploitable_critical_count,
        exploitable_after=retest_scan.exploitable_critical_count,
        remediated_items=remediated_items,
        persisting_items=persisting_items,
        new_items=new_items
    )

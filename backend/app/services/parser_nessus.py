import csv
import io
import re
import sys
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# Increase CSV field size limit to handle enterprise scans with large outputs (e.g. 100MB)
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2147483647)

def normalize_header(header: str) -> str:
    """Normalizes header string for robust matching."""
    if not header:
        return ""
    cleaned = header.strip().lower().replace("_", " ").replace("-", " ")
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned

HEADER_MAP = {
    "plugin_id": ["plugin id", "pluginid", "plugin", "id"],
    "cve": ["cve", "cve id", "cves"],
    "cvss_v3": ["cvss3 base score", "cvss v3.0 base score", "cvss v3 base score", "cvss v3.0", "cvss v3", "cvss3", "cvss v3 score"],
    "cvss_v2": ["cvss base score", "cvss v2.0 base score", "cvss v2 base score", "cvss v2.0", "cvss v2", "cvss2", "cvss v2 score", "cvss"],
    "severity": ["risk", "severity", "risk factor", "original severity", "criticidade"],
    "ip_address": ["ip address", "ip", "host ip"],
    "host": ["host", "target"],
    "fqdn": ["fqdn", "dns name"],
    "netbios": ["netbios", "netbios name", "computer name"],
    "hostname": ["hostname", "fqdn", "dns name", "netbios", "netbios name"],
    "os": ["os", "operating system", "system type"],
    "mac_address": ["mac address", "mac"],
    "protocol": ["protocol", "proto"],
    "port": ["port", "porta"],
    "name": ["name", "plugin name", "vulnerability", "title", "nome"],
    "synopsis": ["synopsis", "sinopse", "resumo"],
    "description": ["description", "descricao", "descrição", "vuln description"],
    "solution": ["solution", "solucao", "solução", "remediation", "fix"],
    "see_also": ["see also", "referencias", "references"],
    "plugin_output": ["plugin output", "output", "resultado"],
    "vulnerability_state": ["vulnerability state", "state"],
    "vpr": ["vulnerability priority rating (vpr)", "vpr", "vpr score"],
    "plugin_family": ["plugin family", "family"],
    "patch_available": ["patch available", "patch"],
    "exploit_available": ["exploit available", "exploit?", "exploit", "exploravel?", "explorável"],
    "exploit_frameworks": ["exploit frameworks", "exploited with", "frameworks", "exploit framework"],
    "metasploit": ["metasploit", "metasploit framework"],
    "canvas": ["canvas"],
    "core_exploits": ["core exploits", "core impact"],
    "d2_elliot": ["d2 elliot", "elliot"],
    "exploithub": ["exploithub"],
    "exploited_by_malware": ["exploited by malware"],
    "exploited_by_nessus": ["exploited by nessus"],
    "first_found": ["first found", "first_found", "first seen", "data primeira detecção", "data de detecção", "primeira detecção", "first_seen", "descoberta em", "data da descoberta", "data descoberta", "primeira visualização", "data da primeira visualização"],
    "last_found": ["last found", "last_found", "last seen", "data última detecção", "última detecção", "last_seen", "ultima detecção", "última visualização", "data da última visualização"],
    "plugin_type": ["plugin type", "type", "tipo de plugin", "plugin_type"]
}

def parse_date_safe(value: Any) -> Optional[datetime]:
    if not value:
        return None
    val_str = str(value).strip()
    if not val_str or val_str.lower() in ["n/a", "none", "null", "-", ""]:
        return None
    
    # Remove milissegundos e sufixos de fuso horário ISO: ex: 2025-08-14T18:01:16.096Z -> 2025-08-14 18:01:16
    clean_str = re.sub(r'\.\d+.*$', '', val_str)
    clean_str = clean_str.replace('T', ' ').replace('Z', '').strip()

    formats = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
        "%d-%m-%Y",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y/%m/%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y",
        "%m-%d-%Y %H:%M:%S",
        "%m-%d-%Y %H:%M",
        "%m-%d-%Y",
        "%b %d, %Y",
        "%b %d %Y",
        "%B %d, %Y"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(clean_str[:19].strip(), fmt)
        except Exception:
            pass
    return None

def map_headers(fieldnames: List[str]) -> Dict[str, str]:
    """Finds best matching CSV header for each canonical field."""
    mapping = {}
    normalized_fields = {normalize_header(h): h for h in fieldnames if h}

    for canonical, aliases in HEADER_MAP.items():
        found = False
        for alias in aliases:
            for norm_h, original_h in normalized_fields.items():
                if alias == norm_h or norm_h.startswith(alias):
                    mapping[canonical] = original_h
                    found = True
                    break
            if found:
                break
    return mapping

def normalize_severity(raw_severity: str) -> str:
    """Standardizes severity to Critical, High, Medium, Low, or Info."""
    if not raw_severity:
        return "Info"
    val = raw_severity.strip().lower()
    if "crit" in val:
        return "Critical"
    if "high" in val or "alto" in val or "alta" in val:
        return "High"
    if "med" in val or "medio" in val or "média" in val:
        return "Medium"
    if "low" in val or "baixo" in val or "baixa" in val:
        return "Low"
    if "none" in val or "info" in val:
        return "Info"
    return "Info"

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def extract_cves(raw_val: Any) -> List[str]:
    """Extracts all unique CVE identifiers from a field or text preserving order."""
    if not raw_val:
        return []
    s = str(raw_val).strip()
    if not s or s.lower() in ["none", "n/a", "null", "-", ""]:
        return []
    found = CVE_REGEX.findall(s)
    if found:
        seen = set()
        cves = []
        for c in found:
            cu = c.upper().strip()
            if cu not in seen:
                seen.add(cu)
                cves.append(cu)
        return cves
    tokens = re.split(r"[\s,;\n\r]+", s)
    seen = set()
    cves = []
    for t in tokens:
        tu = t.strip().upper()
        if tu.startswith("CVE-") and tu not in seen:
            seen.add(tu)
            cves.append(tu)
    return cves

SEVERITY_RANK = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1
}

def parse_float_safe(value: Any) -> float:
    if not value:
        return 0.0
    try:
        val_str = str(value).strip().replace(",", ".")
        clean_val = re.findall(r"[-+]?(?:\d*\.\d+|\d+)", val_str)
        return float(clean_val[0]) if clean_val else 0.0
    except Exception:
        return 0.0

def parse_cvss_score(value: Any) -> float:
    """
    Parses CVSS scores safely supporting:
    - Decimal floats with dot or comma: '7.5', '7,5', '9.8', '10.0'
    - Scaled integers: '75' (converts to 7.5), '98' (converts to 9.8), '100' (converts to 10.0), '50' (converts to 5.0)
    - Empty or non-numeric values -> 0.0
    """
    if not value:
        return 0.0
    val_str = str(value).strip().replace(",", ".")
    clean_val = re.findall(r"[-+]?(?:\d*\.\d+|\d+)", val_str)
    if not clean_val:
        return 0.0
    try:
        score = float(clean_val[0])
        # If integer scale (e.g. 75 represents 7.5, 98 represents 9.8, 100 represents 10.0)
        if 10.0 < score <= 100.0:
            score = round(score / 10.0, 1)
        elif score > 100.0:
            score = round(score / 100.0, 1)
        return min(10.0, max(0.0, score))
    except Exception:
        return 0.0

def parse_int_safe(value: Any) -> int:
    if not value:
        return 0
    try:
        val_str = str(value).strip().replace(",", ".")
        clean_val = re.findall(r"[-+]?(?:\d*\.\d+|\d+)", val_str)
        if clean_val:
            return int(round(float(clean_val[0])))
        return 0
    except Exception:
        return 0

def is_truthy(val: Any) -> bool:
    if not val:
        return False
    clean = str(val).strip().lower()
    return clean in ["true", "yes", "1", "y", "sim", "s", "verdadeiro", "verdadeira", "v", "positive", "t"]

def is_falsy(val: Any) -> bool:
    if not val:
        return True
    clean = str(val).strip().lower()
    return clean in ["false", "no", "0", "n", "nao", "não", "falso", "falsa", "f", "none", "null", ""]

def parse_exploit_info(row: Dict[str, Any], header_map: Dict[str, str]) -> Tuple[bool, str]:
    """Evaluates global exploit status and aggregates specific exploit frameworks."""
    frameworks = []
    exploit_bool = False

    gen_exp_col = header_map.get("exploit_available")
    if gen_exp_col:
        raw_val = row.get(gen_exp_col)
        if is_truthy(raw_val):
            exploit_bool = True
        elif is_falsy(raw_val):
            exploit_bool = False

    gen_f_col = header_map.get("exploit_frameworks")
    if gen_f_col:
        raw_f = str(row.get(gen_f_col, "")).strip()
        if raw_f and raw_f.lower() not in ["none", "no", "null", "false", "", "n/a"]:
            frameworks.append(raw_f)
            exploit_bool = True

    framework_keys = [
        ("metasploit", "Metasploit"),
        ("canvas", "CANVAS"),
        ("core_exploits", "Core Exploits"),
        ("d2_elliot", "D2 Elliot"),
        ("exploithub", "ExploitHub"),
        ("exploited_by_malware", "Malware"),
        ("exploited_by_nessus", "Nessus")
    ]

    for key, label in framework_keys:
        col = header_map.get(key)
        if col and is_truthy(row.get(col)):
            exploit_bool = True
            if label not in frameworks:
                frameworks.append(label)

    return exploit_bool, ", ".join(frameworks)

def detect_delimiter(first_line: str) -> str:
    """Detects delimiter from header row with priority on semicolon, comma, and tab."""
    if ";" in first_line:
        return ";"
    if "\t" in first_line:
        return "\t"
    if "," in first_line:
        return ","
    if "|" in first_line:
        return "|"
    return ";"

def stitch_and_read_csv(clean_content: str, delimiter: str):
    """
    Reconstructs Nessus CSV rows where raw unquoted newlines occur inside
    fields like Plugin Output or Synopsis, and parses safely.
    """
    raw_lines = clean_content.splitlines()
    if not raw_lines:
        return [], []

    header_line = raw_lines[0]
    
    # Check header
    header_reader = csv.reader([header_line], delimiter=delimiter)
    header_row = next(header_reader, None)
    if not header_row:
        return [], []
    
    fieldnames = [h.strip() for h in header_row]
    header_len = len(fieldnames)

    # Regex: every valid Nessus data row begins with a numeric plugin ID
    record_start_pattern = re.compile(r'^\s*"?\d+"?\s*' + re.escape(delimiter))

    stitched_lines = [header_line]
    for line in raw_lines[1:]:
        if not line.strip():
            continue
        if record_start_pattern.match(line):
            stitched_lines.append(line)
        else:
            # Continuation of previous unquoted multiline field
            if len(stitched_lines) > 1:
                stitched_lines[-1] += " " + line.strip()
            else:
                stitched_lines.append(line)

    reconstructed_content = "\n".join(stitched_lines)
    stream = io.StringIO(reconstructed_content, newline="")
    reader = csv.reader(stream, delimiter=delimiter)
    
    # Skip header
    next(reader, None)

    rows = []
    for row in reader:
        if not row or not any(row):
            continue
        if len(row) < header_len:
            row = row + [""] * (header_len - len(row))
        elif len(row) > header_len:
            row = row[:header_len]
        rows.append(dict(zip(fieldnames, row)))

    return fieldnames, rows

def parse_nessus_csv(content: str) -> Dict[str, Any]:
    """
    Parses Nessus / Tenable CSV content of any size (including large 40MB+ exports),
    semicolon/comma delimiters, and multi-line unquoted fields without crashing.
    """
    if not content or not content.strip():
        raise ValueError("O arquivo CSV está vazio.")

    # 1. Strip null bytes and BOM
    clean_content = content.replace("\x00", "").lstrip("\ufeff")
    
    first_line = clean_content.splitlines()[0] if clean_content.splitlines() else clean_content
    delimiter = detect_delimiter(first_line)

    fieldnames, rows = stitch_and_read_csv(clean_content, delimiter)
    
    if not fieldnames:
        raise ValueError("O arquivo CSV não possui cabeçalhos válidos.")

    header_map = map_headers(fieldnames)
    
    if ("host" not in header_map and "ip_address" not in header_map) and \
       ("name" not in header_map and "plugin_id" not in header_map):
        raise ValueError("Formato CSV incompatível. Certifique-se que as colunas 'Plugin ID', 'Name' e 'Host' ou 'IP Address' estão presentes.")

    hosts_dict: Dict[str, Dict[str, Any]] = {}
    findings_dict: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}

    stats = {
        "total_rows": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "exploitable_critical_count": 0
    }

    for row in rows:
        stats["total_rows"] += 1
        
        # 1. Resolve Host IP & Hostname
        ip_col = header_map.get("ip_address")
        host_col = header_map.get("host")
        raw_ip = (row.get(ip_col, "") if ip_col else "").strip()
        raw_host = (row.get(host_col, "") if host_col else "").strip()

        host_key = raw_ip if raw_ip else (raw_host if raw_host else "127.0.0.1")

        fqdn_col = header_map.get("fqdn")
        netbios_col = header_map.get("netbios")
        hostname_col = header_map.get("hostname")

        hostname = ""
        if fqdn_col and row.get(fqdn_col):
            hostname = str(row.get(fqdn_col, "")).strip()
        elif netbios_col and row.get(netbios_col):
            hostname = str(row.get(netbios_col, "")).strip()
        elif hostname_col and row.get(hostname_col):
            hostname = str(row.get(hostname_col, "")).strip()
        elif raw_host and raw_host != host_key:
            hostname = raw_host

        os_col = header_map.get("os")
        os_value = str(row.get(os_col, "")).strip() if os_col else ""

        mac_col = header_map.get("mac_address")
        mac_address = str(row.get(mac_col, "")).strip() if mac_col else ""

        # 2. Extract Plugin ID & Name
        p_id_col = header_map.get("plugin_id")
        plugin_id = str(row.get(p_id_col, "")).strip() if p_id_col else ""
        
        name_col = header_map.get("name")
        plugin_name = str(row.get(name_col, "")).strip() if name_col else ""
        if not plugin_name and plugin_id:
            plugin_name = f"Plugin ID {plugin_id}"
        elif not plugin_name and not plugin_id:
            continue
        if not plugin_id:
            plugin_id = str(abs(hash(plugin_name)) % 1000000)

        # 3. Port & Protocol
        port_col = header_map.get("port")
        port = parse_int_safe(row.get(port_col, 0) if port_col else 0)
        
        proto_col = header_map.get("protocol")
        protocol = (str(row.get(proto_col, "tcp") if proto_col else "tcp")).strip().lower() or "tcp"

        # 4. Severity & Risk
        sev_col = header_map.get("severity")
        severity = normalize_severity(str(row.get(sev_col, "")) if sev_col else "")

        # 5. CVSS Scores
        cvss3_col = header_map.get("cvss_v3")
        cvss_v3 = parse_cvss_score(row.get(cvss3_col)) if cvss3_col else None
        
        cvss2_col = header_map.get("cvss_v2")
        cvss_v2 = parse_cvss_score(row.get(cvss2_col)) if cvss2_col else None

        if (cvss_v3 is None or cvss_v3 == 0.0) and cvss_v2:
            cvss_v3 = cvss_v2
        if (cvss_v3 is None or cvss_v3 == 0.0):
            if severity == "Critical": cvss_v3 = 9.8
            elif severity == "High": cvss_v3 = 7.5
            elif severity == "Medium": cvss_v3 = 5.0
            elif severity == "Low": cvss_v3 = 2.5
            else: cvss_v3 = 0.0

        # 6. CVE Extraction (supports multiple CVEs per cell or references)
        cve_col = header_map.get("cve")
        cve_raw = str(row.get(cve_col, "")).strip() if cve_col else ""
        cves_from_row = extract_cves(cve_raw)

        # 7. Exploit status & Frameworks
        exploit_available, exploit_frameworks = parse_exploit_info(row, header_map)
        exploit_frameworks_set = set([f.strip() for f in exploit_frameworks.split(",") if f.strip()]) if exploit_frameworks else set()

        # 8. Detailed Descriptive Fields
        synopsis_col = header_map.get("synopsis")
        synopsis = str(row.get(synopsis_col, "")).strip() if synopsis_col else ""

        desc_col = header_map.get("description")
        description = str(row.get(desc_col, "")).strip() if desc_col else ""

        sol_col = header_map.get("solution")
        solution = str(row.get(sol_col, "")).strip() if sol_col else ""

        see_col = header_map.get("see_also")
        see_also = str(row.get(see_col, "")).strip() if see_col else ""

        out_col = header_map.get("plugin_output")
        plugin_output = str(row.get(out_col, "")).strip() if out_col else ""

        # Fallback CVE search in see_also / synopsis if cve column didn't have any
        if not cves_from_row:
            cves_from_row = extract_cves(see_also)
        if not cves_from_row:
            cves_from_row = extract_cves(synopsis)

        # Initialize Host in aggregated map if not present
        if host_key not in hosts_dict:
            hosts_dict[host_key] = {
                "ip_address": host_key,
                "hostname": hostname,
                "mac_address": mac_address,
                "os": os_value,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "exploitable_critical_count": 0,
                "risk_score": 0.0
            }
        
        # Update metadata if newly found
        if not hosts_dict[host_key]["hostname"] and hostname:
            hosts_dict[host_key]["hostname"] = hostname
        if not hosts_dict[host_key]["mac_address"] and mac_address:
            hosts_dict[host_key]["mac_address"] = mac_address
        if not hosts_dict[host_key]["os"] and os_value:
            hosts_dict[host_key]["os"] = os_value

        # Detect OS from plugin 11936 if not provided in column
        if not hosts_dict[host_key]["os"] and plugin_id in ["11936", "10287", "45590"] and (plugin_output or synopsis):
            os_detected = plugin_output.split("\n")[0] if plugin_output else synopsis
            hosts_dict[host_key]["os"] = os_detected[:190]

        # 9. Detection timestamps for Aging
        ff_col = header_map.get("first_found")
        first_found = parse_date_safe(row.get(ff_col)) if ff_col else None
        
        lf_col = header_map.get("last_found")
        last_found = parse_date_safe(row.get(lf_col)) if lf_col else None

        # 10. Tenable VPR, Patch Available, Malware & Plugin Type
        vpr_col = header_map.get("vpr")
        vpr_raw = parse_float_safe(row.get(vpr_col)) if vpr_col else None
        vpr = vpr_raw if vpr_raw is not None else cvss_v3

        patch_col = header_map.get("patch_available")
        patch_available = is_truthy(row.get(patch_col)) if patch_col else False

        malware_col = header_map.get("exploited_by_malware")
        exploited_by_malware = is_truthy(row.get(malware_col)) if malware_col else False

        ptype_col = header_map.get("plugin_type")
        plugin_type = str(row.get(ptype_col, "remote")).strip().lower() if ptype_col else "remote"

        # Unique finding signature per host, plugin, port, and protocol
        vuln_key = (host_key, plugin_id, port, protocol)

        if vuln_key not in findings_dict:
            findings_dict[vuln_key] = {
                "host_ip": host_key,
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "cves": list(cves_from_row),
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "vpr": vpr,
                "severity": severity,
                "port": port,
                "protocol": protocol,
                "synopsis": synopsis,
                "description": description,
                "solution": solution,
                "see_also": see_also,
                "plugin_output": plugin_output,
                "exploit_available": exploit_available,
                "exploit_frameworks": exploit_frameworks_set,
                "exploited_by_malware": exploited_by_malware,
                "patch_available": patch_available,
                "plugin_type": plugin_type,
                "treatment_status": "Open",
                "first_found": first_found,
                "last_found": last_found
            }
        else:
            existing = findings_dict[vuln_key]

            # Aggregate all unique CVEs from subsequent rows
            for c in cves_from_row:
                if c not in existing["cves"]:
                    existing["cves"].append(c)

            # Escalate to highest severity among grouped rows
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing["severity"], 0):
                existing["severity"] = severity

            # Keep maximum CVSS & VPR scores
            if cvss_v3 is not None:
                existing["cvss_v3"] = max(existing["cvss_v3"] or 0.0, cvss_v3)
            if cvss_v2 is not None:
                existing["cvss_v2"] = max(existing["cvss_v2"] or 0.0, cvss_v2)
            if vpr is not None:
                existing["vpr"] = max(existing["vpr"] or 0.0, vpr)

            # Aggregate exploit information
            if exploit_available:
                existing["exploit_available"] = True
            existing["exploit_frameworks"].update(exploit_frameworks_set)
            if exploited_by_malware:
                existing["exploited_by_malware"] = True
            if patch_available:
                existing["patch_available"] = True

            # Preserve best descriptive information
            if len(synopsis) > len(existing.get("synopsis") or ""):
                existing["synopsis"] = synopsis
            if len(description) > len(existing.get("description") or ""):
                existing["description"] = description
            if len(solution) > len(existing.get("solution") or ""):
                existing["solution"] = solution
            if len(plugin_output) > len(existing.get("plugin_output") or ""):
                existing["plugin_output"] = plugin_output
            if see_also and see_also not in (existing.get("see_also") or ""):
                existing["see_also"] = ((existing.get("see_also") or "") + " " + see_also).strip()

            # Preserve earliest first_found and latest last_found
            if first_found:
                if existing["first_found"] is None or first_found < existing["first_found"]:
                    existing["first_found"] = first_found
            if last_found:
                if existing["last_found"] is None or last_found > existing["last_found"]:
                    existing["last_found"] = last_found

    # Convert consolidated findings and update host and global metrics
    findings_list: List[Dict[str, Any]] = []

    for vuln_key, f in findings_dict.items():
        host_key = f["host_ip"]
        sev = f["severity"]
        exp = f["exploit_available"]

        # Aggregate formatted CVE string
        f["cve"] = ", ".join(f["cves"]) if f["cves"] else ""
        f["exploit_frameworks"] = ", ".join(sorted(f["exploit_frameworks"])) if f["exploit_frameworks"] else ""

        # Update host counts and global stats once per consolidated finding
        if sev == "Critical":
            hosts_dict[host_key]["critical_count"] += 1
            stats["critical_count"] += 1
            if exp:
                hosts_dict[host_key]["exploitable_critical_count"] += 1
                stats["exploitable_critical_count"] += 1
        elif sev == "High":
            hosts_dict[host_key]["high_count"] += 1
            stats["high_count"] += 1
        elif sev == "Medium":
            hosts_dict[host_key]["medium_count"] += 1
            stats["medium_count"] += 1
        elif sev == "Low":
            hosts_dict[host_key]["low_count"] += 1
            stats["low_count"] += 1
        else:
            hosts_dict[host_key]["info_count"] += 1
            stats["info_count"] += 1

        del f["cves"]
        findings_list.append(f)

    # Recompute Host Risk Scores (ISO 27001 metric)
    for h in hosts_dict.values():
        h["risk_score"] = round(
            (h["critical_count"] * 10.0) +
            (h["high_count"] * 5.0) +
            (h["medium_count"] * 2.0) +
            (h["low_count"] * 0.5) +
            (h["exploitable_critical_count"] * 5.0),
            1
        )

    return {
        "hosts": hosts_dict,
        "findings": findings_list,
        "stats": stats
    }

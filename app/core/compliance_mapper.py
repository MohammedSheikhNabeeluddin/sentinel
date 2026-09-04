"""
Compliance & Framework Mapping
- Maps risk metrics / findings to ISO 27001, NIST CSF, CIS Controls, RBI Cyber Security Framework, SEBI Cyber Resilience
- Generates evidence-based report
"""

FRAMEWORKS = {
    "ISO27001": {
        "name":"ISO/IEC 27001:2022",
        "controls": {
            "A.5.17": "Authentication information",
            "A.5.23": "Information security for cloud services",
            "A.8.8": "Management of technical vulnerabilities",
            "A.8.26": "Application security requirements",
            "A.5.33": "Protection of PII",
        },
        "mapping": {
            "sqli": ["A.8.26","A.8.8"],
            "xss": ["A.8.26","A.5.23"],
            "idor": ["A.5.17","A.8.26"],
            "rce": ["A.8.26","A.8.8"],
            "ssrf": ["A.8.26"],
            "exposure": ["A.5.33","A.8.8"],
            "hardcoded_secret": ["A.5.17","A.5.33"],
        }
    },
    "NIST": {
        "name":"NIST Cybersecurity Framework 2.0",
        "controls": {
            "PR.DS-1": "Data-at-rest protected",
            "PR.DS-7": "Development lifecycle protected",
            "PR.AC-3": "Remote access managed",
            "PR.AC-7": "MFA for privileged",
            "DE.CM-1": "Network monitoring",
            "RS.MA-2": "Incident remediation",
        },
        "mapping": {
            "sqli": ["PR.DS-1","PR.DS-7"],
            "xss": ["PR.DS-7"],
            "idor": ["PR.AC-3","PR.DS-1"],
            "rce": ["PR.DS-7","RS.MA-2"],
            "ssrf": ["PR.DS-7","DE.CM-1"],
            "exposure": ["PR.DS-1"],
            "hardcoded_secret": ["PR.AC-7","PR.DS-1"],
        }
    },
    "CIS": {
        "name":"CIS Controls v8",
        "controls": {
            "3.3": "Configure Data Access Controls",
            "3.10": "Encrypt sensitive data",
            "4.1": "Secure configuration process",
            "6.5": "Account management - MFA",
            "16.6": "Application isolation",
        },
        "mapping": {
            "sqli": ["3.3","16.6"],
            "xss": ["16.6"],
            "idor": ["3.3"],
            "rce": ["4.1"],
            "ssrf": ["3.3"],
            "exposure": ["3.3","3.10"],
            "hardcoded_secret": ["6.5"],
        }
    },
    "RBI": {
        "name":"RBI Cyber Security Framework (Banks)",
        "controls": {
            "Annex1-8": "Application security & vulnerability mgmt",
            "Annex1-11": "Access control & identity mgmt",
            "Annex1-12": "Network security",
            "Annex1-15": "Incident response",
        },
        "mapping": {
            "sqli": ["Annex1-8"],
            "xss": ["Annex1-8"],
            "idor": ["Annex1-11"],
            "rce": ["Annex1-8","Annex1-15"],
            "ssrf": ["Annex1-12"],
            "exposure": ["Annex1-11"],
            "hardcoded_secret": ["Annex1-11"],
        }
    },
    "SEBI": {
        "name":"SEBI Cyber Security & Cyber Resilience (CSCRF)",
        "controls": {
            "12.3": "Access controls",
            "15.1": "Vulnerability assessment",
            "16.2": "Security monitoring (SIEM)",
            "19.1": "Incident reporting",
        },
        "mapping": {
            "sqli": ["15.1"],
            "xss": ["15.1"],
            "idor": ["12.3"],
            "rce": ["15.1","19.1"],
            "ssrf": ["15.1"],
            "exposure": ["12.3"],
            "hardcoded_secret": ["12.3"],
        }
    },
}

def map_findings_to_framework(findings, framework_key: str):
    fw = FRAMEWORKS.get(framework_key)
    if not fw:
        return {"error": f"Unknown framework {framework_key}"}
    mapping = fw["mapping"]
    controls = fw["controls"]
    coverage = {}
    gaps = []
    for f in findings:
        cat = f.get("category","general").lower()
        # normalize
        key = cat
        if "hardcoded" in cat or "secret" in cat:
            key = "hardcoded_secret"
        mapped = mapping.get(key, [])
        for c in mapped:
            coverage[c] = coverage.get(c, 0) + 1
        if not mapped:
            gaps.append(f)
    # Compliance score: % controls with at least one finding vs total controls
    # Actually invert: compliance = 100 - (gaps/total)
    total_controls = len(controls)
    impacted = len(coverage)
    compliance_pct = max(0, 100 - (impacted/total_controls*40) - len(findings)*1.5)
    compliance_pct = round(min(100, compliance_pct),1)
    # Build control status
    control_status = []
    for cid, cname in controls.items():
        cnt = coverage.get(cid,0)
        status = "fail" if cnt>0 else "pass"
        control_status.append({"control_id":cid,"name":cname,"findings_count":cnt,"status":status})
    return {
        "framework": framework_key,
        "framework_name": fw["name"],
        "compliance_pct": compliance_pct,
        "controls": control_status,
        "gaps": gaps[:3],
        "summary": f"{framework_key} compliance {compliance_pct}% — {impacted}/{total_controls} controls impacted by {len(findings)} findings. Prioritize remediation for {list(coverage.keys())[:3]}"
    }

def generate_evidence_report(findings, risk_summary):
    reports = {}
    for fw_key in FRAMEWORKS.keys():
        reports[fw_key] = map_findings_to_framework(findings, fw_key)
    # Overall governance score avg
    avg = sum(r["compliance_pct"] for r in reports.values())/len(reports)
    return {
        "overall_governance_score": round(avg,1),
        "frameworks": reports,
        "risk_context": risk_summary.get("org",{}),
        "evidence": f"Report generated from {len(findings)} findings across {risk_summary.get('org',{}).get('asset_count',0)} assets. EAL ₹{risk_summary.get('org',{}).get('total_eal_cr',0):.2f}Cr. See per-framework control status for audit evidence."
    }

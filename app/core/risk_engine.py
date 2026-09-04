"""
Risk Quantification Engine
- Continuous aggregation & normalization of vuln scanner, SIEM, IAM, EDR, CSPM, asset inventory, threat intel
- Statistical/ML estimation of likelihood + business impact (downtime, breach, penalty, reputation)
- EAL (Expected Annual Loss) & VaR at org / business unit / asset levels
- Asset criticality modeling
- Control effectiveness evaluation
"""
import math
import random
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

# -- Constants for financial impact estimation (tunable per org) --
ASSET_VALUE_BASE = {
    "critical": 50000000,  # 5 Cr INR
    "high": 20000000,
    "medium": 5000000,
    "low": 1000000,
}
# Business impact multipliers
DOWNTIME_COST_PER_HOUR = 250000  # INR
BREACH_COST_PER_RECORD = 5000
REGULATORY_PENALTY_FACTOR = 0.15
REPUTATION_FACTOR = 0.20

CVSS_SEVERITY_WEIGHT = {
    "critical": 0.9,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.15,
    "none": 0.02
}

@dataclass
class Asset:
    asset_id: str
    name: str
    type: str  # web, api, db, infra, etc.
    criticality: str  # critical/high/medium/low
    business_unit: str
    value: float = 0
    service_dependencies: List[str] = None
    def __post_init__(self):
        if self.service_dependencies is None:
            self.service_dependencies = []
        if self.value == 0:
            self.value = ASSET_VALUE_BASE.get(self.criticality, 1000000)

@dataclass
class Vulnerability:
    vuln_id: str
    title: str
    severity: str
    cvss: float
    asset_id: str
    category: str  # e.g., SQLi, XSS, IDOR, RCE
    exploitability: float  # 0-1
    control_gap: str = ""  # which control missing
    discovered_at: str = ""

@dataclass
class RiskMetrics:
    asset_id: str
    sle: float
    aro: float
    eal: float
    var_95: float
    risk_score: float  # 0-100

class RiskEngine:
    def __init__(self):
        self.assets: Dict[str, Asset] = {}
        self.vulns: List[Vulnerability] = []
        self.history: List[Dict] = []  # for trend

    # --- Asset management ---
    def add_asset(self, asset: Asset):
        self.assets[asset.asset_id] = asset

    def load_default_assets(self):
        defaults = [
            Asset("web-01", "Customer Portal", "web", "critical", "Retail Banking"),
            Asset("api-01", "Payments API", "api", "critical", "Payments"),
            Asset("db-01", "Core Banking DB", "db", "critical", "Core Banking", value=80000000),
            Asset("iam-01", "IAM Service", "infra", "high", "IT"),
            Asset("edr-01", "Endpoint Fleet", "infra", "medium", "Operations"),
        ]
        for a in defaults:
            self.add_asset(a)

    # --- Ingest & Normalize ---
    def ingest_vulns(self, vulns: List[Dict[str, Any]]):
        """Normalize from Strix/SIEM/CSPM/etc. Dicts with title,severity,cvss,asset_id,category"""
        for v in vulns:
            vuln = Vulnerability(
                vuln_id=v.get("vuln_id", f"VULN-{random.randint(1000,9999)}"),
                title=v.get("title", "Unknown Vuln"),
                severity=v.get("severity", "medium").lower(),
                cvss=v.get("cvss", 5.0),
                asset_id=v.get("asset_id", "web-01"),
                category=v.get("category", "general"),
                exploitability=v.get("exploitability", CVSS_SEVERITY_WEIGHT.get(v.get("severity","medium"),0.4)),
                control_gap=v.get("control_gap",""),
                discovered_at=v.get("discovered_at", datetime.now().isoformat())
            )
            self.vulns.append(vuln)

    def ingest_strix_findings(self, findings: List[Dict]):
        """Specific adapter for Strix report.json -> vulns"""
        mapped = []
        for f in findings:
            mapped.append({
                "vuln_id": f.get("id") or f.get("vuln_id"),
                "title": f.get("title") or f.get("name") or f.get("vulnerability"),
                "severity": f.get("severity") or "high",
                "cvss": f.get("cvss") or f.get("cvss_score") or 7.5,
                "asset_id": f.get("asset_id") or "web-01",
                "category": f.get("category") or f.get("cwe") or "injection",
                "exploitability": f.get("exploitability") or 0.7,
            })
        self.ingest_vulns(mapped)

    # --- Core quantification ---
    def _likelihood(self, vuln: Vulnerability, asset: Asset) -> float:
        """Statistical + ML-like likelihood: CVSS * exploitability * asset weight * threat intel trend"""
        base = CVSS_SEVERITY_WEIGHT.get(vuln.severity, 0.4) * (vuln.cvss / 10.0)
        exploit = vuln.exploitability
        # Asset criticality weight
        crit_w = {"critical":1.5, "high":1.2, "medium":1.0, "low":0.7}.get(asset.criticality,1.0)
        # Simulate ML adjustment: if vuln category trending (e.g., rce higher)
        trending = 1.2 if vuln.category.lower() in ["rce","sqli","idor"] else 1.0
        # Control effectiveness dampening (if control gap mitigated, lower likelihood)
        control_damp = 0.85 if vuln.control_gap else 1.0
        aro = base * exploit * crit_w * trending * control_damp
        # Clamp to realistic ARO 0.01 to 3.5 per year
        return max(0.01, min(3.5, aro))

    def _impact(self, vuln: Vulnerability, asset: Asset) -> float:
        """SLE estimation: asset value * severity factor + downtime + regulatory + reputation"""
        severity_factor = {"critical":0.6, "high":0.35, "medium":0.15, "low":0.05}.get(vuln.severity,0.15)
        base_loss = asset.value * severity_factor
        # Add breach cost if data-related vuln
        records = 50000 if vuln.category.lower() in ["sqli","idor","xss","exposure"] else 5000
        breach = records * BREACH_COST_PER_RECORD * severity_factor
        downtime = DOWNTIME_COST_PER_HOUR * (12 if vuln.severity=="critical" else 4) * severity_factor
        regulatory = (base_loss+breach) * REGULATORY_PENALTY_FACTOR
        reputation = (base_loss+breach) * REPUTATION_FACTOR
        sle = base_loss + breach + downtime + regulatory + reputation
        return sle

    def compute_risk(self) -> Dict[str, Any]:
        per_asset: Dict[str, RiskMetrics] = {}
        total_eal = 0
        # Group vulns by asset
        from collections import defaultdict
        vulns_by_asset = defaultdict(list)
        for v in self.vulns:
            vulns_by_asset[v.asset_id].append(v)
        # Ensure all assets have entry even if no vulns
        for aid, asset in self.assets.items():
            vulns = vulns_by_asset.get(aid, [])
            if not vulns:
                sle, aro, eal, var95, score = 0, 0.01, 0, 0, 5
            else:
                sle_sum = sum(self._impact(v, asset) for v in vulns)
                # ARO aggregated: 1 - product(1 - likelihood) approx for multiple vulns
                aros = [self._likelihood(v, asset) for v in vulns]
                aro = 1 - math.prod([1 - (a/3.5) for a in aros])  # normalize
                aro = aro * 2.5  # scale back to meaningful ARO
                aro = max(0.05, min(3.0, aro))
                eal = sle_sum * (aro / len(vulns)) * 1.2  # average EAL
                # VaR via Monte Carlo lognormal simulation
                var95 = self._var_monte_carlo(sle_sum, aro)
                # Risk score 0-100
                score = min(100, (eal / 2000000) * 10 + len(vulns)*3 + asset.value/10000000)
            per_asset[aid] = RiskMetrics(aid, sle_sum if vulns else 0, aro, eal, var95, score)
            total_eal += per_asset[aid].eal

        # Org-level metrics
        var_total = sum(m.var_95 for m in per_asset.values())
        # Risk score normalized
        org_score = min(100, total_eal / 5000000 * 10 + len(self.vulns)*2)
        # Trend entry
        entry = {"ts": datetime.now().isoformat(), "eal": total_eal, "score": org_score, "var": var_total}
        self.history.append(entry)
        if len(self.history) > 100:
            self.history = self.history[-100:]

        # Top contributors
        top = sorted(per_asset.values(), key=lambda x: x.eal, reverse=True)[:5]
        return {
            "org": {
                "total_eal_inr": total_eal,
                "total_eal_cr": total_eal/10000000,
                "var_95_inr": var_total,
                "var_95_cr": var_total/10000000,
                "risk_score": org_score,
                "vuln_count": len(self.vulns),
                "asset_count": len(self.assets)
            },
            "per_asset": [asdict(m) for m in per_asset.values()],
            "top_contributors": [asdict(m) for m in top],
            "history": self.history[-30:],
        }

    def _var_monte_carlo(self, sle: float, aro: float, n=5000, confidence=0.95) -> float:
        # Simulate annual loss distribution
        np.random.seed(42)
        # Lognormal params
        mu = np.log(max(sle, 100000)) - 0.5
        sigma = 0.8
        losses = np.random.lognormal(mu, sigma, n) * np.random.poisson(aro, n)
        var = np.percentile(losses, confidence*100)
        return float(var)

    # --- Scenario simulation ---
    def simulate(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """What-if: e.g., {'mfa_all_privileged': True, 'patch_high': True, 'delay_days': 30}"""
        orig = self.compute_risk()
        orig_eal = orig["org"]["total_eal_inr"]
        # Estimate reduction factors
        reduction = 0
        if scenario.get("mfa_all_privileged"):
            reduction += 0.25
        if scenario.get("patch_high"):
            reduction += 0.20
            # reduce high/critical vulns by 80%
            reduction += 0.10
        if scenario.get("network_segmentation"):
            reduction += 0.15
        if scenario.get("additional_monitoring"):
            reduction += 0.10
        if scenario.get("delay_days"):
            # delay increases exposure: +2% per week
            weeks = scenario["delay_days"]/7
            reduction -= weeks * 0.02
        reduction = max(-0.3, min(0.7, reduction))
        new_eal = orig_eal * (1 - reduction)
        saved = orig_eal - new_eal
        # ROSI placeholder (cost assumed)
        cost = scenario.get("cost_inr", 1500000)
        rosi = (saved - cost)/cost if cost else 0
        return {
            "scenario": scenario,
            "original_eal_inr": orig_eal,
            "new_eal_inr": new_eal,
            "saved_inr": saved,
            "reduction_pct": reduction*100,
            "estimated_cost_inr": cost,
            "rosi": rosi,
            "narrative": f"Scenario reduces EAL by {reduction*100:.1f}% saving ₹{saved/100000:.1f}L, ROSI {rosi*100:.1f}%"
        }

# Global singleton for app
risk_engine = RiskEngine()
risk_engine.load_default_assets()

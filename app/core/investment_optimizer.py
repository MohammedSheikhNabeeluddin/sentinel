"""
Investment Optimization Module
- Knapsack for max risk reduction per budget (e.g., ₹1 Cr)
- ROSI = (ALE_before - ALE_after - cost)/cost
- Investment vs Risk Reduction curves
"""
import math
from typing import List, Dict, Any
import json

# Catalog of security controls / remediations with cost and risk reduction
CONTROL_CATALOG = [
    {"id":"patch-sqli","name":"Patch SQLi in Customer Portal","category":"patch","cost_inr":600000,"reduction_pct":18,"eal_reduction_inr": 1800000},
    {"id":"mfa-priv","name":"MFA for all privileged accounts","category":"iam","cost_inr":1200000,"reduction_pct":22,"eal_reduction_inr": 2200000},
    {"id":"waf-tuning","name":"WAF tuning + ruleset update","category":"network","cost_inr":400000,"reduction_pct":9,"eal_reduction_inr": 900000},
    {"id":"api-auth","name":"Fix IDOR + authz in Payments API","category":"api","cost_inr":900000,"reduction_pct":16,"eal_reduction_inr": 1600000},
    {"id":"ssrf-patch","name":"SSRF patch in webhook","category":"patch","cost_inr":500000,"reduction_pct":11,"eal_reduction_inr": 1100000},
    {"id":"rce-fix","name":"RCE fix in queue worker","category":"patch","cost_inr":750000,"reduction_pct":20,"eal_reduction_inr": 2000000},
    {"id":"secrets-rotate","name":"Rotate & vault hardcoded secrets","category":"iam","cost_inr":300000,"reduction_pct":7,"eal_reduction_inr": 700000},
    {"id":"segmentation","name":"Network segmentation for DB","category":"network","cost_inr":2000000,"reduction_pct":14,"eal_reduction_inr": 1400000},
    {"id":"edr-rollout","name":"EDR rollout to 500 endpoints","category":"monitoring","cost_inr":2500000,"reduction_pct":13,"eal_reduction_inr": 1300000},
    {"id":"siem-rules","name":"SIEM detection rules + SOAR","category":"monitoring","cost_inr":1800000,"reduction_pct":10,"eal_reduction_inr": 1000000},
    {"id":"pentest-quarterly","name":"Quarterly Strix pentests","category":"governance","cost_inr":800000,"reduction_pct":8,"eal_reduction_inr": 800000},
    {"id":"training","name":"Secure coding training","category":"governance","cost_inr":600000,"reduction_pct":6,"eal_reduction_inr": 600000},
]

def optimize(budget_inr: int, catalog: List[Dict] = None) -> Dict[str, Any]:
    catalog = catalog or CONTROL_CATALOG
    n = len(catalog)
    # 0/1 Knapsack DP - maximize total eal_reduction within budget
    # Budget up to 1Cr, scale to lakhs to keep DP feasible
    scale = 100000  # 1 unit = 1 lakh
    B = budget_inr // scale
    # DP arrays
    dp = [[0]*(B+1) for _ in range(n+1)]
    keep = [[False]*(B+1) for _ in range(n+1)]
    for i in range(1, n+1):
        cost = catalog[i-1]["cost_inr"] // scale
        val = catalog[i-1]["eal_reduction_inr"]
        for w in range(B+1):
            if cost <= w and dp[i-1][w-cost] + val > dp[i-1][w]:
                dp[i][w] = dp[i-1][w-cost] + val
                keep[i][w] = True
            else:
                dp[i][w] = dp[i-1][w]
    # Backtrack
    w = B
    selected = []
    for i in range(n,0,-1):
        if keep[i][w]:
            selected.append(catalog[i-1])
            w -= catalog[i-1]["cost_inr"] // scale
    selected = list(reversed(selected))
    total_cost = sum(c["cost_inr"] for c in selected)
    total_reduction = sum(c["eal_reduction_inr"] for c in selected)
    total_pct = sum(c["reduction_pct"] for c in selected)
    # ROSI overall
    rosi = (total_reduction - total_cost)/total_cost if total_cost else 0
    # Unselected
    selected_ids = {c["id"] for c in selected}
    remaining = [c for c in catalog if c["id"] not in selected_ids]
    # Sort remaining by efficiency (reduction per cost)
    for c in remaining:
        c["efficiency"] = c["eal_reduction_inr"]/c["cost_inr"]
    remaining = sorted(remaining, key=lambda x: x["efficiency"], reverse=True)
    return {
        "budget_inr": budget_inr,
        "budget_cr": budget_inr/10000000,
        "selected": selected,
        "remaining": remaining[:5],
        "total_cost_inr": total_cost,
        "total_cost_cr": total_cost/10000000,
        "total_reduction_inr": total_reduction,
        "total_reduction_cr": total_reduction/10000000,
        "total_reduction_pct": round(total_pct,1),
        "rosi": round(rosi,2),
        "rosi_pct": round(rosi*100,1),
        "unspent_inr": budget_inr - total_cost,
        "efficiency": total_reduction/total_cost if total_cost else 0
    }

def investment_curve(max_budget_cr: float = 2.0, step_cr: float = 0.2) -> List[Dict]:
    """Generate Investment vs Risk Reduction curve points"""
    points = []
    for cr in [i*step_cr for i in range(1, int(max_budget_cr/step_cr)+1)]:
        budget = int(cr*10000000)
        opt = optimize(budget)
        points.append({
            "budget_cr": cr,
            "budget_inr": budget,
            "reduction_pct": opt["total_reduction_pct"],
            "reduction_cr": opt["total_reduction_cr"],
            "rosi": opt["rosi"],
            "cost_cr": opt["total_cost_cr"],
        })
    return points

def cost_benefit_for_control(control_id: str) -> Dict:
    for c in CONTROL_CATALOG:
        if c["id"] == control_id:
            rosi = (c["eal_reduction_inr"] - c["cost_inr"])/c["cost_inr"]
            return {**c, "rosi": round(rosi,2), "rosi_pct": round(rosi*100,1)}
    return {}

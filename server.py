#!/usr/bin/env python3
"""
PCI DSS Compliance MCP Server
===============================
By MEOK AI Labs | https://meok.ai

Automates PCI DSS payment card industry compliance assessment.
Covers all 12 requirements, cardholder data flow analysis,
network segmentation, vulnerability scanning, and SAQ generation.

Install: pip install mcp
Run:     python server.py
"""

import json
import os
import sys
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

# ── Authentication ──────────────────────────────────────────────
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access

_MEOK_API_KEY = os.environ.get("MEOK_API_KEY", "")


def _check_auth(api_key: str = "") -> str | None:
    if _MEOK_API_KEY and api_key != _MEOK_API_KEY:
        return "Invalid API key. Get one at https://meok.ai/api-keys"
    return None


# ── Rate limiting ───────────────────────────────────────────────
FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _rl(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit ({FREE_DAILY_LIMIT}/day). "
            "Upgrade: https://meok.ai/mcp/pci-dss/pro"
        )
    _usage[caller].append(now)
    return None


# ── PCI DSS 4.0 Knowledge Base ─────────────────────────────────

PCI_REQUIREMENTS = {
    "1": {"name": "Install and Maintain Network Security Controls", "category": "Build and Maintain a Secure Network",
          "checks": ["firewall_config", "network_diagram", "dmz_implemented", "personal_firewall"]},
    "2": {"name": "Apply Secure Configurations to All System Components", "category": "Build and Maintain a Secure Network",
          "checks": ["no_vendor_defaults", "system_hardening", "non_console_encryption", "primary_functions_only"]},
    "3": {"name": "Protect Stored Account Data", "category": "Protect Account Data",
          "checks": ["data_retention_policy", "no_sensitive_auth_data", "pan_masked", "encryption_key_management"]},
    "4": {"name": "Protect Cardholder Data with Strong Cryptography During Transmission", "category": "Protect Account Data",
          "checks": ["strong_cryptography", "no_pan_via_messaging", "tls_1_2_minimum"]},
    "5": {"name": "Protect All Systems and Networks from Malicious Software", "category": "Maintain a Vulnerability Management Program",
          "checks": ["anti_malware_deployed", "anti_malware_current", "periodic_scans", "anti_malware_logging"]},
    "6": {"name": "Develop and Maintain Secure Systems and Software", "category": "Maintain a Vulnerability Management Program",
          "checks": ["security_patches", "sdlc_process", "change_control", "web_app_protection"]},
    "7": {"name": "Restrict Access to System Components and Cardholder Data by Business Need to Know", "category": "Implement Strong Access Control",
          "checks": ["access_control_system", "least_privilege", "default_deny"]},
    "8": {"name": "Identify Users and Authenticate Access to System Components", "category": "Implement Strong Access Control",
          "checks": ["unique_ids", "strong_authentication", "mfa_for_admin", "password_policy"]},
    "9": {"name": "Restrict Physical Access to Cardholder Data", "category": "Implement Strong Access Control",
          "checks": ["physical_access_controls", "visitor_management", "media_controls"]},
    "10": {"name": "Log and Monitor All Access to System Components and Cardholder Data", "category": "Regularly Monitor and Test Networks",
           "checks": ["audit_trails", "time_synchronization", "log_review", "log_retention"]},
    "11": {"name": "Test Security of Systems and Networks Regularly", "category": "Regularly Monitor and Test Networks",
           "checks": ["wireless_scanning", "vulnerability_scans", "penetration_testing", "ids_ips"]},
    "12": {"name": "Support Information Security with Organizational Policies and Programs", "category": "Maintain an Information Security Policy",
           "checks": ["security_policy", "risk_assessment", "security_awareness", "incident_response"]},
}

SAQ_TYPES = {
    "A": {"description": "Card-not-present merchants, all cardholder data functions fully outsourced", "requirements": ["2", "6", "8", "9", "12"]},
    "A-EP": {"description": "E-commerce merchants with website that impacts payment security", "requirements": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]},
    "B": {"description": "Merchants using imprint machines or standalone dial-out terminals", "requirements": ["3", "4", "7", "9", "12"]},
    "B-IP": {"description": "Merchants using standalone IP-connected PTS POI terminals", "requirements": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]},
    "C": {"description": "Merchants with payment application systems connected to Internet", "requirements": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]},
    "C-VT": {"description": "Merchants using virtual terminals on isolated computers", "requirements": ["2", "3", "4", "6", "8", "9", "12"]},
    "D": {"description": "All other merchants and all service providers", "requirements": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]},
    "P2PE": {"description": "Merchants using validated P2PE solutions", "requirements": ["3", "9", "12"]},
}


# ── FastMCP Server ──────────────────────────────────────────────

mcp = FastMCP(
    "pci-dss-mcp",
    instructions=(
        "PCI DSS Compliance MCP Server by MEOK AI Labs. "
        "Assess payment card data security against PCI DSS 4.0 requirements. "
        "Analyze cardholder data flows, check network segmentation, "
        "evaluate vulnerability scanning, and generate Self-Assessment Questionnaires."
    ),
)


@mcp.tool()
def assess_pci_compliance(
    organization_name: str,
    merchant_level: int = 4,
    has_firewall: bool = False,
    has_secure_config: bool = False,
    has_data_protection: bool = False,
    has_encryption_transit: bool = False,
    has_anti_malware: bool = False,
    has_secure_sdlc: bool = False,
    has_access_control: bool = False,
    has_strong_auth: bool = False,
    has_physical_security: bool = False,
    has_logging: bool = False,
    has_security_testing: bool = False,
    has_security_policy: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Evaluate an organization against all 12 PCI DSS 4.0 requirements."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    req_status = {
        "1": has_firewall, "2": has_secure_config, "3": has_data_protection,
        "4": has_encryption_transit, "5": has_anti_malware, "6": has_secure_sdlc,
        "7": has_access_control, "8": has_strong_auth, "9": has_physical_security,
        "10": has_logging, "11": has_security_testing, "12": has_security_policy,
    }

    results = []
    for req_id, met in req_status.items():
        req = PCI_REQUIREMENTS[req_id]
        results.append({
            "requirement": req_id,
            "name": req["name"],
            "category": req["category"],
            "status": "PASS" if met else "FAIL",
            "checks_needed": req["checks"],
        })

    passed = sum(1 for r in results if r["status"] == "PASS")
    score = round(passed / 12 * 100, 1)

    return json.dumps({
        "organization": organization_name,
        "merchant_level": merchant_level,
        "pci_dss_version": "4.0",
        "assessment_date": datetime.now().isoformat(),
        "overall_score": score,
        "compliance_status": "COMPLIANT" if passed == 12 else "NON_COMPLIANT",
        "requirements_passed": passed,
        "requirements_failed": 12 - passed,
        "results": results,
    }, indent=2)


@mcp.tool()
def check_cardholder_data(
    data_flow_description: str,
    stores_pan: bool = False,
    stores_cvv: bool = False,
    stores_pin: bool = False,
    stores_track_data: bool = False,
    pan_encrypted: bool = False,
    pan_truncated: bool = False,
    tokenization_used: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Analyze cardholder data flow for PCI DSS compliance."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    issues = []
    if stores_cvv:
        issues.append({"violation": "CVV/CVC storage prohibited", "requirement": "3.3.1",
                        "severity": "CRITICAL", "remediation": "Never store CVV/CVC after authorization"})
    if stores_pin:
        issues.append({"violation": "PIN storage prohibited", "requirement": "3.3.1",
                        "severity": "CRITICAL", "remediation": "Never store PIN data after authorization"})
    if stores_track_data:
        issues.append({"violation": "Full track data storage prohibited", "requirement": "3.3.1",
                        "severity": "CRITICAL", "remediation": "Never store full track data after authorization"})
    if stores_pan and not pan_encrypted and not tokenization_used:
        issues.append({"violation": "PAN stored without protection", "requirement": "3.5.1",
                        "severity": "HIGH", "remediation": "Encrypt PAN at rest or use tokenization"})
    if stores_pan and not pan_truncated and not pan_encrypted:
        issues.append({"warning": "PAN displayed without masking", "requirement": "3.4.1",
                        "severity": "MEDIUM", "remediation": "Mask PAN when displayed (show max first 6 / last 4)"})

    scope_reduction = []
    if tokenization_used:
        scope_reduction.append("Tokenization reduces PCI scope for stored data")
    if pan_encrypted:
        scope_reduction.append("Encryption at rest meets Requirement 3.5")
    if pan_truncated:
        scope_reduction.append("Truncation removes PAN from scope when properly implemented")

    return json.dumps({
        "data_flow": data_flow_description,
        "assessment_date": datetime.now().isoformat(),
        "sensitive_auth_data": {"cvv": stores_cvv, "pin": stores_pin, "track_data": stores_track_data},
        "pan_storage": {"stored": stores_pan, "encrypted": pan_encrypted, "truncated": pan_truncated, "tokenized": tokenization_used},
        "compliance_status": "COMPLIANT" if not issues else "NON_COMPLIANT",
        "issues": issues,
        "scope_reduction_notes": scope_reduction,
    }, indent=2)


@mcp.tool()
def network_segmentation_check(
    has_segmentation: bool = False,
    cde_isolated: bool = False,
    segmentation_tested: bool = False,
    firewall_between_zones: bool = False,
    wireless_isolated: bool = False,
    third_party_isolated: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Check network segmentation for PCI DSS scope reduction."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    checks = {
        "network_segmentation": {"met": has_segmentation, "requirement": "1.3",
            "description": "Network segmentation implemented to isolate CDE"},
        "cde_isolation": {"met": cde_isolated, "requirement": "1.3.1",
            "description": "Cardholder Data Environment isolated from other networks"},
        "segmentation_testing": {"met": segmentation_tested, "requirement": "11.4.5",
            "description": "Segmentation controls tested at least every 6 months"},
        "firewall_zones": {"met": firewall_between_zones, "requirement": "1.3.2",
            "description": "Firewalls between all security zones"},
        "wireless_isolation": {"met": wireless_isolated, "requirement": "1.3.3",
            "description": "Wireless networks isolated from CDE"},
        "third_party_isolation": {"met": third_party_isolated, "requirement": "1.3.4",
            "description": "Third-party connections isolated"},
    }

    passed = sum(1 for c in checks.values() if c["met"])
    total = len(checks)
    scope_impact = "REDUCED" if has_segmentation and cde_isolated else "FULL_NETWORK"

    return json.dumps({
        "assessment_date": datetime.now().isoformat(),
        "segmentation_score": round(passed / total * 100, 1),
        "pci_scope": scope_impact,
        "checks_passed": passed,
        "checks_total": total,
        "results": {k: v for k, v in checks.items()},
        "recommendation": "Proper segmentation can significantly reduce PCI DSS assessment scope and cost."
            if scope_impact == "FULL_NETWORK" else "Segmentation is reducing your PCI scope effectively.",
    }, indent=2)


@mcp.tool()
def vulnerability_scan_check(
    last_external_scan_date: str = "",
    last_internal_scan_date: str = "",
    external_scan_passed: bool = False,
    internal_scan_passed: bool = False,
    asv_vendor: str = "",
    quarterly_scans: bool = False,
    scan_after_changes: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Evaluate vulnerability scanning compliance per PCI DSS ASV requirements."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    issues = []
    now = datetime.now()

    if last_external_scan_date:
        try:
            ext_date = datetime.strptime(last_external_scan_date, "%Y-%m-%d")
            days_since = (now - ext_date).days
            if days_since > 90:
                issues.append({"issue": f"External scan {days_since} days old (>90 days)",
                               "requirement": "11.3.2", "severity": "HIGH"})
        except ValueError:
            issues.append({"issue": "Invalid external scan date format", "severity": "LOW"})
    else:
        issues.append({"issue": "No external scan date provided", "requirement": "11.3.2", "severity": "HIGH"})

    if last_internal_scan_date:
        try:
            int_date = datetime.strptime(last_internal_scan_date, "%Y-%m-%d")
            days_since = (now - int_date).days
            if days_since > 90:
                issues.append({"issue": f"Internal scan {days_since} days old (>90 days)",
                               "requirement": "11.3.1", "severity": "HIGH"})
        except ValueError:
            issues.append({"issue": "Invalid internal scan date format", "severity": "LOW"})
    else:
        issues.append({"issue": "No internal scan date provided", "requirement": "11.3.1", "severity": "HIGH"})

    if not asv_vendor:
        issues.append({"issue": "No ASV vendor specified", "requirement": "11.3.2", "severity": "MEDIUM",
                        "note": "External scans must be performed by a PCI SSC Approved Scanning Vendor"})

    if not external_scan_passed:
        issues.append({"issue": "Last external scan did not pass", "requirement": "11.3.2", "severity": "HIGH"})
    if not internal_scan_passed:
        issues.append({"issue": "Last internal scan did not pass", "requirement": "11.3.1", "severity": "HIGH"})
    if not quarterly_scans:
        issues.append({"issue": "Quarterly scanning schedule not maintained", "requirement": "11.3", "severity": "HIGH"})
    if not scan_after_changes:
        issues.append({"issue": "Scans not performed after significant changes", "requirement": "11.3.1.3", "severity": "MEDIUM"})

    return json.dumps({
        "assessment_date": now.isoformat(),
        "external_scan": {"last_date": last_external_scan_date, "passed": external_scan_passed, "asv": asv_vendor},
        "internal_scan": {"last_date": last_internal_scan_date, "passed": internal_scan_passed},
        "quarterly_compliance": quarterly_scans,
        "change_scan_compliance": scan_after_changes,
        "compliance_status": "COMPLIANT" if not issues else "NON_COMPLIANT",
        "issues": issues,
    }, indent=2)


@mcp.tool()
def generate_saq(
    organization_name: str,
    saq_type: str = "D",
    caller: str = "",
    api_key: str = "",
) -> str:
    """Generate a PCI DSS Self-Assessment Questionnaire template."""
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    saq_type_upper = saq_type.upper()
    if saq_type_upper not in SAQ_TYPES:
        return json.dumps({"error": f"Invalid SAQ type. Valid: {list(SAQ_TYPES.keys())}"})

    saq = SAQ_TYPES[saq_type_upper]
    applicable_reqs = []
    for req_id in saq["requirements"]:
        req = PCI_REQUIREMENTS[req_id]
        applicable_reqs.append({
            "requirement": req_id,
            "name": req["name"],
            "checks": req["checks"],
            "status": "NOT_ASSESSED",
        })

    return json.dumps({
        "document_type": f"PCI DSS SAQ {saq_type_upper}",
        "pci_dss_version": "4.0",
        "organization": organization_name,
        "generated": datetime.now().isoformat(),
        "saq_type": saq_type_upper,
        "saq_description": saq["description"],
        "applicable_requirements": applicable_reqs,
        "total_requirements": len(applicable_reqs),
        "attestation": {
            "merchant_name": organization_name,
            "date": "",
            "signature": "",
            "title": "",
        },
        "disclaimer": "TEMPLATE ONLY. Complete assessment with a Qualified Security Assessor (QSA) for validation.",
    }, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()

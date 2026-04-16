# PCI DSS Compliance MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

Automates PCI DSS 4.0 payment card industry compliance assessment. Evaluate all 12 requirements, analyze cardholder data flows, check network segmentation, assess vulnerability scanning compliance, and generate Self-Assessment Questionnaires.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/pci-dss)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Features

- Full PCI DSS 4.0 compliance assessment across all 12 requirements
- Cardholder data flow analysis (PAN, CVV, PIN, track data storage validation)
- Network segmentation evaluation for PCI scope reduction
- Vulnerability scanning compliance (ASV vendor, quarterly cadence, internal/external)
- Self-Assessment Questionnaire (SAQ) generation for all 8 types (A, A-EP, B, B-IP, C, C-VT, D, P2PE)
- Merchant level classification (Level 1-4)
- Sensitive authentication data detection (CVV/PIN/track data storage is always CRITICAL)
- Built-in rate limiting (10 free/day) and API key authentication

## Tools

| Tool | Description |
|------|-------------|
| `assess_pci_compliance` | Evaluate against all 12 PCI DSS 4.0 requirements with per-requirement pass/fail and overall score |
| `check_cardholder_data` | Analyze cardholder data flow -- detects prohibited storage (CVV, PIN, track data), validates PAN encryption/tokenization |
| `network_segmentation_check` | Check network segmentation for scope reduction -- CDE isolation, firewall zones, wireless, third-party |
| `vulnerability_scan_check` | Evaluate vulnerability scanning compliance -- ASV vendor, 90-day recency, quarterly schedule, post-change scans |
| `generate_saq` | Generate a PCI DSS Self-Assessment Questionnaire template for any of the 8 SAQ types |

## PCI DSS 4.0 Requirements Coverage

| # | Requirement | Category |
|---|------------|----------|
| 1 | Network Security Controls | Build and Maintain a Secure Network |
| 2 | Secure Configurations | Build and Maintain a Secure Network |
| 3 | Protect Stored Account Data | Protect Account Data |
| 4 | Strong Cryptography in Transit | Protect Account Data |
| 5 | Malicious Software Protection | Vulnerability Management |
| 6 | Secure Systems and Software | Vulnerability Management |
| 7 | Access Control by Need to Know | Strong Access Control |
| 8 | User Identification and Auth | Strong Access Control |
| 9 | Restrict Physical Access | Strong Access Control |
| 10 | Log and Monitor Access | Monitor and Test Networks |
| 11 | Test Security Regularly | Monitor and Test Networks |
| 12 | Information Security Policies | Information Security Policy |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/pci-dss-mcp.git
cd pci-dss-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "pci-dss": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/pci-dss-mcp"
    }
  }
}
```

## Usage Examples

```python
# Full PCI DSS compliance assessment
result = assess_pci_compliance(
    organization_name="Acme Payments",
    merchant_level=3,
    has_firewall=True,
    has_encryption_transit=True,
    has_access_control=True,
    has_logging=True,
    has_security_policy=True
)

# Check cardholder data handling
result = check_cardholder_data(
    data_flow_description="Online checkout payment processing",
    stores_pan=True,
    pan_encrypted=True,
    tokenization_used=True
)

# Check network segmentation
result = network_segmentation_check(
    has_segmentation=True,
    cde_isolated=True,
    firewall_between_zones=True,
    segmentation_tested=True
)

# Generate SAQ template
result = generate_saq(
    organization_name="Small Retailer Co",
    saq_type="A"
)
```

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 10 requests/day |
| Pro | $29/mo | Unlimited |

## Authentication

Set `MEOK_API_KEY` environment variable. Get your key at [meok.ai/api-keys](https://meok.ai/api-keys).

## Links

- [MEOK AI Labs](https://meok.ai)
- [All MCP Servers](https://meok.ai/mcp)
- [GitHub](https://github.com/CSOAI-ORG/pci-dss-mcp)

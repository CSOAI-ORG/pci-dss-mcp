[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/pci-dss-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/pci-dss-mcp)

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/pci-dss-mcp)](https://pypi.org/project/pci-dss-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/pci-dss-mcp)](https://pypi.org/project/pci-dss-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/pci-dss-mcp)](https://github.com/CSOAI-ORG/pci-dss-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# PCI DSS 4.0 MCP

**Payment card compliance assessment across all 12 PCI DSS 4.0 requirements with cardholder data flow analysis and SAQ generation.**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing) · [Attestation API](#attestation-api)

</div>

---

## Why This Exists

PCI DSS 4.0 took effect March 2024 with 64 new requirements, many of which become mandatory by March 2025. Any organisation that stores, processes, or transmits cardholder data must comply, and AI systems that touch payment flows (fraud detection, transaction scoring, customer authentication) bring new scoping challenges.

The 4.0 revision introduces targeted risk analysis, customised approach validation, and stricter requirements for scripts, headers, and client-side protections. Most QSA-led assessments cost $50-200K. This MCP assesses compliance across all 12 requirements, analyses cardholder data flows, validates network segmentation, checks vulnerability scanning posture, and generates the appropriate Self-Assessment Questionnaire.

## Install

```bash
pip install pci-dss-mcp
```

## Tools

| Tool | PCI DSS Reference | What it does |
|------|-------------------|--------------|
| `assess_pci_compliance` | Req 1-12 | Full assessment against all 12 PCI DSS 4.0 requirements |
| `check_cardholder_data` | Req 3, 4 | Cardholder data flow analysis and storage assessment |
| `network_segmentation_check` | Req 1 | Validate network segmentation and firewall controls |
| `vulnerability_scan_check` | Req 5, 6, 11 | ASV scan compliance and vulnerability management posture |
| `generate_saq` | SAQ A-D | Generate the appropriate Self-Assessment Questionnaire |

## Example

```
Prompt: "Assess PCI DSS 4.0 compliance for our e-commerce platform.
We use Stripe for payment processing but store the last 4 digits of card
numbers in our database for order history. We run an AI fraud detection
model that sees full transaction metadata."

Result: Assessment across all 12 requirements with findings: stored card
digits need Req 3 encryption validation, AI fraud model scoping under
Req 12.5.2 targeted risk analysis, client-side JavaScript needs Req 6.4.3
integrity controls. SAQ D-Merchant generated with gap remediation plan.
```

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day — compliance assessment + SAQ generation |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations + verify URLs |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports + webhooks |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

Every Pro/Enterprise audit produces a cryptographically signed certificate:

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

Zero-dep verifier: `pip install meok-attestation-verify`

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT

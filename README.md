# PCI DSS Compliance MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

Automates PCI DSS 4.0 payment card compliance. Assess all 12 requirements, analyze cardholder data flows, check network segmentation, evaluate vulnerability scanning, and generate SAQs.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/pci-dss)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `assess_pci_compliance` | Evaluate against all 12 PCI DSS 4.0 requirements |
| `check_cardholder_data` | Analyze cardholder data flow for compliance |
| `network_segmentation_check` | Check network segmentation for scope reduction |
| `vulnerability_scan_check` | Evaluate vulnerability scanning per ASV requirements |
| `generate_saq` | Generate a PCI DSS Self-Assessment Questionnaire template |

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

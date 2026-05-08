<div align="center">

# Pci Dss MCP

**MCP server for pci dss mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-pci-dss-mcp)](https://pypi.org/project/meok-pci-dss-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Pci Dss MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `assess_pci_compliance` | Evaluate an organization against all 12 PCI DSS 4.0 requirements. |
| `check_cardholder_data` | Analyze cardholder data flow for PCI DSS compliance. |
| `network_segmentation_check` | Check network segmentation for PCI DSS scope reduction. |
| `vulnerability_scan_check` | Evaluate vulnerability scanning compliance per PCI DSS ASV requirements. |
| `generate_saq` | Generate a PCI DSS Self-Assessment Questionnaire template. |

## Installation

```bash
pip install meok-pci-dss-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "pci-dss-mcp": {
      "command": "python",
      "args": ["-m", "meok_pci_dss_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)

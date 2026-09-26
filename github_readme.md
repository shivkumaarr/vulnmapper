# ⚡ VulnMapper

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/)

**VulnMapper** is a lightning-fast, 100% free, terminal-based intelligence utility designed for penetration testers, security researchers, and red teams. It queries live vulnerability registries and automatically maps out post-exploitation attack vectors using the **MITRE ATT&CK** framework—**without requiring any paid APIs, OpenAI keys, or subscriptions.**

---

## 🌟 Key Features
- **NVD NIST Integration (v2)**: Automatically fetches official CVE numbers, CVSS scores, severities, and CWE classifications for any service version.
- **Exploit-DB Integration**: Parses live Exploit-DB GitLab registries or local `searchsploit` utilities to provide matching Exploit IDs and author details.
- **MITRE ATT&CK Auto-Mapping**: Instantly constructs an offline kill-chain attack tree mapping service weaknesses to MITRE tactics and techniques.
- **Built-in Help & CLI**: Run with `--help` for complete command-line guidance.
- **Export Options**: Export structured JSON data or beautiful standalone HTML reports that open directly in your browser.
- **Cross-Platform**: Works seamlessly on **Linux**, **Windows**, and **macOS**.

---

## ⚙️ Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/your-username/vulnmapper.git
   cd vulnmapper
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Or let the script install them for you via `python vulnmapper.py --install`)*

---

## 🚀 Usage & Commands

To view the built-in help menu:
```bash
python vulnmapper.py --help
```

### Examples:
* **Search Apache version**:
  ```bash
  python vulnmapper.py apache 2.4.49
  ```

* **Search Log4j and generate an interactive HTML report**:
  ```bash
  python vulnmapper.py log4j 2.14.1 --report
  ```

* **Export results to JSON**:
  ```bash
  python vulnmapper.py openssh 7.2p2 --json results.json
  ```

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.
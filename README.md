# P1-URLs-High-Speed-Stealth-Edition

# P1 URLs - v2.1.3 (Definitive Production Release)

<p align="center">
  <a href="https://www.python.org" target="_blank"><img src="https://img.shields.io/badge/Made%20with-Python-blue.svg" alt="Made with Python"></a>
  <a href="#" target="_blank"><img src="https://img.shields.io/badge/Version-2.1.3-brightgreen.svg" alt="Version"></a>
  <a href="#" target="_blank"><img src="https://img.shields.io/badge/Maintained%3F-yes-green.svg" alt="Maintained"></a>
  <a href="#"><img src="https://img.shields.io/badge/Contributions-welcome-brightgreen.svg" alt="Contributions Welcome"></a>
</p>

<p align="center">
  <i>An advanced, high-speed, and evasive automation framework for discovering high-impact web vulnerabilities.</i>
</p>

P1 URLs is the culmination of an iterative development process, designed to chain together leading security tools with custom, intelligent vulnerability testing modules. It automates the entire workflow from discovery to real-time alerting, focusing on speed, accuracy, and stealth.

<p align="center">
  <b>For best performance and to avoid IP blocks, running on a VPS is highly recommended.</b>
</p>

---

## 🚀 Key Features

-   **Flexible URL Discovery:** Uses **Katana** in a high-concurrency bulk mode by default. An optional `--wayback` flag can be used to add **GAU** for deeper, historical URL discovery on domains.
-   **Intelligent LFI Detection:** Employs a **Dynamic Differential Analysis** technique, comparing page content similarity to accurately detect LFI with a very low false-positive rate.
-   **Evasive Blind SQLi Engine:**
    -   **Smart Probing:** First runs a fast "probe" scan with canary payloads to identify high-potential targets, avoiding a full scan on every URL.
    -   **Multi-Vector Attack:** Tests both **URL Parameters** and **HTTP Headers** for SQLi.
    -   **Multi-Technique Approach:** Automatically uses **Standard Injection**, **HTTP Parameter Pollution (HPP)**, and **Out-of-Band (OOB)** techniques.
    -   **Traceable OOB Payloads:** When using OOB, each payload is embedded with a unique ID that is logged on-screen and to a file, allowing for perfect attribution of any callbacks.
    -   **Prioritized Payloads:** Intelligently tests more evasive `XOR`-based payloads first to find vulnerabilities faster.
-   **Advanced User Control:**
    -   **Interactive Skipping:** Gracefully skip long-running tests on a single target with `Ctrl+C` without quitting the entire scan.
    -   **Proxy Chaining:** Use different proxies for different tests (`--proxy-lfi`, `--proxy-sqli`, `--proxy-nuclei`) for maximum evasion.
    -   **Performance Tuning:** Fine-tune the scan's speed and stealth with `--concurrency` and `--rate-limit` flags.
-   **Real-Time, Dual-Channel Alerts:** Sends an **immediate, detailed notification to your terminal screen AND Slack** for every confirmed vulnerability, complete with verifiable `curl` commands.
-   **Professional Presentation & Organization:**
    -   Features a fully animated, custom startup banner.
    -   Provides constant feedback with real-time `tqdm` progress bars.
    -   Creates a unique, timestamped directory for each scan to store all logs, preventing data contamination.

---

## 🛠️ Installation & Setup

This tool is designed to run on a Linux-based environment (like Kali, Ubuntu, or a VPS).

### 1. Install Python Dependencies

The script requires `rich`, `requests`, and `tqdm`.
```bash
pip3 install rich requests tqdm
```

# Web Crawlers

``go install -v github.com/projectdiscovery/katana/cmd/katana@latest``


``go install -v github.com/lc/gau/v2/cmd/gau@latest``

# URL Deduplicator
``pipx install uro``

# Pattern Matching Tool
``go install -v github.com/tomnomnom/gf@latest``

# Vulnerability Scanner
``go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest``

```
./P1-URLs.py -l domains.txt
./P1-URLs.py -l domains.txt --wayback
./P1-URLs.py -l my_url_list.txt -u
./P1-URLs.py -l domains.txt --wayback -c my-id.oast.online --proxy-lfi http://proxy1:8080 --proxy-sqli http://proxy2:8080

```

```
  
  -l, --list          Path to a file with subdomains or URLs. (Required)
  -u, --use-urls      Skip discovery, use the input file as a direct list of URLs.
  -p, --lfi-payloads  Optional: Path to a custom LFI payloads file.
  -c, --collab-url    Collaborator URL for Out-of-Band (OOB) SQLi checks.
  --wayback           Also use GAU to gather URLs from historical archives.
  --concurrency       Set concurrency for LFI/SQLi tests (default: 25).
  --rate-limit        Set max requests per second (default: 20).
  --proxy             Global fallback proxy for all HTTP/S requests.
  --proxy-lfi         Dedicated proxy for LFI tests.
  --proxy-sqli        Dedicated proxy for custom SQLi tests.
  --proxy-nuclei      Dedicated proxy for Nuclei scans.

```

  ## Credits

    Author: Vivek (@starkcharry on X | bugcrowd.com/realvivek)

    Core Toolchain: ProjectDiscovery (katana, nuclei), tomnomnom (gf), s0md3v (uro), lc (gau), and all their respective contributors.

# 🛡️ PCAP Hunter

> **Air-Gapped Network Traffic Forensics & Multi-Vector Malware C2 Detection Platform**  
> *Empowering SOC Analysts, Threat Hunters, and Incident Responders with 100% Offline Deep Packet Inspection.*

---

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Mode](https://img.shields.io/badge/network%20mode-100%25%20Air--Gapped%20Offline-red.svg)](#security--privacy-architecture)
[![Forensics Engines](https://img.shields.io/badge/detection%20engines-4%20Multi--Vector-orange.svg)](#-multi-vector-forensic-detection-engines)
[![Code Style](https://img.shields.io/badge/code%20style-PEP%208-informational.svg)](https://peps.python.org/pep-0008/)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Multi-Vector Forensic Detection Engines](#-multi-vector-forensic-detection-engines)
  - [1. C2 Beaconing Detector](#1-command--control-c2-beaconing-detector)
  - [2. DNS Tunneling & Exfiltration Detector](#2-dns-tunneling--covert-channel-detector)
  - [3. Suspicious Traffic & Threat Intel Engine](#3-suspicious-traffic--threat-intelligence-engine)
  - [4. Data Exfiltration Detector](#4-data-exfiltration-detector)
- [Unified Threat Scoring & IOC Synthesis](#-unified-threat-scoring--ioc-synthesis)
- [Web Dashboard & SOC UI](#-web-dashboard--soc-ui)
- [Automated Incident PDF Reporting](#-automated-incident-pdf-reporting)
- [Project Architecture](#-project-architecture)
- [Installation & Quick Start](#-installation--quick-start)
- [Synthetic Malware PCAP Generator](#-synthetic-malware-pcap-generator)
- [Running Automated Tests](#-running-automated-tests)
- [REST API Reference](#-rest-api-reference)
- [Security & Privacy Architecture](#-security--privacy-architecture)
- [Configuration & Tuning](#-configuration--tuning)
- [Contributing & License](#-contributing--license)

---

## 🔍 Overview

**PCAP Hunter** is an enterprise-grade, offline-first network forensics and threat hunting tool developed to analyze raw packet captures (`.pcap`, `.pcapng`, `.cap`) without leaking a single byte of sensitive traffic to third-party cloud services or external APIs.

Modern cyber incident response teams frequently investigate sensitive network dumps containing confidential communications, internal IP schemes, authentication tokens, and advanced malware payloads. Sending packet captures to public inspection services introduces severe compliance and data confidentiality risks.

**PCAP Hunter solves this by running 100% locally and air-gapped**, combining high-performance Scapy-based streaming packet parsing, statistical variance analysis, Shannon entropy mathematics, and curated offline threat intelligence feeds to identify stealthy threat actor behaviors.

```
                    ┌─────────────────────────────────────────┐
                    │       Raw Network Packet Capture        │
                    │         (.pcap / .pcapng / .cap)        │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │       Low-Memory Streaming Parser       │
                    │      (SHA256, Flow & Protocol Extr.)    │
                    └────────────────────┬────────────────────┘
                                         │
       ┌──────────────────┬──────────────┴─────┬──────────────────┐
       ▼                  ▼                    ▼                  ▼
┌──────────────┐   ┌──────────────┐     ┌──────────────┐   ┌──────────────┐
│   Engine 1   │   │   Engine 2   │     │   Engine 3   │   │   Engine 4   │
│ C2 Beaconing │   │ DNS Tunneling│     │ Threat Intel │   │     Data     │
│   Analysis   │   │  & Entropy   │     │ & Direct IPs │   │ Exfiltration │
└──────┬───────┘   └──────┬───────┘     └──────┬───────┘   └──────┬───────┘
       │                  │                    │                  │
       └──────────────────┴──────────────┬─────┴──────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │       Pipeline Aggregator & Scorer      │
                    │   - Threat Score (0 - 100)              │
                    │   - Threat Level (CLEAN to CRITICAL)    │
                    │   - Automated IOC Extraction            │
                    │   - Executive Summary Synthesis         │
                    └────────────────────┬────────────────────┘
                                         │
                         ┌───────────────┴───────────────┐
                         ▼                               ▼
            ┌────────────────────────┐      ┌────────────────────────┐
            │ Interactive SOC Web UI │      │ Multi-Page PDF Report  │
            │   (Chart.js & Dark)    │      │  (Forensics & Charts)  │
            └────────────────────────┘      └────────────────────────┘
```

---

## ✨ Key Features

- **100% Offline & Air-Gapped**: Zero external network calls. Designed specifically for classified, private, or restricted security operations environments.
- **Low-Memory Streaming Engine**: Memory-efficient generator streaming via `scapy.PcapReader`, preventing system memory exhaustion on multi-gigabyte captures.
- **4 Autonomous Forensic Engines**: Detects C2 beaconing heartbeats, high-entropy DNS tunneling, direct external IP connections without DNS resolution, non-standard backdoor ports, and mass data exfiltration.
- **Forensic File Integrity**: Automatically computes SHA-256 hashes, capture durations, packet totals, and data volumes.
- **Comprehensive Threat Scoring**: Evaluates multi-vector findings into a weighted 0–100 cyber threat index (`CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Automated IOC Extraction**: Extracts and unifies indicators of compromise (IP addresses, ports, apex domains, threat families) for instant SIEM/EDR export.
- **Interactive SOC Dark-Mode Dashboard**: Cyber-themed analyst interface with live charts (traffic timelines, protocol distributions, top talkers) and finding filters.
- **SOC Executive & Technical PDF Reports**: One-click generation of branded, publication-ready PDF incident reports with embedded charts and IOC tables.
- **Synthetic Multi-Vector Sample Generator**: Built-in Scapy generator to create synthetic malware PCAPs simulating Cobalt Strike, Metasploit, DNS tunneling, and RedLine Stealer attacks.

---

## 🔬 Multi-Vector Forensic Detection Engines

### 1. Command & Control (C2) Beaconing Detector
Malware frameworks (such as Cobalt Strike, Sliver, Brute Ratel, and Empire) frequently establish periodic callbacks to their teamservers. The C2 Beaconing Engine tracks flows grouped by `(Source IP, Destination IP, Destination Port, Protocol)`:
- Calculates intervals $\Delta t_i = t_{i} - t_{i-1}$ between consecutive outbound requests.
- Collapses sub-second retransmissions ($\Delta t < 0.2\text{s}$) into single logical transactions.
- Computes the mean interval $\mu = \frac{1}{N}\sum \Delta t_i$ and sample standard deviation $\sigma = \sqrt{\frac{1}{N-1}\sum (\Delta t_i - \mu)^2}$.
- **Flag Criteria**: Flow with $\ge 10$ outbound requests, mean interval between $5\text{s}$ and $600\text{s}$, and strict low jitter standard deviation $\sigma < 5.0\text{s}$.
- Low jitter confirms automated algorithmic heartbeats rather than human web browsing.

### 2. DNS Tunneling & Covert Channel Detector
DNS is typically permitted outbound through corporate firewalls, making it a prime vector for covert C2 communications and data theft (tools like iodine, dnscat2).
- **Shannon Entropy Analysis**: Calculates query character entropy:
  $$H(S) = - \sum_{i=1}^{k} P(c_i) \log_2 P(c_i)$$
  Legitimate domain names have low entropy ($H < 3.0$), while encrypted or Base64/Hex-encoded payloads exhibit high entropy ($H > 4.2$).
- **Subdomain Character Length**: Flags queries exceeding 40 characters in length.
- **Apex Domain Burst Frequency**: Identifies volume anomalies exceeding 100 queries/minute destined for the same root domain.

### 3. Suspicious Traffic & Threat Intelligence Engine
- **Direct IP Connections (No DNS)**: Legitimate client applications typically resolve hostnames via DNS prior to establishing TCP/UDP connections. Malware often hardcodes C2 IP addresses to bypass DNS sinkholing. The engine audits all outbound connections against observed DNS responses in the capture.
- **Malware & Backdoor Port Signatures**: Identifies communication over known adversary ports:
  - Port `4444` (Metasploit default reverse shell)
  - Port `1337` (Elite backdoor)
  - Port `5555` (Android ADB Trojan / exploit listener)
  - Port `6667` (IRC Botnet C2)
  - Port `9001` (Tor Exit Node / Custom TLS C2)
  - Port `31337` (Back Orifice legacy RAT)
- **Offline Curated Threat Intelligence**: Cross-references external endpoints against curated offline blacklists (Cobalt Strike teamservers, Emotet epoch listeners, Qakbot tier-1 nodes, Sliver listeners, RedLine Stealer drop endpoints).

### 4. Data Exfiltration Detector
Identifies large-volume data theft from internal subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) to external destinations:
- **Cumulative Thresholding**: Triggers when outbound data to an external IP exceeds 10 MB (configurable).
- **Traffic Asymmetry Ratio**: Evaluates upload-to-download byte ratios. An outbound ratio exceeding $5:1$ indicates data exfiltration rather than normal downloading/streaming.

---

## 🎯 Unified Threat Scoring & IOC Synthesis

PCAP Hunter evaluates detections across all four engines to produce a weighted composite **Threat Score** ranging from **0 to 100**:

| Threat Score | Threat Level | SOC Recommended Action |
|:---:|:---:|:---|
| **0 – 19** | `CLEAN` | Routine benign traffic. No malicious signatures identified. |
| **20 – 44** | `LOW` | Minor anomalies observed (e.g. uncommon ports or low-volume direct IPs). |
| **45 – 69** | `MEDIUM` | Multiple direct IP connections or elevated DNS query lengths. Monitor host. |
| **70 – 89** | `HIGH` | Verified C2 beaconing or offline threat intelligence match. Initiate containment. |
| **90 – 100** | `CRITICAL` | Active multi-vector compromise (e.g. Beaconing + Exfiltration + Known C2). Isolate host immediately. |

### Consolidated IOC Extraction
Every analysis compiles an actionable list of Indicators of Compromise (IOCs) including:
- Malicious & Target IP Addresses
- Contacted Ports and Transport Protocols
- Covert Apex Domains and Tunnels
- Associated Threat Actor / Malware Families (Cobalt Strike, Emotet, Qakbot, RedLine, etc.)

---

## 🖥️ Web Dashboard & SOC UI

PCAP Hunter features a responsive SOC command dashboard built with clean modern design aesthetics:

- **Executive KPI Cards**: Instant summary of Total Packets, Total Volume (MB), Capture Duration, Active Protocols, and Threat Level.
- **Threat Gauge Indicator**: Circular visual metric highlighting threat score severity with dynamic accent lighting.
- **Interactive Visual Forensics**:
  - **Traffic Over Time**: Chronological packet throughput graph.
  - **Protocol Distribution**: Visual breakdown of TCP, UDP, DNS, ICMP, and HTTPS traffic.
  - **Top Destinations**: Bar graph of the highest volume external endpoints.
- **Multi-Tab Findings Explorer**: Filter detections by C2 Beaconing, DNS Tunneling, Suspicious Traffic, and Data Exfiltration.
- **IOC Quick Export**: One-click download of all extracted IOCs in standardized JSON format.
- **Drag-and-Drop Capture Upload**: Seamless upload zone accepting `.pcap`, `.pcapng`, and `.cap` files up to 1 GB.
- **One-Click Built-in Malware Simulation**: Instant analysis trigger using the built-in synthetic test capture.

---

## 📄 Automated Incident PDF Reporting

Generate comprehensive, audit-compliant PDF incident reports with a single click:
- **Confidential SOC Header & Footer**: Branded styling with page numbering and confidentiality markings.
- **Forensics Capture Metadata**: SHA-256 integrity hash, packet counts, time windows, and analysis runtime.
- **Executive Threat Assessment**: Executive summary paragraph synthesized by the scoring engine.
- **High-Resolution Vector Charts**: Embedded throughput timeline, protocol distribution, and top target endpoints.
- **Engine-by-Engine Forensic Evidence**: Granular breakdown of intervals, entropy scores, and exfiltration volumes.
- **Structured IOC Summary Table**: Clear list of indicators ready for hand-off to forensics examiners and incident responders.

---

## 📂 Project Architecture

```
PCAPhunter/
├── app.py                         # Flask application & REST API controller
├── config.py                      # Global detection thresholds & system configuration
├── requirements.txt               # Project Python dependencies
├── .gitignore                     # Git isolation for captures, reports & secrets
├── core/
│   ├── __init__.py                # Core package initialization
│   ├── parser.py                  # Scapy streaming PCAP reader & metadata extractor
│   ├── pipeline.py                # Pipeline orchestrator & threat scoring logic
│   ├── engine_beaconing.py        # Engine 1: C2 beaconing statistical detector
│   ├── engine_dns_tunneling.py    # Engine 2: Shannon entropy & DNS tunnel detector
│   ├── engine_suspicious.py       # Engine 3: Threat intel & direct IP detector
│   └── engine_exfiltration.py     # Engine 4: Mass outbound data exfiltration detector
├── data/
│   ├── blacklist_ips.json         # Curated offline C2 & botnet threat intelligence
│   └── port_signatures.json       # Malware port database and service definitions
├── reports/
│   ├── __init__.py                # Reports package initialization
│   ├── chart_generator.py         # Matplotlib headless chart renderer
│   ├── pdf_generator.py           # FPDF2 SOC incident report generator
│   └── generated/                 # Generated PDF reports directory (runtime)
│       └── .gitkeep
├── samples/
│   ├── generate_sample_pcap.py    # Synthetic multi-vector attack PCAP builder
│   └── sample_malware.pcap        # Generated synthetic capture (auto-created)
├── static/
│   ├── css/
│   │   └── dashboard.css          # SOC cyber theme styling & animations
│   └── js/
│       ├── chart.min.js           # Chart.js library (bundled locally for offline use)
│       ├── charts.js              # Chart initialization & updates
│       └── dashboard.js           # Upload handlers, UI tabs, and API communication
├── templates/
│   └── index.html                 # Main dashboard Jinja2 HTML5 template
├── tests/
│   └── test_engines.py            # Unit and end-to-end integration test suite
└── uploads/                       # User uploaded PCAPs directory (runtime)
    └── .gitkeep
```

---

## 🚀 Installation & Quick Start

### 1. Prerequisites
- **Python**: Version 3.9, 3.10, 3.11, 3.12, or 3.13
- **Git**

### 2. Clone the Repository
```bash
git clone https://github.com/anas-himself/PCAP.git
cd PCAP
```

### 3. Create and Activate a Virtual Environment
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Launch PCAP Hunter
```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Synthetic Malware PCAP Generator

PCAP Hunter includes a synthetic malware generator (`samples/generate_sample_pcap.py`) that constructs an artificial, multi-vector attack capture with:
1. **Benign Traffic**: Real-world Google DNS lookups and HTTPS flows.
2. **Cobalt Strike C2 Beaconing**: 16 periodic connections spaced ~30 seconds apart ($\sigma < 0.35\text{s}$) to `198.51.100.45:8443`.
3. **DNS Tunneling**: 15 high-entropy Base64-like subdomains exceeding 50 characters query length.
4. **Direct IP Reverse Shell**: Metasploit payload connection to `45.154.255.88:4444` without prior DNS resolution.
5. **Data Exfiltration**: Outbound payload of ~10.65 MB sent over TCP port 8080 to `195.123.245.89`.

To generate or regenerate the sample PCAP manually:
```bash
python samples/generate_sample_pcap.py
```

*Note: If the sample is not present, `app.py` will automatically generate it on first execution.*

---

## 🧪 Running Automated Tests

A comprehensive test suite is provided in `tests/test_engines.py`, verifying:
- Shannon entropy mathematical correctness
- DNS tunneling detection thresholds
- C2 beaconing interval calculations and jitter bounds
- Data exfiltration volume calculations
- End-to-end pipeline execution with sample PCAP verification

Execute the test suite using Python's standard `unittest` framework:
```bash
python -m unittest tests/test_engines.py
```

Example output:
```text
.....
----------------------------------------------------------------------
Ran 5 tests in 6.427s

OK
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|:---:|:---|:---|
| `GET` | `/` | Serves the main Cyber SOC interactive dashboard |
| `GET` | `/health` | Returns application health status and confirms offline operational mode |
| `POST` | `/api/upload` | Uploads a `.pcap`, `.pcapng`, or `.cap` file (multipart form-data: `file`) and returns forensic analysis JSON |
| `GET` | `/api/sample` | Runs full forensic analysis on the built-in synthetic malware sample PCAP |
| `GET` | `/api/report/pdf` | Downloads the generated SOC Incident Report PDF for the latest analyzed capture |
| `GET` | `/api/export/ioc` | Exports extracted IOCs (IPs, domains, ports, malware families) in structured JSON format |

---

## 🔒 Security & Privacy Architecture

- **Air-Gapped Compliance**: The platform does not make outbound HTTP/HTTPS requests to external threat intelligence APIs, telemetry trackers, or cloud CDNs. All libraries (including Chart.js and fonts) are bundled locally.
- **Data Protection via `.gitignore`**:
  - Raw packet captures (`*.pcap`, `*.pcapng`, `*.cap`) are ignored to prevent accidental leaks of sensitive internal network dumps.
  - Uploaded captures in `uploads/` are isolated.
  - Generated incident reports in `reports/generated/` and temporary chart artifacts are strictly excluded from version control.
  - Environment variables, secrets, certificates (`*.pem`, `*.key`), and local credentials are protected.
- **Memory Safety**: Uses streaming packet iterators (`PcapReader`) rather than reading entire captures into RAM, safeguarding servers against out-of-memory denial-of-service conditions.

---

## ⚙️ Configuration & Tuning

Detection thresholds can be tuned in [config.py](config.py):

```python
# C2 Beaconing Thresholds
BEACON_MIN_CONNECTIONS = 10       # Minimum connections to evaluate interval statistics
BEACON_MIN_INTERVAL = 5.0         # 5 seconds minimum mean interval
BEACON_MAX_INTERVAL = 600.0       # 10 minutes maximum mean interval
BEACON_MAX_STD_DEV = 5.0          # Maximum standard deviation (jitter) in seconds

# DNS Tunneling Thresholds
DNS_TUNNEL_MIN_LENGTH = 40        # Flag if subdomain query length > 40 chars
DNS_TUNNEL_MIN_ENTROPY = 4.2      # Flag if Shannon entropy > 4.2
DNS_TUNNEL_BURST_RATE = 100       # Queries per minute to identical apex domain

# Data Exfiltration Thresholds
EXFIL_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB upload threshold
EXFIL_BURST_RATIO = 5.0                  # Upload to Download byte ratio > 5:1
```

---

## 📄 License & Attribution

This project is licensed under the **MIT License**.

Built for cybersecurity professionals, SOC tier 1-3 analysts, incident responders, and digital forensics investigators.

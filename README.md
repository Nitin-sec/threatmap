# ThreatMap Infra
Autonomous VAPT Orchestrator & Localized AI Triage Engine.

ThreatMap Infra is a modular security assessment suite designed to automate the end-to-end VAPT pipeline. It orchestrates industry-standard reconnaissance tools and leverages local Small Language Models (SLMs) to perform automated triage, risk assessment, and professional reporting.

## Key Features
- Multi-threaded reconnaissance and service discovery.
- Local-first AI triage using GGUF-based LLMs (No data exfiltration).
- Automated reporting engine (Professional XLSX/HTML outputs).
- Adaptive evasion logic and randomized fingerprinting.
- Modular architecture supporting Nmap, Nuclei, Nikto, and more.

## Installation

### Clone the repository
gh repo clone Nitin-sec/ThreatMap-Infra
cd ThreatMap-Infra

### Initial Setup
The included launcher handles environment creation and dependency resolution.
chmod +x run.sh
./run.sh

### AI Model Initialization
ThreatMap requires a local model for offline triage. Use the helper script to cache your preferred SLM.
python3 setup_slm.py          # Default: Qwen2.5-1.5B (~1.0GB)
python3 setup_slm.py --phi3   # Optional: Phi-3-mini (~2.2GB)

## Usage
Execute the primary launcher to start the interactive Metasploit-style interface.

./run.sh

### Target Specification
Provide a domain or IP range when prompted. The suite will ask for:
- Authorization Confirmation (Legal requirement)
- Scan Intensity (Balanced vs Aggressive)
- Subdomain Discovery (Subfinder/Assetfinder integration)

## Technical Architecture

The tool executes through five distinct phases:
1. Discovery: Subdomain enumeration and live-host validation.
2. Scanning: Parallelized port discovery and service fingerprinting.
3. Analysis: Rule-based and AI-enhanced vulnerability triage.
4. Persistence: Data normalization into a local SQLite state.
5. Synthesis: Generation of stakeholder-ready documentation.

## Requirements
The engine assumes the following binaries are present in your system PATH:
- nmap, nikto, gobuster, nuclei
- subfinder, assetfinder, httpx
- whatweb, wafw00f, sslscan

## Disclaimer
ThreatMap Infra is developed for authorized security testing and research purposes only. Unauthorized use of this tool against infrastructure without explicit written consent is illegal. The developer assumes no liability for misuse.

## License
MIT License.

# 👁️ Drishti OSINT Framework
**Advanced Attack Surface Mapping & Intelligence Broker**

![Drishti OSINT](https://img.shields.io/badge/Status-v1.0.0--Stable-emerald)
![Field](https://img.shields.io/badge/Field-Cybersecurity--Forensics-blue)
![License](https://img.shields.io/badge/License-MIT-gray)

```text
    ____       _     _     _   _      ____  ____ ___ _   _ _____ 
   |  _ \ _ __(_)___| |__ | |_(_)    / __ \/ ___|_ _| \ | |_   _|
   | | | | '__| / __| '_ \| __| |   | |  | \___ \| ||  \| | | |  
   | |_| | |  | \__ \ | | | |_| |   | |__| |___) | || |\  | | |  
   |____/|_|  |_|___/_| |_|\__|_|    \____/|____/___|_| \_| |_|
```

🚀 Overview
Drishti OSINT is a modular, high-performance reconnaissance framework designed for Digital Forensics and Attack Surface Management (ASM). Developed as a final-year project at VIT Bhopal University, it moves beyond basic API wrappers by implementing a dynamic "Intelligence Broker" that ensures data continuity even when third-party services are throttled or exhausted.

💎 The "Hit" Factors (Core Innovations)
Intelligence Broker Layer: A dynamic orchestrator that monitors API health and credit availability (Shodan, Censys, ZoomEye). It automatically pivots to the most reliable source in real-time to avoid "empty reports".

Active-Passive Hybrid Failover: If passive API credits are 0, the framework automatically triggers a Local Stealth Nmap Engine to identify active services without external reliance.

Multi-Engine Dorking (Bypassing 429): To evade aggressive Google rate-limiting, Drishti intelligently rotates between Google and DuckDuckGo dorking engines.

Forensic Persistence & Diffing: Results are stored in a local SQLite database with cryptographic timestamps, allowing researchers to track Attack Surface Evolution (what changed?) over time.

🛠️ Feature ModulesModuleIntelligence TypeSourcesInfrastructure Service & Port DiscoveryShodan, Censys, ZoomEye, Local NmapLeaks & Dorks Credential & Config LeaksGoogle Search, DuckDuckGo DorkingAsset Discovery Domain/Subdomain Mappingcrt.sh, HackerTarget, DNS Resolution

📦 Installation
1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/drishti-osint.git](https://github.com/YOUR_USERNAME/drishti-osint.git)
cd drishti-osint
```

2. Set Up Environment
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3. Configure Keys
Create a .env file in the root directory:

```Code snippet
SHODAN_API_KEY=your_key
CENSYS_ID=your_id
CENSYS_SECRET=your_secret
ZOOMEYE_API_KEY=your_key
```

📈 Risk Quantification Model
Drishti uses a Logarithmic Risk Scoring model to prioritize findings:

CRITICAL: Active CVEs on infrastructure or exposed .sql/.env database files.

HIGH: Open management ports (SSH/RDP) or exposed admin portals.

MEDIUM: Unencrypted protocols (HTTP, FTP) or directory indexing.

LOW: Informational findings such as new subdomains or SSL certificate details.

###🛡️ Security Disclaimer
This tool is for educational and authorized security auditing purposes only. The developer (Aryan Gupta) assumes no liability for misuse or damage caused by this tool. Always ensure you have explicit permission before scanning any infrastructure.

Developed by Aryan Gupta 4th Year B.Tech (Cybersecurity & Digital Forensics) VIT Bhopal University

# TryHackMe: Threat Intelligence Tools

Room URL: https://tryhackme.com/room/threatinteltools

---
# Threat Intelligence Overview

Threat Intelligence is the analysis of data and information using tools and techniques to generate meaningful patterns. It helps mitigate potential risks associated with existing or emerging threats targeting organizations, industries, sectors, or governments.

## Key Questions to Mitigate Risks
- **Who's attacking you?**
- **What's their motivation?**
- **What are their capabilities?**
- **What artefacts and indicators of compromise (IOCs) should you look out for?**

## Threat Intelligence Classifications

### 1. Strategic Intelligence
- High-level analysis of the organization's threat landscape.
- Identifies risk areas based on trends, patterns, and emerging threats.
- Supports business decision-making.

### 2. Technical Intelligence
- Focuses on evidence and artefacts of attacks used by adversaries.
- Helps Incident Response teams create a baseline attack surface.
- Supports the development of defense mechanisms.

### 3. Tactical Intelligence
- Assesses adversaries' tactics, techniques, and procedures (TTPs).
- Strengthens security controls.
- Addresses vulnerabilities through real-time investigations.

### 4. Operational Intelligence
- Analyzes specific motives and intent of adversaries.
- Helps understand which critical assets (people, processes, technologies) are targeted.
- Guides proactive security measures.

> **Note:** Threat Intel bridges the gap between the operational environment and the adversary to support better defense strategies.




---
# Threat Intelligence Tools
> **Note:**  
> This section below is a summarized version based on external resources and is **not directly sourced from the TryHackMe platform**.

## 🔍 Threat Intelligence Platforms (TIPs)
- **[MISP (Malware Information Sharing Platform)](https://www.misp-project.org/)** — Open-source platform for sharing indicators of compromise (IOCs).
- **[Anomali ThreatStream](https://www.anomali.com/products/threatstream)** — Aggregates threat data from multiple sources.
- **[ThreatConnect](https://threatconnect.com/)** — Combines threat intel with security operations and incident response (SOAR).
- **[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)** — Cloud-based threat intelligence sharing platform.
- **[Recorded Future](https://www.recordedfuture.com/)** — Combines machine learning with human analysis.

## 🛠 Threat Hunting and Analysis Tools
- **[Maltego](https://www.maltego.com/)** — Visual link analysis and data mining tool (great for OSINT and network mapping).
- **[Shodan](https://www.shodan.io/)** — Search engine for internet-connected devices.
- **[SpiderFoot](https://www.spiderfoot.net/)** — Automated OSINT collection and threat intel.
- **[Recon-ng](https://github.com/lanmaster53/recon-ng)** — Web reconnaissance framework written in Python.

## 📈 Security Information and Event Management (SIEM) Tools
- **[Splunk](https://www.splunk.com/)** — Popular SIEM platform enhanced with threat intel feeds.
- **[ELK Stack (Elasticsearch, Logstash, Kibana)](https://www.elastic.co/elk-stack)** — Open-source stack for logging and visualization.
- **[IBM QRadar](https://www.ibm.com/products/qradar-siem)** — SIEM platform that integrates with threat intel feeds.

## 🔒 Malware Analysis Tools
- **[Cuckoo Sandbox](https://cuckoosandbox.org/)** — Automated malware analysis system.
- **[Any.Run](https://any.run/)** — Interactive malware sandbox.
- **[VirusTotal](https://www.virustotal.com/)** — Scans files and URLs for viruses and malicious content (community-powered intelligence).

## 🌎 Open-Source Threat Intelligence Feeds
- **[AlienVault OTX (Open Threat Exchange)](https://otx.alienvault.com/)** — Free platform to share and receive threat intel.
- **[AbuseIPDB](https://www.abuseipdb.com/)** — Database of reported malicious IP addresses.
- **[VirusShare](https://virusshare.com/)** — Large collection of malware samples for research.

## 🤖 Automation & Enrichment Tools
- **[TheHive](https://thehive-project.org/)** — Open-source incident response platform.
- **[Cortex](https://www.thehive-project.org/projects/cortex/)** — Connects with TheHive to automate threat intel enrichment.
- **[OpenCTI (Open Cyber Threat Intelligence)](https://www.opencti.io/)** — Open-source platform for managing threat intel.

> **Pro Tip**: Most real-world setups combine multiple tools — like using MISP for threat sharing, Maltego for mapping, and Splunk for monitoring — for a complete 360° threat view.

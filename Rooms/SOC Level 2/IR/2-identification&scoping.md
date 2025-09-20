# TryHackMe: Identification & Scoping Summary

Room Url: https://tryhackme.com/room/identificationandscoping

## Identification

### **The Identification Phase of Incident Response**

The core message is that successful identification of security incidents depends on a balanced integration of **People, Process, and Technology**.

- **Technology's Role:** Provides the essential tools (like EDR, IDPS, and SIEM systems) to generate **Security Alerts** or **Event Notifications** that signal potential threats.
- **People's Role:** It is the responsibility of **all employees**, not just the security team, to be vigilant. They must be able to interpret alerts and report any anomalies through proper channels.
- **Process's Role:** Well-defined **procedures** are the glue that holds it all together. They ensure that when an alert is generated or an anomaly is spotted, the right people are notified with the correct information, enabling a swift and effective response.

This phase is supported by a **top-down culture of continuous learning and vigilance**, where management prioritizes cybersecurity training and clear policies. Ultimately, identification is the critical trigger that sets the entire Incident Response Process in motion, and its success hinges on this triad working in concert.

## Socping

### **The Scoping Phase of Incident Response**

Following the identification of an incident, the next critical step is **Scoping**. This phase is dedicated to understanding the full extent of the security breach by determining which systems are affected, what data is at risk, and the potential impact on the organization. Effective scoping is essential for formulating a targeted mitigation strategy.

Scoping is powered by two indispensable tools that provide context and accelerate the response:

1. **Asset Inventory:** This is a comprehensive list of all organizational assets (servers, workstations, etc.), detailing their name, IP address, operating system, and owner. It acts as a quick reference to rapidly identify and assess what specific equipment and data might be compromised.
    
    
    | **Asset Type** | **Asset Name** | **IP Address** | **Operating System** | **Owner** |
    | --- | --- | --- | --- | --- |
    | Domain Controller | DC-01 | 172.16.1.10 | Windows Server 2019 | Derick Marshall |
    | Mail Server | MAILSVR-01 | 172.16.1.15 | Windows Server 2019 | Stan Simon |
    | Web Server | WEBSVR-01 | 172.16.1.110 | Ubuntu Server 20.04 | Damian Hall |
    | Proxy Server | PROXY-01 | 172.16.1.119 | Windows Server 2019 | Stan Simon |
2. **Spreadsheet of Doom (SoD):** This is a dynamic, centralized list of **Indicators of Compromise (IoCs)** such as malicious IP addresses, domains, and file hashes. Each IoC is enriched with context like the threat type and its source. The SoD is more than a list; it's a vital resource for:
    - Quickly understanding the nature of the threat.
    - Streamlining team communication.
    - Tracking recurring threats and attack patterns.
    - Enabling a proactive and intelligence-driven response.

Together, these tools allow incident responders to efficiently correlate evidence against known assets and threats, providing a comprehensive overview of the incident's scope at a glance.

| **Indicator Type** | **Indicator** | **Threat Type** | **Source** |
| --- | --- | --- | --- |
| IP Address | 188.40.75.132 | Malware Hosting | AlienVault OTX |
| Domain | b24b-158-62-19-6.ngrok-free.app | Phishing domain | Ticket#2023012398704232 |
| Email address | alex.swift@swiftspend.finance | Spoofed email | Ticket#2023012398704232 |
| Email address | mike.ascot@swiftspend.finance | Spoofed email | Ticket#2023012398704232 |

## **The Intelligence-Driven Feedback Loop**

The **Identification and Scoping** phases are not a one-time, linear process but form a continuous, **intelligence-driven feedback loop**. This cyclical process ensures the understanding of an incident is constantly refined and expanded as new information is uncovered.

The loop consists of five key stages:

1. **Event Notification:** The loop is triggered by an initial report or alert of a potential issue.
2. **Documentation:** All known details about the incident are meticulously recorded, creating a foundation for the investigation.
3. **Evidence Collection:** Data is gathered from logs, network traffic, and other sources to find evidence of the incident.
4. **Artefact Identification:** The collected evidence is analyzed to identify specific artefacts (IoC's, patterns, etc.) that reveal clues about the threat.
5. **Pivot Point Discovery:** These artefacts lead to new questions and areas of investigation ("pivot points"), which send the process back to the **Documentation** step to incorporate the new findings and begin the loop again.

<img width="1140" height="800" alt="image" src="https://github.com/user-attachments/assets/106eaae4-3fec-4ce3-a8cc-29a583992956" />

**The Power of the Loop:**

This iterative approach transforms incident response from reactive to **proactive and dynamic**. By leveraging real-time data, historical context, and shared knowledge, the loop:

- Continuously adds context and deepens the understanding of the incident.
- Facilitates ongoing learning and information sharing within the team.
- Ensures a more efficient and effective response.
- Helps organizations comply with legal and data protection obligations by ensuring a thorough investigation.

# TryHackMe - Threat Intel & Containment Room Summary


### **TryHackMe - Threat Intel & Containment Room**

This room focuses on the critical steps immediately after an incident is confirmed: using intelligence to understand your adversary and taking swift action to limit their damage.

### **Part 1: Threat Intelligence (The "Brain")**

The room emphasizes that containment must be **intelligence-driven**. You can't effectively stop an attacker if you don't know who they are or what they want.

- **Goal:** Understand the adversary's goals, tools, and methods to predict their next move and tailor your response.
- **Key Concepts:**
    - **Indicators of Compromise (IOCs):** You learn to gather specific artifacts like malicious IP addresses, domain names, file hashes (MD5, SHA-256), and suspicious registry keys. These are the "fingerprints" of the attack.
    - **Tactics, Techniques, and Procedures (TTPs):** This is the more strategic level. Instead of just blocking one bad IP, you learn to understand the *behavior*—e.g., the attacker uses PowerShell for lateral movement (Technique T1059.001) or credential dumping (Technique T1003).
    - **Threat Actor Identification:** The room might introduce frameworks like **MITRE ATT&CK®**, which helps categorize TTPs and understand the entire attack lifecycle. You learn to map the discovered IOCs and TTPs to known threat actor groups or malware families.

### **Part 2: Containment (The "Brawn")**

Containment is about **isolating the threat to prevent further damage** while you prepare for eradication. The room highlights that strategies are not one-size-fits-all; they are a trade-off between completely stopping the attacker and preserving evidence.

- **Goal: Limit the attacker's reach and prevent further damage to systems and data.**
- **Containment Strategies:**
    1. **Network Containment:** This is the most common first step.
        - **Quarantine a Host:** Disable the network port or move the endpoint to a isolated VLAN.
        - **Block IOCs:** Use firewalls and security tools to block the malicious IPs, domains, and hashes identified during the intel phase.
        - **Segment the Network:** Prevent lateral movement by isolating critical network segments.
    2. **Host-Based Containment:** Actions taken directly on the infected system.
        - **Disable Accounts:** Immediately disable compromised user or service accounts.
        - **Isolate from Network:** Turn off Wi-Fi/unplug the network cable.
        - **Stop Processes:** Kill malicious running processes identified during scoping.
- **The Key Trade-off:**
    
    The room will stress a critical dilemma: **Aggressive containment (like pulling the plug) alerts the attacker and might cause them to destroy evidence. Less aggressive containment (like blocking a single C2 domain) allows you to monitor their activity but risks them finding another way out.** The choice depends on the business impact and your intelligence about the attacker's goals.
    

### **How It Fits with the Previous Summaries:**

- **Scoping is Prerequisite:** You cannot do effective Threat Intel & Containment without first scoping the incident. The IOCs and TTPs you use here are discovered during the scoping phase.
- **Leads to Eradication:** Successful containment creates a controlled environment where you can safely plan and execute your eradication (e.g., cleaning a host or rebuilding it) without the attacker fighting back in real-time.
- **Informs Remediation:** The TTPs you discover directly inform your long-term remediation plan (e.g., "The attacker used Pass-the-Hash, so we need to implement stronger credential hardening").

**Overall Room Objective:** To teach you that containment is not a panicked reaction. It is a strategic decision based on evidence and intelligence. You learn to balance the need to stop the bleeding with the need to gather evidence and avoid alerting the adversary, all while setting the stage for the next phases of the response.

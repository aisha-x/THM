# TryHackMe -Preparation Room Summary

Room Url: https://tryhackme.com/room/preparation

### **TryHackMe - Preparation Room**

This room establishes a critical principle: **You cannot effectively respond to an incident you are not prepared for.** The Preparation phase is about building the foundation—the tools, plans, and permissions—*before* an incident occurs, turning a potential chaotic reaction into a managed process.

### **Key Learning Objectives of the Room:**

The room is designed to teach you that preparation is split into two main areas: **Building the Foundation** and **Gathering the Tools.**

**1. Building the Foundation: The IR Framework & Plans**

- **Adopting an IR Framework:** You are introduced to established frameworks like **NIST SP 800-61** (Computer Security Incident Handling Guide) or the **SANS Incident Handler's Handbook**. These provide a structured, phased approach (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) that ensures a comprehensive response.
- **Developing an Incident Response Plan (IRP):** This is the core document. The room covers the essential components of an IRP:
    - **Team Roles & Responsibilities:** Who is on the CSIRT (Computer Security Incident Response Team)? What does each person (Lead, Analyst, Communications Liaison, Management) do?
    - **Communication Plan:** How will the team communicate securely during an incident? Who is responsible for communicating with management, law enforcement, or the public?
    - **Escalation Paths:** What defines a "severe" incident? Who needs to be notified and when?
- **Getting Legal & Management Buy-in:** The room emphasizes that without pre-approved **policies and procedures**, your response will be hamstrung. This includes:
    - **Rules of Engagement (RoE):** What are you allowed to do during an investigation? (e.g., Are you permitted to probe attacker systems?).
    - **Acceptable Use Policy (AUP):** Defining what "normal" use is, which helps in identifying "abnormal" malicious activity.

**2. Gathering the Tools: Visibility is Key**

You can't investigate what you can't see. This section focuses on pre-deploying the necessary tools for visibility and evidence collection.

- **Endpoint Visibility:** The importance of having a centralized logging system and agents deployed *before* an incident.
    - **EDR (Endpoint Detection & Response) / AV (Antivirus):** Tools for monitoring, detecting, and sometimes containing malicious activity on hosts.
    - **Host-Based Logging:** Ensuring critical logs (Windows Event Logs, Sysmon, Linux auditd) are enabled and being collected by a SIEM.
- **Network Visibility:** Tools to see what's happening on the wire.
    - **SIEM (Security Information and Event Management):** A central platform for aggregating and correlating logs from all over the environment (e.g., Splunk, Elastic Stack).
    - **Network Monitoring:** The use of tools like Wireshark, Zeek (formerly Bro), or Argus for packet and flow analysis.
    - **NetFlow/IPFIX Data:** For understanding network traffic patterns and identifying anomalies.
- **Forensic Readiness:** Preparing the tools needed to collect evidence without altering it.
    - **Forensic Toolkits:** Having trusted software ready to go (e.g., FTK Imager, Autopsy, Velociraptor).
    - **Write-Blockers:** Understanding the importance of preserving evidence integrity.

**3. The Human Element: Training and Testing**

A plan is useless if no one knows how to execute it. The room concludes that preparation is an ongoing process.

- **Tabletop Exercises:** Running simulated incidents with the team to walk through the IRP, identify gaps, and improve communication.
- **Continuous Training:** Keeping skills sharp and staying updated on the latest threats and TTPs (Tactics, Techniques, and Procedures).

**Overall Room Objective:** To move from a reactive, ad-hoc mindset to a proactive, prepared one. By the end, you understand that the goal of the Preparation phase is to have a **tested plan, a skilled team, and the right tools already in place**, dramatically increasing the chances of a successful response when a real incident strikes.

# TryHackMe: IR Playbooks Room Summary

Room Link: https://tryhackme.com/room/irplaybooks

# The Incident Response Documentation Universe

The text explains how mature organizations, particularly Security Operations Centers (SOCs), use structured processes to handle security incidents efficiently and consistently.

**Core Concept:** As organizations mature, they document expected scenarios and the steps to handle them. In a SOC, this primarily governs how to respond to security alerts.

**1. The Incident Response (IR) Process:**

This is the high-level, governing process for handling incidents. It defines the overall framework but not the detailed steps. Its key components include:

- A **RACI matrix** for roles and responsibilities.
- An **escalation matrix** for management communication.
- A **severity matrix** for classifying incidents.
- General **procedures for handling crises**.
    
    The IR process ensures the organization is prepared and provides confidence, even if deviations are sometimes necessary.
    

**2. The Need for Playbooks:**

Playbooks provide the **granular detail** that the high-level IR process lacks. They are needed to avoid conflicts and ambiguity during a crisis by specifying exact, repeatable steps for different alert types (e.g., a separate playbook for phishing, malware, ransomware).

<img width="1140" height="500" alt="image" src="https://github.com/user-attachments/assets/62d8f439-6726-499a-b267-fd449951faf4" />

**3. Relationship with Use Cases:**

- **Use cases** are automated queries that sift through vast amounts of data to **flag suspicious activity** for investigation.
- **Playbooks** are the guides that tell an analyst **what to do** once a use case triggers an alert.
- The relationship is **one-to-many**: Multiple use cases can map to a single playbook (e.g., different malware detection use cases all trigger the "Malware Response" playbook).


<img width="1140" height="550" alt="image" src="https://github.com/user-attachments/assets/ea348ab7-b4cc-462e-b599-18edf9190bdd" />

**4. Automating Playbooks:**

- Playbooks, with their defined, repeatable steps, are the perfect foundation for automation.
- Organizations use **SOAR platforms** to automate parts or all of a playbook, reducing analyst workload and alert fatigue.
- The level of automation varies by organization, but well-defined playbooks are the essential first step toward it.

**Conclusion:**

Together, IR processes, use cases, and playbooks create a consistent, unambiguous, and efficient SOC operation. They ensure analysts know what to do, produce reliable output, and identify opportunities for automation to make their jobs easier.

# IR Process and Playbooks: Preparation

This section explains that while the "Preparation" stage is the first step of the IR process, it is not typically a step within a playbook itself. Instead, preparation is addressed as a set of **prerequisites** that must be in place *before* a playbook can be effectively used.

**Key Points:**

- **Purpose of Prerequisites:** They ensure the SOC has the capability to detect, investigate, and respond to an incident. Without these foundational elements, a playbook cannot be triggered or followed.
- **General Prerequisites:** These are the basic requirements for any playbook and include:
    - **Logging:** Relevant logs must be integrated into the SIEM.
    - **Parsing:** Logs must be properly parsed with necessary fields (IPs, usernames, process names, etc.) extracted and searchable.
    - **Use Cases:** Specific detection use cases must be created to flag the behavior the playbook is designed to respond to.
    - **Security Controls:** Recommended security controls (like blocking or quarantining) must be deployed and represent organizational policy.

**Examples of Playbook-Specific Prerequisites:**

The text provides templates for two specific types of playbooks:

1. **Phishing Playbook Prerequisites:**
    - **Relevant Logs:** Email gateway logs.
    - **Required Fields:** Sender, recipient, subject, URLs, attachment hashes.
    - **Example Use Cases:** Detection of known malicious hashes, suspicious sender domains, or credential harvesting URLs.
    - **Recommended Controls:** Ability to block emails, quarantine attachments, and delete messages from inboxes.
2. **Malware Playbook Prerequisites:**
    - **Relevant Logs:** EDR, Sysmon, Windows Event, and network logs.
    - **Required Fields:** Process names/IDs, hashes, command line parameters.
    - **Example Use Cases:** Detection of suspicious parent-child process relationships or suspicious network activity.
    - **Recommended Controls:** Malware quarantine, shellcode blocking, and exploit prevention.

**Conclusion:** The prerequisites section of a playbook is where the "Preparation" phase is documented. It lists all the necessary data, detections, and tools that must be operational for the subsequent response steps in the playbook to be executable. These prerequisites are customizable based on an organization's specific requirements and security policies.

# IR Process and Playbooks: Detection and Analysis

This section details how playbooks provide granular, step-by-step instructions for the "Detection and Analysis" stage of the Incident Response (IR) process, which begins once an alert is triggered.

**Key Components of this Stage in a Playbook:**

1. **Workflow Diagrams:** Playbooks often start with a visual workflow diagram that outlines the entire process from alert to escalation or closure. This provides analysts with a clear, high-level overview of the steps they need to follow.
    
<img width="1140" height="570" alt="image" src="https://github.com/user-attachments/assets/763ea196-85e5-4c22-81f1-61aac035898b" />
    
2. **General Checklist:** The core actions for Detection & Analysis can be summarized in a checklist:
    - **Alert Trigger:** The starting point of the process.
    - **Initial Verification:** Examining the raw log data.
    - **IOC Verification:** Checking indicators of compromise (hashes, IPs, domains) against threat intelligence sources (OSINT, internal docs).
    - **Context Analysis:** Investigating metadata (parent processes, command lines, domain age) to understand the full context of the alert.
    - **Decision:** Based on the findings, the analyst decides to either close the incident (false positive) or escalate it for containment.

**Practical Examples:**

The text provides specific steps for two types of incidents:

**A. Phishing Playbook Example:**

- **Detection (Trigger):** Alerts can come from automated use cases (e.g., email from a newly created domain, known malicious link) or from user reports. Multiple use cases feed into a single phishing playbook.
- **Analysis (Steps):**
    - Identify sender, recipient, and gather context from the email.
    - Extract all artifacts: URLs, attachments, QR codes.
    - Check the reputation of sender details and all extracted artifacts on threat intelligence platforms (VirusTotal, etc.).
    - Check if URLs lead to credential phishing platforms.
    - Hunt for suspicious logins from the recipients to see if anyone fell for the phish.
    - Decide: Phishing (escalate) or Clean (close).

**B. Malware Playbook Example:**

- **Detection (Trigger):** Use cases like an EDR flagging a process, a suspicious file executing from a temp directory, or a browser launching a script engine.
- **Analysis (Steps):**
    - Identify the triggering process and check its hash for a reputation.
    - **Important:** Avoid uploading sensitive files to public platforms without management approval.
    - Analyze any files that triggered the process (e.g., a Word document).
    - Investigate the parent process chain.
    - Determine the initial infection vector (download, email) and trigger other playbooks (e.g., phishing) if needed.
    - Execute in a private sandbox to understand behavior.
    - **Preserve evidence** (memory, disk images) and perform forensic analysis.
    - Conduct a threat hunt to find other potentially affected machines in the network.
    - Decide: False Positive (close) or True Positive (escalate).

**Conclusion:** The Detection and Analysis phase of a playbook transforms a generic alert into a verified incident through a detailed, repeatable process of investigation, evidence collection, and context building, leading to a critical decision on whether to escalate or close the case.

# IR Process and Playbooks: Containment, Eradication, and Recovery

This section covers the final active stages of the Incident Response process, which are triggered only after an incident has been confirmed as a **True Positive** during the Analysis phase.

**Key Points:**

- **Escalation Process:** Typically, an L1 analyst performs initial triage (Detection & Analysis). If a True Positive is found, it is escalated to an L2 analyst who executes the Containment, Eradication, and Recovery steps, often with support from L3 analysts for advanced forensic or malware analysis.
- **Objective:** The goal of this phase is to **limit and reverse** the impact of the incident, restoring normal operations securely.

**General Checklist for this Phase:**

1. Identify the root cause.
2. Identify the impact and all affected assets.
3. **Contain:** Isolate assets and limit connectivity to prevent further damage.
4. **Eradicate:** Remove the threat from the affected assets.
5. **Recover:** Restore assets to a known good configuration and resume services.

**Practical Examples:**

**A. Phishing Playbook Example:**

- **Containment:**
    - Extract IOCs (IPs, domains, hashes) from the email.
    - Block the sender, domains, IPs on the email gateway.
    - Block malicious file hashes on the EDR and URLs on the web proxy.
- **Eradication:**
    - Delete the phishing email from all user inboxes.
    - For users who interacted with the email: isolate their machine, reset their credentials, and initiate the malware playbook if an attachment was opened.
- **Recovery:**
    - Reset passwords and ensure MFA is enabled for affected accounts.
    - Audit user account activity for suspicious actions.
    - Reimage any compromised machines.

**B. Malware Playbook Example:**

- **Containment:**
    - Immediately isolate infected systems from the network.
    - Revoke active sessions on those systems.
    - Block communication to known malicious C2 servers.
- **Eradication:**
    - Terminate malicious processes.
    - Delete malicious files.
    - Reimage severely compromised systems.
    - Perform a full antivirus/EDR scan.
    - Reset credentials for affected user accounts.
- **Recovery:**
    - Enable MFA and enforce strong passwords (especially critical after infostealer malware).
    - Audit and revert any changes made by the malware (e.g., in databases or files).
    - Restore systems to a known good state and resume services.

**Conclusion:** The Containment, Eradication, and Recovery phase involves decisive action to stop an attack, remove its presence, and safely restore business operations. These phases are often grouped together due to their overlapping nature. Playbooks provide the critical, pre-defined steps to ensure this is done consistently and effectively, minimizing business impact.

# IR Process and Playbooks: Post-Incident Activity

<img width="1140" height="497" alt="image" src="https://github.com/user-attachments/assets/19e188d8-0715-49ab-9ea6-508b9d12100c" />

**Core Concept:** Post-Incident Activity is the final, crucial stage of the IR process focused on **learning from the incident** to improve future security posture. It is a process of continuous improvement.

**Key Characteristics:**

- **Not in Playbooks:** This phase is highly subjective and varies greatly depending on the incident type, organizational dynamics, and identified gaps. Therefore, it is **not included in detailed playbooks**.
- **Guided by the IR Plan:** Instead, it is governed by **broad guidelines outlined in the high-level Incident Response (IR) Plan**.
- **Scope:** Organizations often conduct formal post-incident activities only for **high and critical-severity incidents**.

**Primary Goals (The Questions It Answers):**

The phase is designed to answer key improvement-oriented questions:

- **Root Cause:** Why did the incident happen? (e.g., using the "5 Whys" technique).
- **Identified Gaps:** What vulnerabilities in people, processes, or technology could have been prevented the incident?
- **Future Improvement:** How can we improve our People, Processes, and Technology to prevent future occurrences?
- **Impact Mitigation:** What steps could have minimized the incident's impact?

**Conclusion:** While not a step in a tactical playbook, the Post-Incident Activity phase is essential for transforming a security incident from a one-time event into a valuable learning experience. It ensures the organization adapts and strengthens its defenses against future threats. A playbook may simply refer the analyst to the organization's IR plan to initiate this process after an incident is resolved

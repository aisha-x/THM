# TryHackMe: Intro to Threat Emulation Summary

Room url: https://tryhackme.com/room/threatemulationintro

## **Threat Emulation**

**Core Purpose:** Threat emulation is a security practice designed to help organizations understand and improve their security defenses by safely mimicking the tactics, techniques, and procedures (TTPs) of real-world adversaries in a controlled environment. This provides an attacker's perspective without the risk of a real attack, ensuring the organization is better prepared.

---

### **The Problem with Traditional Security Assessments**

The text outlines why common assessments like Vulnerability Assessments, Penetration Tests, and Red Teaming are insufficient on their own:

- They often don't replicate **real-world, multi-stage attack cycles**.
- They can create a lack of cooperation and knowledge sharing between offensive (Red) and defensive (Blue) teams.

**Threat emulation is presented as the solution to these challenges.**

---

### **Emulation vs. Simulation**

- **Threat Emulation:** An **intelligence-driven** effort to **exactly impersonate** the specific TTPs of a real-world adversary or threat group (e.g., mimicking a known ransomware group's exact attack chain). It's about behaving *as* the adversary.
- **Threat Simulation:** Uses **predefined, automated attack patterns** that *represent* general adversary behavior but are not an exact imitation of a specific threat actor.

---

### **Key Characteristics of Threat Emulation**

Threat emulation is defined by several key concepts:

1. **Real-World Threats:** Based on actual breaches and threat intelligence (e.g., MITRE ATT&CK framework).
2. **Behaviour-Focused:** Aims to improve defenses against adversarial behaviors, not just specific malware signatures.
3. **Transparency & Collaboration:** Encourages knowledge sharing between Red and Blue teams to improve security holistically (also known as **Purple Teaming**).
4. **Repeatable:** Exercises and specific TTPs can be automated for continuous testing.
    
    <img width="920" height="560" alt="image" src="https://github.com/user-attachments/assets/bcdd888e-16b6-4fb3-9f6d-a0f254dd7c42" />

    

---

### **Applications and Benefits**

Threat emulation exercises are used for:

- **Assessment & Improvement:** Testing people, processes, and technology.
- **Capability Development:** Building and refining security tools and analytics.
- **Professional Development:** Breaking down barriers between teams and fostering collaboration and knowledge sharing.

In essence, threat emulation provides vital, actionable insights for an organization to effectively protect itself against sophisticated attacks.

---

## Threat emulation methodologies

Threat emulation methodologies are structured strategies used to simulate real-world cyber attacks in order to discover weaknesses in an organization's security defenses. The key takeaway is that these methodologies can be used individually or combined to create a comprehensive emulation plan.

---

### **Key Methodologies Explained:**

**1. [MITRE ATT&CK](https://tryhackme.com/room/mitre)**

- **What it is:** A globally recognized **knowledge base and framework** that catalogs the Tactics, Techniques, and Procedures (TTPs) used by real adversaries.
- **How it's used:** It serves as a common language and foundation for planning emulation exercises. The **ATT&CK Navigator** tool helps visualize and plan which specific techniques to emulate.
- **Purpose:** Provides a structured way to describe adversarial behavior and align emulation activities with real-world threats.

<img width="2048" height="764" alt="image" src="https://github.com/user-attachments/assets/49b52630-1768-45d0-a319-752ea6de9971" />


**2. [Atomic Testing (Atomic Red Team)](https://github.com/redcanaryco/atomic-red-team)**

- **What it is:** A **library of small, focused tests** ("atomics") designed to test specific security controls.
- **How it's used:** Teams can execute these pre-built tests to generate malicious activity and see if their defenses (like antivirus or EDR) detect them. Each test is **mapped to the MITRE ATT&CK framework**.
- **Purpose:** Offers a quick, repeatable, and automated way to validate defenses against specific, individual adversary techniques.

<img width="548" height="449" alt="image" src="https://github.com/user-attachments/assets/870afc97-97e6-450e-acdc-f9d0036eadcf" />

**3. [TIBER-EU Framework](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html)**

- **What it is:** A **formal, European framework** for conducting intelligence-led red team tests on critical live systems (e.g., in the financial sector).
- **How it's used:** It's a rigorous, three-phase process:
    - **Preparation:** Establishing scope, teams, and getting formal approval.
    - **Testing:** The Threat Intel team provides a report on realistic threats, which the Red Team uses to craft attacks. The Blue Team defends and assesses their performance.
    - **Closure:** Reporting findings and planning remediation.
- **Purpose:** Provides a standardized, high-assurance guideline for large-scale, controlled adversary emulation to improve cyber resilience.

<img width="920" height="300" alt="image" src="https://github.com/user-attachments/assets/8acc0a77-550d-405a-b9c1-18bea6ee83e1" />


**4. [CTID Adversary Emulation Library](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/)**

- **What it is:** An **open-source library of detailed emulation plans** developed by the Center for Threat-Informed Defense (MITRE Engenuity).
- **How it's used:** Offers two approaches:
    - **Full Emulation:** Comprehensive plans that mimic a specific threat group (e.g., APT29) from start to finish.
    - **Micro Emulation:** Focused plans that test a specific technique (e.g., process injection) used by many adversaries.
- **Purpose:** Gives organizations a head start by providing ready-to-use, intelligence-driven plans to test their defenses against known advanced threats.

---

## **Threat Emulation Process**

This process is a structured, iterative method for planning and executing a realistic cyber attack simulation to test and improve an organization's defenses.

---

### **The 5-Step Process:**

**1. Define Objectives**

- **Purpose:** To ensure the exercise is focused and measurable.
- **Example (VASEPY Corp):** The objective is to identify security gaps related to **credit card fraud and ransomware attacks**, specific threats to the retail industry.

**2. Research Adversary TTPs**

- **Purpose:** To accurately model the behavior of a real-world threat group.
- This phase involves four sub-steps:
    1. **Information Gathering:** Consult internal teams (CTI, SOC, sysadmins) and external threat reports to identify relevant threat groups. For VASEPY, this led to a shortlist of financially motivated groups like **FIN6, FIN7, and FIN8**.
    2. **Select the Adversary:** Choose the most relevant group based on:
        - **Relevance** to business goals and geography.
        - **Available Threat Intelligence** (CTI) on the group's TTPs.
        - **TTP Complexity** and **Available Resources** (time, budget, tools).
        - For VASEPY, **FIN7** was selected.
    3. **Select Specific TTPs:** Use frameworks like **MITRE ATT&CK Navigator** to visualize and choose which specific techniques (e.g., spear phishing) to emulate.
        
        <img width="2048" height="906" alt="image" src="https://github.com/user-attachments/assets/0e1dedc8-2e78-4081-8cef-3b8783849b34" />
        
    4. **Construct a TTP Outline:** Create a scenario that details how the selected TTPs will be implemented during the exercise. For example: 
        
        <img width="2048" height="646" alt="image" src="https://github.com/user-attachments/assets/2766b3ad-74d1-4c23-81ee-eece6e5cd795" />


**3. Plan the Engagement**

- **Purpose:** To avoid risks like data loss or system downtime and ensure the exercise is safe and authorized.
- A formal **Threat Emulation Plan** must include:
    - **Clear Objectives and Scope** (what/who is being tested).
    - A detailed **Schedule**.
    - **Rules of Engagement** (defining acceptable attack behaviors).
    - **Explicit Permission** from leadership.
    - A **Communication Plan** for all involved teams (Red, Blue, executives).

**4. Conduct the Emulation**

- **Purpose:** To execute the attack simulation in a controlled manner.
- This involves:
    - **Setting up a Lab Environment** with attack, analysis, and test systems.
    - **Implementation:** Technically executing the planned TTPs. For the [FIN7](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/fin7/Emulation_Plan/Scenario_1#step-1---initial-breach-evaluations-step-11) example, this meant creating and delivering a malicious RTF file via a spear-phishing email.
    - **Detection & Mitigation:** The Blue Team uses security tools (logs, EDR, etc.) to try to detect the attack. This is a collaborative effort to improve defenses.

**5. Conclude and Report**

- **Purpose:** To document the results and provide actionable recommendations.
- This final phase involves:
    - **Observing Results:** The Blue Team analyses artefacts (logs, network traffic) to see if the attack was successful, blocked, or detected.
    - **Documenting & Reporting:** Creating a formal report that details the procedures, findings, impact, and, most importantly, **recommendations** for improving security controls, policies, and training.

This end-to-end process ensures that threat emulation is a valuable, repeatable exercise that tangibly improves an organization's security posture.

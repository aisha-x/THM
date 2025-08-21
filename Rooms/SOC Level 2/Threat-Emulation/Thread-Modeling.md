# TryHackMe: Threat Modeling Summary

Room Link: https://tryhackme.com/room/threatmodelling

**Learning Objectives:**

- Significance of threat modelling in building an organisation's resiliency from threats.
- Fundamentals of modelling a significant threat applicable to your organisation for emulation purposes.
- Learn different threat modelling frameworks like MITRE ATT&CK, DREAD, STRIDE and PASTA.

## **What is Threat Modelling?**

Threat modelling is a **proactive and systematic process** used to identify, prioritize, and address potential security threats to an organization's systems and applications. It involves simulating attack scenarios to find vulnerabilities, enabling the organization to build stronger defences and allocate security resources effectively.

---

### **Key Concepts: Threat, Vulnerability, and Risk**

These three concepts are the foundation of threat modelling:

- **Threat:** A potential event or actor that can cause harm (e.g., a hacker, a natural disaster).
- **Vulnerability:** A weakness or flaw that a threat can exploit (e.g., a software bug, a misconfigured server).
- **Risk:** The potential for loss or damage when a threat successfully exploits a vulnerability. It combines the likelihood of an attack and its potential impact.

---

### **The High-Level Process**

Threat modelling typically follows these steps:

1. **Define Scope:** Decide which systems, apps, or networks to analyze.
2. **Identify Assets:** Pinpoint and diagram important components (e.g., servers, data) and classify them based on value.
3. **Identify Threats:** Brainstorm potential threats that could target those assets.
4. **Analyze & Prioritize:** Find vulnerabilities, assess the risks, and rank them based on likelihood and impact.
5. **Implement Countermeasures:** Develop and deploy security controls to mitigate the highest-priority risks.
6. **Monitor & Evaluate:** Continuously check if the countermeasures are working and track progress.

---

### **Collaboration is Crucial**

Threat modelling requires input from multiple teams across an organization:

- **Security Team:** Leads the process with expertise on threats and mitigation.
- **Development Team:** Ensures security is built into applications from the start.
- **IT & Operations:** Provides knowledge of the infrastructure and systems.
- **GRC Team:** Aligns the process with compliance and risk management goals.
- **Business Stakeholders & End Users:** Provide context on business goals, critical assets, and real-world usage.

### **Attack Trees**

An **attack tree** is a useful tool for visualizing threats. It's a hierarchical diagram that:

- Starts with an attacker's **primary goal** (the root node).
- Breaks that goal down into smaller, specific **methods and steps** (child nodes).
- Can also be shown as **attack paths**, which are sequences of vulnerabilities an attacker would exploit to reach their goal.

<img width="1140" height="491" alt="image" src="https://github.com/user-attachments/assets/4f444afe-0e65-40bc-9995-d68663f77182" />
Image source: [tryhackme](https://tryhackme.com/room/threatmodelling)

This structured approach helps teams thoroughly understand and plan for potential attack scenarios.

---

## Modelling with MITRE ATT&CK

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a **globally-accessible knowledge base** that catalogs the methods and behaviors cyber adversaries use to carry out attacks. It's structured as a matrix of **Tactics** (the "why" or goals of an attack) and **Techniques** (the "how" or specific methods to achieve those goals).

---

### **Structure of a Technique Page**

Each technique in the framework (e.g., **`Exploit Public-Facing Application`**) contains detailed information in five key sections:

1. **Technique Details:** A description of the method, the systems it affects, and what to look for in logs.
2. **Procedure Examples:** Real-world examples of how specific threat groups have used this technique.
3. **Mitigations:** Recommended security measures and best practices to prevent this technique.
4. **Detections:** Strategies and clues to help identify if this technique is being used against you.
5. **References:** Links to external reports and articles for further reading.

---

### **Applying MITRE ATT&CK to Threat Modelling**

The framework can be directly integrated into the threat modelling process. After identifying potential threats, you add a step:

- **Map to MITRE ATT&CK:** Connect the threats you've identified to specific tactics and techniques in the ATT&CK matrix. This allows you to leverage the framework's rich information on mitigations and detections to deeply understand your vulnerabilities and design stronger countermeasures.

---

### **Other Key Use Cases**

Beyond threat modelling, the framework is versatile and can be used for:

- **Identifying Attack Paths:** Mapping out potential routes an attacker could take through your specific infrastructure.
- **Developing Threat Scenarios:** Simulating attacks based on the known behaviors of threat groups that target your industry.
- **Prioritizing Vulnerability Remediation:** Using the framework's context to understand the real-world impact of a vulnerability and decide which ones to fix first.

---

## DREAD Framework

**What is DREAD?**

DREAD is a **qualitative risk assessment model** (originally developed by Microsoft) used to evaluate, score, and prioritize security threats. It is an acronym that represents five key categories for rating a vulnerability's risk.

---

### **The DREAD Acronym**

Each letter stands for a question used to assess risk:

- **D**amage: How bad would an attack be? (e.g., data loss, downtime, reputational harm)
- **R**eproducibility: How easy is it to reproduce the attack?
- **E**xploitability: How much work is it to launch the attack? (e.g., skills, tools, time required)
- **A**ffected Users: How many people will be impacted?
- **D**iscoverability: How easy is it to find the vulnerability?

---

### **How Scoring Works**

Each category is scored on a scale (typically 1 to 10). The scores are based on subjective assessment, guided by an organization's own predefined criteria. The **overall DREAD risk rating** is the average of the five individual scores.

**Example from the text:**

- **Unauthenticated Remote Code Execution** received a high score (8) because it causes maximum Damage, is highly Exploitable, and affects All Users, making it a critical risk.
- An **IDOR vulnerability** received a medium score (6.5) because, while it affects All Users and is easy to exploit, the potential Damage is lower.
- **Server Misconfiguration** received a lower score (5) because, while easy to find and exploit, it resulted in no Damage and affected no users in this specific scenario.

---

### **Important Guidelines**

Because DREAD relies on subjective opinion, its reliability depends on following guidelines:

1. **Standardize:** Create clear, consistent definitions and examples for each score level to ensure different analysts score the same way.
2. **Collaborate:** Involve multiple teams (security, development, etc.) to discuss and justify scores, improving accuracy.
3. **Combine Methods:** Use DREAD alongside other frameworks (like MITRE ATT&CK) to get a more complete picture of risk.
4. **Review and Update:** Regularly review and update scoring guidelines to keep them relevant.

---

## STRIDE Framework

**What is STRIDE?**

STRIDE is a **threat categorization framework** developed by Microsoft. It is used to systematically identify and classify potential security threats during the design of a system or application. The acronym represents six core types of threats, each violating a key security principle.

---

### **The STRIDE Acronym**

Each letter corresponds to a type of threat and the security property it breaks:

| **Category** | **Definition** | **Violates** |
| --- | --- | --- |
| **S**poofing | Impersonating a user or system. | **Authentication** |
| **T**ampering | Modifying data or code maliciously. | **Integrity** |
| **R**epudiation | Denying an action occurred (due to poor logs). | **Non-Repudiation** |
| **I**nformation Disclosure | Exposing sensitive data to unauthorized parties. | **Confidentiality** |
| **D**enial of Service | Disrupting service to make it unavailable. | **Availability** |
| **E**levation of Privilege | Gaining higher access rights than intended. | **Authorization** |

**Examples:**

- **Spoofing:** A phishing website.
- **Tampering:** Changing another user's password.
- **Information Disclosure:** Accessing a misconfigured cloud storage bucket.
- **Denial of Service:** Overwhelming a server with traffic.
- **Elevation of Privilege:** Exploiting a bug to get admin rights.

---

### **How to Use STRIDE in Threat Modelling**

The framework is integrated into a structured process:

1. **System Decomposition:** Break down the system into its components and data flows.
2. **Apply STRIDE Categories:** For each component, brainstorm threats that fall into each of the six STRIDE categories.
3. **Threat Assessment:** Evaluate the risk (impact and likelihood) of each identified threat.
4. **Develop Countermeasures:** Design security controls to mitigate the threats (e.g., implement DMARC to prevent email spoofing).
5. **Validation:** Test the controls via pentests, code reviews, etc.
6. **Continuous Improvement:** Regularly update the threat model as the system and threat landscape change.

Results are often tracked in a checklist table to see which STRIDE categories apply to each system scenario.

---

### **Team Collaboration**

Applying STRIDE effectively requires collaboration from multiple teams:

- **Development Team:** Builds the system securely.
- **System Architecture Team:** Designs the overall system.
- **Security Team:** Provides expertise on threats and mitigations.
- **Business Stakeholders:** Define critical assets and business goals.
- **Network Infrastructure Team:** Manages the underlying infrastructure.

This collaborative approach ensures threats are identified from all angles and that mitigations are practical and aligned with business objectives.

---

## PASTA Framework

 

**What is PASTA?**

PASTA (Process for Attack Simulation and Threat Analysis) is a **risk-centric, seven-stage** threat modelling framework. Its goal is to help organizations identify, evaluate, and prioritize security threats through a structured process that includes simulating attack scenarios. It was designed to align technical risks with business objectives.

---

### **The Seven-Step PASTA Methodology**

The framework follows a detailed, phased approach:

1. **Define the Objectives:** Set the scope, security goals, and compliance requirements for the exercise.
2. **Define the Technical Scope:** Inventory all assets (hardware, software, data) and understand the system architecture.
3. **Decompose the Application:** Break down the system into components, identifying entry points, trust boundaries, and data flows.
4. **Analyse the Threats:** Identify potential threats from various sources (external, internal, accidental) using threat intelligence.
5. **Vulnerabilities and Weaknesses Analysis:** Actively look for and document vulnerabilities (e.g., via scanning, pentesting) that could be exploited.
6. **Analyse the Attacks:** Simulate realistic attack scenarios (e.g., using Attack Trees) to understand their likelihood and potential impact.
7. **Risk and Impact Analysis:** Prioritize risks based on their severity and develop cost-effective countermeasures aligned with business risk tolerance.

---

### **Key Benefits of PASTA**

- **Comprehensive & Systematic:** The seven-step process ensures a thorough analysis of the entire risk landscape.
- **Risk-Centric:** Focuses on business impact, helping to prioritize the most significant risks.
- **Collaborative:** Fosters communication and a shared understanding of risk across different teams (development, architecture, security, business).
- **Adaptable:** Can be customized to fit an organization's unique needs and objectives.
- **Compliance-Friendly:** Helps meet regulatory requirements by systematically documenting security risks and controls.

---

### **Team Collaboration**

Applying PASTA effectively requires input from multiple teams:

- **Development Team:** Provides details on how the system is built.
- **System Architecture Team:** Explains the overall design and dependencies.
- **Security Team:** Offers expertise on threats, vulnerabilities, and mitigations.
- **Business Stakeholders:** Define what is critical to the business and the organization's risk appetite.

This ensures the threat model is technically sound and aligned with business goals.

---

## Summary

### **Summary of Threat Modeling Frameworks**

| **Framework** | **Primary Focus & Best Use Case** |
| --- | --- |
| **MITRE ATT&CK** | **Real-World Adversary Behavior.**Best for understanding and defending against the **actual tactics and techniques** used by hackers. It's used to test your defenses against known attack patterns and prioritize vulnerabilities based on real-world threats. |
| **DREAD** | **Quantitative Risk Prioritization.**Best for **scoring and ranking** the risk level of identified threats. It provides a simple, numerical way to prioritize which vulnerabilities to fix first based on Damage, Exploitability, etc. |
| **STRIDE** | **Systematic Threat Categorization.**Best for **design-time analysis** of software systems. It provides a structured checklist (Spoofing, Tampering, etc.) to ensure all categories of threats are considered during development. |
| **PASTA** | **Business-Aligned Risk Management.**Best for **connecting technical risks to business impact**. Its 7-step, risk-centric process is holistic and adaptable, making it ideal for ensuring threat modeling supports overall business objectives. |

**In short:**

- Use **STRIDE** to **find and categorize** threats in a system's design.
- Use **DREAD** to **score and prioritize** those threats.
- Use **MITRE ATT&CK** to **test your defenses** against real-world attack methods.
- Use **PASTA** to ensure the entire process is **aligned with business goals** and manages overall risk.

In general, all these frameworks significantly aid in reducing risks in organisations by:

- Enhancing threat awareness and identifying vulnerabilities
- Prioritising risk mitigation efforts and optimising security controls
- Continuous improvement and adaptation to evolving threats

All four frameworks have their unique strengths and applications in threat modelling. Leveraging these frameworks in real-world scenarios can significantly enhance an organisation's ability to identify and mitigate risks, thereby reducing the overall risk landscape and improving resilience against potential threats.

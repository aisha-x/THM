# Summary of Computer Security Incident Handling Guide by NIST


PDF link: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf

## Table of contents:

2. **Organizing a Computer Security Incident Response Capability**
3. **Handling an Incident**
4. **Coordination and Information Sharing**

## **2. Organizing a Computer Security Incident Response Capability**

This section of the NIST guide is dedicated to the foundational step of building an organization's incident response (IR) capability. It covers the necessary policies, team models, staffing, and services required to establish an effective Computer Security Incident Response Team (CSIRT).

---

### **2.1 Incident Response Policy, Plan, and Procedure Creation**

- **Incident Response Policy:** This is the high-level, management-approved document that mandates the existence of an IR capability. It defines what constitutes an incident, establishes the authority of the IR team, and outlines management's support.
- **Incident Response Plan (IRP):** This is the strategic document derived from the policy. It provides the framework for operating the IR capability, including:
    - The team's mission, goals, and objectives.
    - Senior management's endorsement.
    - The organization's approach to incident response.
    - Metrics for measuring the IR capability.
    - The structure and staffing of the CSIRT.
- **Incident Response Procedure:** These are the detailed, tactical step-by-step instructions for *how* to implement the plan. They are more granular and cover specific processes for different incident types (e.g., how to handle a malware outbreak, a denial-of-service attack, or a data breach).

### **2.2 Incident Response Team Structure**

NIST describes several common models for structuring a CSIRT:

- **Central Incident Response Team:** A single team handles incidents for the entire organization. This is efficient and consistent but may not be practical for large, geographically dispersed organizations.
- **Distributed Incident Response Team:** Multiple teams are established within different subunits (e.g., by department, division, or geographic location). This offers local expertise and focus but can lead to inconsistency and communication challenges.
- **Coordinating Team:** A central, small team coordinates incident response across the organization, but the actual response is carried out by individual subunits. This model balances central guidance with decentralized execution.

The guide also notes that many organizations use a hybrid of these models.

### **2.3 Team Models**

This subsection details options for staffing the IR team:

- **Employees / Internal Team:** The most common model. Team members are dedicated full-time or part-time to IR duties. This provides the best institutional knowledge and control.
- **Outsourced:** IR services are fully provided by a third-party Managed Security Service Provider (MSSP). This can be cost-effective for organizations lacking in-house expertise but may lack specific knowledge of the organization's environment.
- **Partially Outsourced:** A hybrid model where some functions are handled internally (e.g., coordination, critical system analysis) while others are outsourced (e.g., 24/7 monitoring and initial analysis).

### **2.4 Incident Response Personnel**

- **Selecting Team Members:** NIST emphasizes that IR requires a diverse set of skills beyond technical prowess, including:
    - **Technical Skills:** Network and system forensics, malware analysis, intrusion detection, system administration.
    - **Non-Technical Skills:** Communication (especially during high-stress situations), problem-solving, documentation, and an understanding of law and policy.
- **Dependencies:** The IR team cannot work in a vacuum. The guide highlights the critical importance of building strong relationships with other internal groups *before* an incident occurs, including:
    - **Management:** For authorization and resource allocation.
    - **Information Security:** For implementing preventative controls.
    - **IT Support / System Owners:** For technical expertise on specific systems.
    - **Legal Department:** For guidance on legal issues and evidence handling.
    - **Public Affairs / Communications:** For managing external messaging.
    - **Human Resources:** For incidents involving employees.

### **2.5 Services Provided by an Incident Response Team**

A mature CSIRT provides a core set of services, which can be proactive or reactive:

- **Reactive Services:** (Answering the phone when an incident occurs)
    - **Analysis:** Determining the scope, impact, and cause of incidents.
    - **Incident Handling:** Executing the response lifecycle (containment, eradication, recovery).
    - **Forensics:** Performing digital evidence acquisition and analysis.
- **Proactive Services:** (Preventing incidents or improving readiness)
    - **Security Management:** Managing security devices like IDS/IPS and firewalls.
    - **Education & Awareness:** Training the organization's user base on security.
    - **Vulnerability Management:** Tracking vulnerabilities and assessing their impact.
    - **Threat Intelligence:** Monitoring for new threats and trends.
    - **Risk Assessment:** Helping to identify and prioritize organizational risks.

---

### **In Essence:**

Section 2 of the NIST guide argues that effective incident response is impossible without proper organization. It provides a blueprint for building an IR capability from the top down: starting with a policy to establish authority, creating a plan to define strategy, structuring a team with the right model and skilled people, and defining the services it will provide to protect the organization. The key takeaway is that success depends on preparation, clear structure, and strong internal relationships.

## **3. Handling an Incident**

This section is the core of the NIST guide, detailing the step-by-step process for managing a security incident through its entire lifecycle. It expands upon the four-phase lifecycle introduced earlier (Preparation, Detection & Analysis, Containment Eradication & Recovery, and Post-Incident Activity) with deep practical guidance.

---

### **3.1 Preparation**

While Section 2 covered organizational preparation, this subsection focuses on the **operational** preparation needed to handle an individual incident. It emphasizes that the previous work—creating the policy, building the team, and acquiring tools—is what makes an effective response possible. Key activities include:

- **Ensuring access to critical information:** Network diagrams, asset inventories, critical system lists, and baseline data.
- **Preparing and maintaining tools:** Having forensic software, secure storage for evidence, and communication tools ready for immediate use.
- **Preventing incidents:** Implementing security controls (like firewalls and patching) is part of preparation, as it reduces the number of incidents the team must handle.

### **3.2 Detection and Analysis**

This is the phase where potential incidents are identified and assessed. NIST highlights that this is often the most challenging phase.

- **Common Detection Sources:**
    - **Alerts from IDS/IPS, Antivirus, and SIEM systems.**
    - **Logs from systems, network devices, and applications.**
    - **Reports from internal personnel (e.g., users reporting strange behavior).**
    - **Reports from external sources (e.g., other CERTs, law enforcement, vendors).**
- **Key Analysis Steps:**
    - **Incident Validation:** Determining if an incident has actually occurred (false positives are common).
    - **Scope Determination:** Understanding which systems, networks, and data are affected.
    - **Impact Analysis:** Assessing the business impact of the incident (e.g., data breach, financial loss, reputational damage).
    - **Incident Prioritization:** Not all incidents are equal. Response priority should be based on the functional impact (e.g., system destruction, data theft) and the information impact (e.g., proprietary information compromised).
    - **Documentation:** Meticulously recording all findings and actions from the very beginning. This is crucial for analysis, recovery, and potential legal proceedings.
- **Challenges:** NIST lists several analysis challenges, including the volume of data, false positives, evidence scattered across systems, and the use of anti-forensics techniques by attackers.

### **3.3 Containment, Eradication, and Recovery**

This is the phase where the organization takes action to stop the damage, remove the cause, and restore systems.

- **Containment Strategy:** The guide advises developing a containment strategy based on the specific incident. Key considerations include:
    - **Choosing a strategy:** Immediate, short-term containment (e.g., disconnecting a system from the network) vs. long-term containment (e.g., applying a firewall filter to block an attacker while clean-up continues).
    - **Evidence Gathering:** Preserving forensic evidence *before* containment actions might destroy volatile data.
    - **Potential for Damage:** Weighing the need to contain the incident against the need to preserve evidence and maintain business operations.
- **Eradication:** This involves removing the root cause of the incident. This could include:
    - Removing malware and disabling breached user accounts.
    - Identifying and patching all vulnerabilities that were exploited.
    - **A key NIST recommendation:** "Eradication may not be necessary if the organization has decided to rebuild the system."
- **Recovery:** The process of restoring systems to normal operation and confirming they are no longer compromised.
    - Actions include restoring systems from clean backups, rebuilding systems from scratch, installing patches, and changing passwords.
    - **Validation is critical:** Systems should be monitored closely after recovery to ensure they are functioning correctly and that the threat has been eliminated.

### **3.4 Post-Incident Activity (The "Lessons Learned" Phase)**

NIST strongly emphasizes that this phase is critical for improving the entire IR process. It should be held no more than two weeks after the incident concludes.

- **Lessons Learned Meeting:** A meeting with all key participants to discuss:
    - What happened and when?
    - How well did the staff and IR plan perform?
    - What went wrong or was overlooked?
    - What should be done differently next time?
- **Incident Report:** A detailed report documenting the incident's chronology, impact, root cause, and the response taken. It should include recommendations for improving security and the IR process.
- **Evidence Retention:** Securely storing all evidence and documentation from the incident for the period of time specified by organizational policy or legal requirements.
- **Implementing Recommendations:** The most important outcome is using the lessons learned to make tangible improvements, such as:
    - Updating the Incident Response Plan.
    - Implementing new security controls (e.g., better filtering, more logging).
    - Providing additional training for the IR team or users.

---

### **In Essence:**

Section 3 provides the tactical playbook for the IR team. It moves from the initial alert (**Detection**), through the critical investigation (**Analysis**), into the decisive action phase (**Containment, Eradication, Recovery**), and concludes with the vital improvement cycle (**Post-Incident Activity**). The overarching theme is that a successful response depends on a methodical, documented, and repeatable process, not on ad-hoc actions.

## **4. Coordination and Information Sharing**

This section of the NIST guide emphasizes that effective incident response does not occur in isolation. Isolated teams are less effective; collaboration is a force multiplier. This section outlines the critical importance of coordinating with both internal stakeholders and external organizations before, during, and after an incident.

---

### **4.1 Coordination**

Coordination involves establishing relationships and integrating efforts with other parties.

- **Internal Coordination:** This is the first and most critical level of coordination. The IR team *must* have established relationships with other internal groups to be effective. Key partners include:
    - **Management:** To ensure authority, secure resources, and make high-impact business decisions.
    - **Information Security and IT Staff:** To provide technical expertise and implement containment measures.
    - **Legal Counsel:** To advise on legal issues, regulatory requirements, and evidence handling to ensure actions are admissible in court.
    - **Human Resources:** Essential for handling incidents involving employees (e.g., policy violations).
    - **Public Affairs / Communications:** To manage public messaging and protect the organization's reputation during a public incident.
    - **Business Continuity Planners:** To align IR activities with broader organizational recovery plans.
- **External Coordination:** Involves working with entities outside the organization.
    - **Other Incident Response Teams:** Such as other CSIRTs or CERTS (e.g., from partner organizations or vendors).
    - **Law Enforcement Agencies (e.g., FBI, Secret Service):** Can provide additional resources, intelligence, and investigative authority. The guide cautions that involving law enforcement has implications (e.g., they may seize evidence, and the incident may become public).
    - **Government Agencies:** Such as the Department of Homeland Security (DHS) or regulatory bodies (e.g., for sectors like healthcare or finance).
    - **Internet Service Providers (ISPs) and Hosting Providers:** Can often help contain incidents by blocking malicious traffic or taking down malicious sites hosted on their infrastructure.

### **4.2 Information Sharing**

Sharing information about incidents, threats, and attacker tactics is one of the most powerful tools for improving security. The guide discusses its benefits and challenges.

- **Benefits of Information Sharing:**
    - **Gaining Awareness:** Learning about new threats, vulnerabilities, and attack patterns targeting other organizations allows a team to defend itself proactively.
    - **Corroboration:** Seeing that other organizations are experiencing the same attack can help validate findings and understand the broader campaign.
    - **Getting Help:** Sharing details of an incident can provide access to expertise and assistance from other teams who have seen similar attacks.
    - **Improving Security Posture:** Collective knowledge makes the entire community more secure.
- **Challenges of Information Sharing:**
    - **Sensitivity:** Information about an incident is often highly sensitive. Sharing it risks exposing organizational weaknesses, potentially damaging reputation, or even providing tips to competitors.
    - **Legal and Regulatory Concerns:** Laws or regulations may restrict the sharing of certain types of information (e.g., personally identifiable information - PII).
    - **Trust:** Organizations must have a trusted relationship or mechanism for sharing information anonymously or confidentially.
- **How and What to Share:** NIST recommends using structured formats and trusted channels.
    - **Channels:** Information Sharing and Analysis Centers (ISACs) for specific sectors, forums, and trusted peer-to-peer relationships.
    - **Content:** The guide recommends sharing indicators of compromise (IOCs), attacker tactics, techniques, and procedures (TTPs), and lessons learned, while carefully sanitizing reports to remove any sensitive organizational data.

### **4.3 Incident Handling Support and Funding**

This brief subsection makes the case that a successful IR capability requires sustained management support and funding. It positions coordination and information sharing not as optional extras, but as core functions that require dedicated resources (e.g., staff time, memberships to ISACs, travel for conferences).

---

### **In Essence:**

Section 4 argues that the quality of an organization's **external relationships and its participation in the broader security community are direct determinants of its incident response effectiveness.** A team that actively coordinates and shares information can detect threats faster, respond more effectively, and recover more completely than one that operates alone. The key takeaway is to build these relationships and establish sharing protocols *during peacetime* so they are already in place when an incident strikes.

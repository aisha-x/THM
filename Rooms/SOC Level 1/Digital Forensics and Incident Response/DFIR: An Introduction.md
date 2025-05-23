# TryHackMe: DFIR: An Introduction Room Summary

Room URL: https://tryhackme.com/room/introductoryroomdfirmodule

---
# What is DFIR?

**DFIR** stands for **Digital Forensics and Incident Response**. It involves the collection and analysis of forensic artifacts from digital devices such as computers, smartphones, and media storage to investigate cybersecurity incidents.

DFIR is crucial for:
- Identifying attacker footprints.
- Assessing the extent of compromise.
- Restoring systems to their pre-incident state.


## 🔍 The Need for DFIR

DFIR supports security professionals in:

- 🕵️ **Identifying evidence** of attacker activity and filtering false positives.
- 🚫 **Eradicating the attacker’s foothold** from the network.
- 📆 **Determining the breach's extent and timeline**, aiding in stakeholder communication.
- 🔐 **Finding and fixing vulnerabilities** that allowed the breach.
- 🧠 **Understanding attacker behavior** to prevent future intrusions.
- 🤝 **Sharing threat intelligence** with the wider security community.


## Who Performs DFIR?

DFIR professionals need a hybrid skillset from two domains:

### Digital Forensics
- Experts in uncovering forensic artifacts and human activity traces on digital systems.

### Incident Response
- Cybersecurity professionals skilled in using forensic data to respond to threats and intrusions.

> DFIR merges these disciplines because they are **mutually reinforcing**. Forensics informs Incident Response (IR), and IR defines the scope and goals of forensic investigations.

---
# DFIR Basic Concepts

##  Artifacts

**Artifacts** are pieces of digital evidence that indicate activity on a system. They support hypotheses about attacker behavior.

- Examples: Registry keys, logs, memory dumps, network traces.
- Sources: File system, memory, and network activity.
- Usage: Used to prove attacker actions like persistence or privilege escalation.

---

## Evidence Preservation

Preserving the **integrity of evidence** is critical in DFIR.

- Evidence must be **write-protected** before analysis.
- **Analysis is performed on a copy** of the original to prevent contamination.
- If the copy gets corrupted, the original is used to make a new one.

> Best practice: Collect, write-protect, copy, and analyze.


## Chain of Custody

The **chain of custody** ensures the evidence is only handled by authorized individuals.

- Protects evidence from unauthorized access or tampering.
- A broken chain raises doubts about **evidence integrity**.
- Must document **who handled what, when, and how**.

> Example: A forensic image passed to an unauthorized person invalidates the chain.


## Order of Volatility

**Volatility** refers to how quickly data is lost.

| Source        | Volatility Level |
|---------------|------------------|
| CPU registers | High             |
| RAM           | High             |
| Network state | Medium           |
| Disk drives   | Low              |
| Backups       | Very low         |

- **Capture high-volatility sources first** (e.g., RAM before disk).
- If volatile data isn’t captured in time, it may be **lost forever**.


## Timeline Creation

Creating a **timeline** helps visualize events chronologically.

- Combines multiple data points (logs, file timestamps, etc.).
- Helps **reconstruct attacker actions**.
- Crucial for identifying when and how incidents occurred.

> Outcome: A clear narrative of the incident based on forensic data.

# DFIR Tools

The security industry has developed several powerful tools to enhance the DFIR (Digital Forensics and Incident Response) process. These tools streamline investigation, improve efficiency, and offer deeper visibility into digital artifacts.

## [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)

Developed by **Eric Zimmerman**, these tools assist in forensic analysis on **Windows systems**, supporting:

- Registry analysis
- File system forensics
- Timeline creation
- Artifact parsing


---

## [KAPE](https://www.sans.org/tools/kape/) (Kroll Artifact Parser and Extractor)

Another tool by **Eric Zimmerman**, KAPE automates:

- Collection of forensic artifacts
- Parsing and extraction of data
- Timeline generation for incident analysis


## [Autopsy](https://www.autopsy.com/)

**Autopsy** is an open-source digital forensics platform useful for:

- Analyzing mobile devices, hard drives, and removable media
- Utilizing plugins for data extraction and presentation
- Conducting investigations with a user-friendly interface

---

## [Volatility](https://volatilityfoundation.org/)

**Volatility** is a powerful memory forensics tool used for analyzing:

- RAM captures from Windows and Linux systems
- In-memory artifacts like processes, network connections, registry keys



## [Redline](https://fireeye.market/apps/211364)

Developed by **FireEye**, **Redline** assists in incident response by:

- Collecting forensic data from endpoints
- Analyzing process and memory activity
- Identifying suspicious behavior


## [Velociraptor](https://docs.velociraptor.app/)

**Velociraptor** is an open-source platform for:

- Endpoint monitoring
- Real-time forensic investigation
- Scalable incident response


---
# Incident Response Process (PICERL Model)

In Security Operations, **Digital Forensics** is a crucial component of **Incident Response (IR)**. Two widely accepted standards—**[NIST SP-800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)** and the **[SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)**—define structured methods for managing security incidents. While they use slightly different terms, their steps are fundamentally the same.

SANS uses the acronym **PICERL** to define the following six stages:

---

## 🛡️ 1. Preparation

- Establish the **people, processes, and tools** needed before an incident occurs.
- Includes building IR plans, training teams, and deploying monitoring technologies.
- Goal: Be ready to detect, respond, and recover efficiently.

---

## 🔎 2. Identification

- Detect potential incidents through **alerts or unusual behavior**.
- Perform initial **triage** and confirm if it's a **true incident** or a false positive.
- Notify relevant stakeholders and begin documentation.

---

## 🚧 3. Containment

- Limit the **impact and spread** of the incident.
- Apply **short-term fixes** (e.g., isolating affected machines) and **long-term solutions** (e.g., firewall updates).
- Digital Forensics helps understand the scope for better containment strategies.

---

## 🧹 4. Eradication

- Fully remove the threat from the environment.
- Identify and **eliminate root causes**, like malware, backdoors, or exploited vulnerabilities.
- Ensure **forensic analysis** is complete before this step to prevent reinfection.

---

## 🔁 5. Recovery

- Restore **normal operations**.
- Rebuild affected systems and **validate security** before bringing them online.
- Monitor closely to ensure the attacker has not regained access.

---

## 🧠 6. Lessons Learned

- Conduct a **post-mortem** to analyze what happened and how it was handled.
- Update **IR plans**, patch vulnerabilities, and improve detection rules.
- Share lessons across teams to enhance future response efforts.

---

# ✅ Summary

| Phase       | Purpose                                      |
|-------------|----------------------------------------------|
| Preparation | Be ready before incidents occur              |
| Identification | Detect and verify an incident            |
| Containment | Stop the spread of the incident              |
| Eradication | Remove the threat from the network           |
| Recovery    | Resume normal business operations            |
| Lessons Learned | Improve future incident handling        |

> Remember: **PICERL** is a practical and memorable way to guide incident response effectively, combining both technical actions and strategic planning.


# OpenCTI TryHackMe Walkthrough

Room URL: https://tryhackme.com/room/opencti

---
# OpenCTI Threat Intelligence Platform Overview

This room will cover the concepts and usage of OpenCTI, an open-source threat intelligence platform. The room will help you understand and answer the following questions:

- What is OpenCTI and how is it used?
- How would I navigate through the platform?
- What functionalities will be important during a security threat analysis?

Cyber Threat Intelligence is typically a managerial mystery to handle, with organisations battling with how to input, digest, analyse and present threat data in a way that will make sense. From the rooms that have been linked on the overview, it is clear that there are numerous platforms that have been developed to tackle the juggernaut that is Threat Intelligence.

---
# OpenCTI

OpenCTI is another open-sourced platform designed to provide organisations with the means to manage CTI through the storage, analysis, visualisation and presentation of threat campaigns, malware and IOCs.

[OpenCTI Getting Started](https://docs.opencti.io/latest/usage/getting-started/)

### Objective

Developed by the collaboration of the French National cybersecurity agency (ANSSI), the platform’s main objective is to create a comprehensive tool that allows users to capitalise on technical and non-technical information while developing relationships between each piece of information and its primary source. The platform can use [the MITRE ATT&CK framework](https://tryhackme.com/room/mitre) to structure the data. Additionally, it can be integrated with other threat intel tools such as MISP and TheHive. Rooms to these tools have been linked in the overview.

![image](https://github.com/user-attachments/assets/dfa6dde8-f913-41ee-8fcd-7030f88423ce)

## OpenCTI Data Model

[OpenCTI](https://www.opencti.io/) uses a variety of knowledge schemas in structuring data, the main one being the Structured Threat Information Expression [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro) standards. STIX is a serialised and standardised language format used in threat intelligence exchange. It allows for the data to be implemented as entities and relationships, effectively tracing the origin of the provided information.

This data model is supported by how the platform’s architecture has been laid out. The image below gives an architectural structure for your know-how.

![image](https://github.com/user-attachments/assets/ca7460be-675d-4e62-beba-e56470140945)

### The highlight services include:

- **GraphQL API**: The API connects clients to the database and the messaging system.
- **Write workers**: Python processes utilised to write queries asynchronously from the RabbitMQ messaging system.
- **Connectors**: Another set of Python processes used to ingest, enrich or export data on the platform. These connectors provide the application with a robust network of integrated systems and frameworks to create threat intelligence relations and allow users to improve their defence tactics.

According to OpenCTI, connectors fall under the following classes:

| Class                          | Description                                               | Examples                          |
|-------------------------------|-----------------------------------------------------------|-----------------------------------|
| External Input Connector      | Ingests information from external sources                | CVE, MISP, TheHive, MITRE         |
| Stream Connector              | Consumes platform data stream                            | History, Tanium                   |
| Internal Enrichment Connector | Takes in new OpenCTI entities from user requests         | Observables enrichment            |
| Internal Import File Connector| Extracts information from uploaded reports               | PDFs, STIX2 Import                |
| Internal Export File Connector| Exports information from OpenCTI into different formats  | CSV, STIX2 export, PDF            |



# OpenCTI Dashboard

Once connected to the platform, the opening dashboard showcases various visual widgets summarizing the threat data ingested into OpenCTI. Widgets on the dashboard showcase the current state of entities ingested on the platform via the total number of entities, relationships, reports and observables ingested, and changes to these properties noted within 24 hours.

![dashboard](https://github.com/user-attachments/assets/cce9182f-dba1-496d-942f-73ea952424e0)

## Activities & Knowledge

The OpenCTI categorises and presents entities under the **Activities** and **Knowledge** groups on the left-side panel. 

- **Activities**: Covers security incidents ingested onto the platform in the form of reports. It makes it easy for analysts to investigate these incidents. 
- **Knowledge**: Provides linked data related to the tools adversaries use, targeted victims and the type of threat actors and campaigns used.


---

## Analysis

The **Analysis** tab contains the input entities in reports analysed and associated external references. Reports are central to OpenCTI as knowledge on threats and events are extracted and processed. 

- Allow for easier identification of the source of information by analysts. 
- Analysts can add their investigation notes and other external resources for knowledge enrichment. 
- Example: Analysis of the Triton Software report published by MITRE ATT&CK.

![analysis](https://github.com/user-attachments/assets/01f2b0d8-daa2-47f2-a891-5e7f45bae619)

---

## Events

- Security analysts investigate and hunt for events involving suspicious and malicious activities across their organizational network.
- Within the **Events** tab, analysts can record their findings and enrich their threat intel by creating associations for their incidents.

![events](https://github.com/user-attachments/assets/c80a68c0-ab7f-4005-8b6c-10396e0244ad)

---

## Observations

- Technical elements, detection rules and artefacts identified during a cyber attack are listed under this tab: one or several identifiable makeup indicators.
- Assist analysts in mapping out threat events during a hunt.
- Perform correlations between what they observe in their environments against the intel feeds.

![obsrv](https://github.com/user-attachments/assets/7f9e171e-cef5-466f-8e7c-4e2157c262d5)

---

## Threats

Information classified as threatening to an organisation includes:

- **Threat Actors**: Individuals or groups propagating malicious actions.
- **Intrusion Sets**: TTPs, tools, malware, and infrastructure used by threat actors.
- **Campaigns**: Series of attacks with specific objectives initiated by advanced persistent threats (APTs).

![image](https://github.com/user-attachments/assets/06d7c45d-cddf-44c0-8d85-59225f915a44)

---

## Arsenal

Lists all items related to an attack and any legitimate tools identified:

- **Malware**: Known malware and trojans (e.g., 4H RAT).
- **Attack Patterns**: TTPs like Command-Line Interface for navigation and investigation.
- **Courses of Action (CoA)**: Techniques mapped by MITRE to prevent attacks.
- **Tools**: Legitimate tools (e.g., CMD) possibly exploited by adversaries.
- **Vulnerabilities**: Known bugs and exposures (e.g., CVEs imported via connector).

![arsenal](https://github.com/user-attachments/assets/94ba62be-8048-4e1e-9a23-d25255b2247c)

---

## Entities

Categorises entities based on:

- Operational sectors
- Countries
- Organisations
- Individuals

This information allows for knowledge enrichment on attacks, organizations or intrusion sets.

![entites](https://github.com/user-attachments/assets/98c6f6ea-aacb-488e-825d-f4808b19b3d2)

---

### Q&A

**Q:** What is the name of the group that uses the 4H RAT malware?  
**A:** ***Putter Panda***

**Q:** What kill-chain phase is linked with the Command-Line Interface Attack Pattern?  
**A:** ***execution-ics***

**Q:** Within the Activities category, which tab would house the Indicators?  
**A:** ***Observations***

---

# General Tabs Navigation

The day-to-day usage of OpenCTI involves navigating through different entities within the platform to understand and utilize information for any threat analysis. Below is a walkthrough using the Cobalt Strike malware entity found under the Arsenal tab.

### Overview Tab
- Displays general information about an entity.
- Information includes:
  - Entity ID
  - Confidence level
  - Description
  - Related threats, intrusion sets, and attack patterns
  - Reports mentioning the entity
  - External references

![image](https://github.com/user-attachments/assets/9a99b7ea-6e79-487f-93d2-9114d26b7b48)

### Knowledge Tab
- Presents linked information associated with the selected entity.
- Includes:
  - Associated reports
  - Indicators
  - Relations
  - Attack pattern timeline
- Right-hand pane shows:
  - Threats
  - Attack vectors
  - Events
  - Observables

 ![knowledgetab](https://github.com/user-attachments/assets/b6438715-c6aa-4287-b096-6a374e78282f)

### Analysis Tab
- Displays reports where the identified entity has been seen.
- Provides usable threat information for investigation tasks.

![image](https://github.com/user-attachments/assets/02165e52-b053-46cc-add1-05149c382fac)

### Indicators Tab
- Shows IOCs identified for all threats and entities.

### Data Tab
- Contains uploaded or generated files related to the entity.
- Used for communicating threat information in technical or non-technical formats.

### History Tab
- Tracks changes made to the element, attributes, and relations.
- Changes are monitored by the platform worker.

---

## Knowledge Check - Cobalt Strike

**Q: What Intrusion sets are associated with the Cobalt Strike malware with a Good confidence level?**
- **A:** ***CopyKittens, FIN7***

**Q: Who is the author of the entity?**
- **A:** ***The MITRE Corporation***

---

## Analyst Assignment: Investigating CaddyWiper Malware and APT37 Group

**Q: What is the earliest date recorded related to CaddyWiper?**

![image](https://github.com/user-attachments/assets/665182e1-39b4-4eac-bdad-0787155ed5b7)

- **A:** ***2022/03/15***

**Q: Which Attack technique is used by the malware for execution?**

![image](https://github.com/user-attachments/assets/a4639f83-2fa5-4c3e-a48d-3ab5995512b5)

- **A:** ***Native API***

**Q: How many malware relations are linked to this Attack technique?**

![image](https://github.com/user-attachments/assets/785456cf-0365-4207-9c03-2883ef578814)

- **A:** ***113***

**Q: Which 3 tools were used by the Attack Technique in 2016?**

![image](https://github.com/user-attachments/assets/310a0b1a-f263-49cc-85ab-2345a9833e35)

- **A:** ***ShimRatReporter, Empire, Bloodhound***

**Q: What country is APT37 associated with?**

![image](https://github.com/user-attachments/assets/94edfc1c-8f65-4ce1-9c5e-09666e646c6d)

- **A:** ***North Korea***

**Q: Which Attack techniques are used by the group for initial access?**

![image](https://github.com/user-attachments/assets/9bdf22eb-f0d2-41d4-8a76-67fdfbf2b32c)

- **A:** ***T1189, T1566***

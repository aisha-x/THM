
# TryHackMe: Sigma Room 

Room URL: https://tryhackme.com/room/sigma

---
# Practical 


Use this Intel [TheDFIRReport](https://twitter.com/TheDFIRReport/status/1423361127472377860?s=20&t=mHiJFnlfWH3cO3XdXEQo_Q) to create a detection rule: 

```yml
title: AnyDesk Installation.
id: 10000001
status: experimental
description: AnyDesk Remote Desktop installation can be used by attacker to gain remote access
date: 
modified: #When was it updated
logsource: 
  category: process_creation
  product: windows
detection:
  selection:
    CurrentDirectory|contains:
      - 'C:\ProgramData\AnyDesk.exe'
    CommandLine|contains|all: 
      - '--silent'
      - '--install'
      - '--start-with-win'
  condition: selection #Action to be taken.
fields: #List of associated fields that are important for the detection

falsepositives: 
  - Legitimate deployment of AnyDesk

level: hight 
references: 
  - https://x.com/TheDFIRReport/status/1423361127472377860?s=20&t=mHiJFnlfWH3cO3XdXEQo_Q
tags: 
  - attack.command_and_control
  - attack.t1219
```



---

**Scenario**
Your organisation, Aurora, has recently been experiencing unusual activities on some of the machines on the network. Amongst these activities, the IT Manager noted that an unknown entity created some scheduled tasks on one of the machines and that ransomware activity was also recorded.

The SOC Manager has approached you to find ways of identifying these activities from the logs collected on the environment. It would be best if you used Sigma rules to set your detection parameters and perform search queries through the Kibana dashboard.

To complete the task, you will require two Sigma rules processed into ElasticSearch to query for the scheduled task and the ransomware events. Below are tips to construct a good rule for the task:

- For the Scheduled Task, understand that it is a `process creation` event.
- The rule's detection variables should contain `image and commandline` arguments.
- You may choose to exclude `SYSTEM` accounts from the query.
- For the ransomware activity, you'll look for a created file ending with `.txt`.
- The file creation process would be run via `cmd.exe`.
- Change the default time window on Kibana from the default last 30 days to last 1 year (or ensure it encompasses 2022).

**1. Detecting Suspicious Sceduled Task**

```yml
title: susicious Scheduled Task
id: 1000002
status: Expermential
description: detect suspicious scheduled task.
author: Aisha
date: 23/6/2025 10:00 pm
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\schtasks.exe'
    winlog.user.name: SYSTEM
  condition: selection 
fields: 
    - Image
    - winlog.user.name
    - CommandLine
    - ParentImage
    - ParentCommandLine

falsepositives: 
    - Legitimate administrative tasks run by SYSTEM

level: high 
tags: 
  - attack.Execution
  - attack.Persistence
  - attack.Privilege_Escalation
  - attack.T1053
```
**Elastic Stack Query (Lucene)**
```query
(event.category:process AND process.executable:/.*\\[Ss][Cc][Hh][Tt][Aa][Ss][Kk][Ss]\.[Ee][Xx][Ee]/ AND winlog.user.name:SYSTEM)
```
![Screenshot 2025-06-23 224457](https://github.com/user-attachments/assets/e28ad4c2-7573-4db2-9d12-19d6eda170c8)


---
**2. Detect Ransomware Activity**

```yml
title: Detect Ransomware Activity
id: 1000003
status: Expermential
author: Aisha
date: 23/6/2025 10:00 pm
logsource: 
  category: file_creation
  product: windows
detection:
  selection:
    EventID: 
       - 11
    TargetFilename|endswith:
      - '.txt'
    Image|endswith:
      - '\cmd.exe'
     
  condition: selection #Action to be taken.
fields:
    - EventID
    - ParentCommandLine
    - CommandLine
    - file.name
```

**Elastic Stack Query (Lucene)**
```query
(winlog.event_id:11 AND file.path:/.*\.[Tt][Xx][Tt]/ AND process.executable:/.*\\[Cc][Mm][Dd]\.[Ee][Xx][Ee]/)
```
![Screenshot 2025-06-23 231500](https://github.com/user-attachments/assets/00628f2c-994f-4d56-8132-03375c055823)

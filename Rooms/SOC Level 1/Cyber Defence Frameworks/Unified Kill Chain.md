# TryHackMe: Unified Kill Chain

Room URL: https://tryhackme.com/room/unifiedkillchain

# Unified Kill Chain (UKC) Summary

![image](https://github.com/user-attachments/assets/d43f94b2-124b-4ce1-ae36-b235c5402143)

---
# Phase: In (Initial Foothold)

![image](https://github.com/user-attachments/assets/1d928772-58c7-4610-9e20-c92c64ff7196)


## Reconnaissance [MITRE Tactic TA0043](https://attack.mitre.org/tactics/TA0043/)
This phase involves gathering information about the target through passive or active reconnaissance.

- Discover what systems and services are running.
- Find contact lists or employee details for impersonation or phishing.
- Search for potential credentials useful for pivoting or access.
- Understand network topology and identify pivot points.

## Weaponization [MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/)
Setting up the infrastructure necessary for the attack.

- Setting up command and control (C2) servers.
- Preparing systems to receive reverse shells and deliver payloads.

## Social Engineering [MITRE Tactic TA0001](https://attack.mitre.org/tactics/TA0001/)
Manipulating employees to aid the attack.

- Getting users to open malicious attachments.
- Impersonating web pages to steal credentials.
- Impersonating individuals to request password resets or gain physical access.

## Exploitation [MITRE Tactic TA0002](https://attack.mitre.org/tactics/TA0002/)
Taking advantage of system vulnerabilities to execute code.

- Uploading and executing a reverse shell via a web application.
- Exploiting automated scripts to execute malicious code.
- Abusing web application vulnerabilities for code execution.

## Persistence [MITRE Tactic TA0003](https://attack.mitre.org/tactics/TA0003/)
Maintaining access to a compromised system.

- Creating services that allow re-access.
- Connecting compromised systems to C2 servers.
- Leaving backdoors triggered by specific actions (e.g., admin logins).

## Defence Evasion [MITRE Tactic TA0005](https://attack.mitre.org/tactics/TA0005/)
Avoiding detection by defensive systems.

- Evading web application firewalls and network firewalls.
- Bypassing antivirus software and intrusion detection systems (IDS).

## Command & Control [MITRE Tactic TA0011](https://attack.mitre.org/tactics/TA0011/)
Establishing communication between the adversary and the compromised system.

- Executing remote commands.
- Stealing data and credentials.
- Using the compromised system to pivot deeper into the network.

## Pivoting [MITRE Tactic TA0008](https://attack.mitre.org/tactics/TA0008/)
Moving through a network to reach otherwise inaccessible systems.

- Using a compromised public server to attack internal systems.
- Targeting weaker, internal systems for further exploitation.



---
# Phase: Through (Network Propagation)

This phase follows a successful foothold being established on the target network. An attacker would seek to gain additional access and privileges to systems and data to fulfil their goals. The attacker would set up a base on one of the systems to act as their pivot point and use it to gather information about the internal network.

![image](https://github.com/user-attachments/assets/72c23582-21ac-4dc6-852c-9d7f962a5504)

## Pivoting [MITRE ATT&CK:TA0008 ](https://attack.mitre.org/tactics/TA0008/)
Once the attacker has access to a system, they use it as a staging point and tunnel between their command operations and the victim’s network. The compromised system becomes the distribution hub for malware and backdoors.


## Discovery [MITRE ATT&CK: TA0007](https://attack.mitre.org/tactics/TA0007/)
The adversary uncovers information about the system and the connected network. Information gathered includes:

- Active user accounts.
- Permissions granted.
- Applications and software in use.
- Web browser activity.
- Files, directories, and network shares.
- System configurations.


## Privilege Escalation [MITRE ATT&CK:TA0004](https://attack.mitre.org/tactics/TA0004/)
After gathering system and network knowledge, the adversary attempts to gain elevated privileges by exploiting vulnerabilities and misconfigurations.

Possible elevated levels:

- SYSTEM/ROOT.
- Local Administrator.
- User accounts with Admin-like access.
- Specific user accounts with privileged functions.



## Execution [MITRE ATT&CK:TA0002](https://attack.mitre.org/tactics/TA0002/)
Deploying malicious code through the pivot system. The attacker may use:

- Remote access trojans (RATs).
- Command & Control (C2) scripts.
- Malicious links.
- Scheduled tasks for persistence.


## Credential Access  [MITRE ATT&CK:TA0006](https://attack.mitre.org/tactics/TA0006/)
The attacker attempts to steal account names and passwords using techniques such as:

- Keylogging.
- Credential dumping.

This allows them to blend in with legitimate users during the attack.


## Lateral Movement [MITRE ATT&CK: TA0008](https://attack.mitre.org/tactics/TA0008/)
With stolen credentials and elevated privileges, the attacker moves across the network to other systems, trying to remain stealthy while achieving their objectives.


# Phase: Out (Action on Objectives)
This phase wraps up the journey of an adversary’s attack on an environment, where they have critical asset access and can fulfil their attack goals. These goals are usually geared toward compromising the confidentiality, integrity and availability (CIA) triad.

## Collection [MITRE ATT&CK:TA0009](https://attack.mitre.org/tactics/TA0009/)
After gaining access and locating valuable assets, the adversary gathers sensitive data. This compromises the confidentiality of information and sets up the next phase—Exfiltration. Main target sources include:

- Drives
- Web browsers
- Audio and video files
- Emails



## Exfiltration [MITRE ATT&CK: TA0010](https://attack.mitre.org/tactics/TA0010/)
The adversary attempts to steal the gathered data, often encrypting and compressing it to evade detection. Previously established Command & Control (C2) channels and tunnels are used for this operation.


## Impact [MITRE ATT&CK:TA0040](https://attack.mitre.org/tactics/TA0040/)
The adversary compromises the integrity and availability of assets by manipulating, interrupting, or destroying them. Techniques may include:

- Removing account access
- Performing disk wipes
- Encrypting data (e.g., ransomware)
- Defacing websites
- Launching denial of service (DoS) attacks



## Objectives
After gaining full control over systems and networks, the adversary aims to achieve their strategic goals, which may include:

- Financial extortion (e.g., encrypting files with ransomware and demanding payment).
- Damaging the organization’s reputation by leaking sensitive information to the public.


---

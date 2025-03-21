# Eviction Walkthrough (SOC Level 1)

Welcome to this walkthrough of the Eviction Room on TryHackMe.

In this room we unearth the monster from under your bed? This is a room to test the knowledge gained during the Cyber Defense Frameworks module.

This room is part of the SOC Level 1 Path.
[Room URL](https://tryhackme.com/r/room/eviction)



# Task 1: Understand the adversary
Sunny is a SOC analyst at E-corp, which manufactures rare earth metals for government and non-government clients. 

She receives a classified intelligence report that informs her that an APT group (APT28) might be trying to attack organizations similar to E-corp. 

To act on this intelligence, she must use the MITRE ATT&CK Navigator to identify the TTPs used by the APT group, to ensure it has not already intruded into the network, and to stop it if it has.

Please visit this [link](https://static-labs.tryhackme.cloud/sites/eviction/) to check out the MITRE ATT&CK Navigator layer for the APT group and answer the questions below.

# Questions

befor answering the question, Who is APT28 group?

[APT28](https://attack.mitre.org/groups/G0007/)

APT28 is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) 
military unit 26165.[1][2] This group has been active since at least 2004.

**1- What is a technique used by the APT to both perform recon and gain initial access?**

If you look at the Reconnaissance column (Tactic) and the Initial Access column (Tactic),  one technique is shared by the two columns: Spearphishing link

![image](https://github.com/user-attachments/assets/c4660a6c-ab6d-4422-9a4f-da1179220656)

Read more about this technique [here](https://attack.mitre.org/techniques/T1598/003)

Answer: ***Spearphishing link***

--------------------------------------------------------------------------------------------------------

**2- Sunny identified that the APT might have moved forward from the recon phase. Which accounts might the APT compromise while developing resources?**


![image](https://github.com/user-attachments/assets/24be3292-cb55-4cba-a762-949c32bc3eb6)

Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct Phishing for Information, Phishing, or large-scale spam email campaigns. 

Read more about this technique [here](https://attack.mitre.org/techniques/T1586/002)

Answer: ***Email accounts***


--------------------------------------------------------------------------------------------------------


**3- E-corp has found that the APT might have gained initial access using social engineering to make the user execute code for the threat actor. Sunny wants to identify if the APT was also successful in execution. What two techniques of user execution should Sunny look out for? (Answer format: <technique 1> and <technique 2>)**

look under the execution tactic 

![image](https://github.com/user-attachments/assets/dd212eaa-5e24-4ecf-8675-b5be623826b7)

since the technique used to perform reconnaissance and gain access was ***spearphishing link***. then the execution was made by the user clicking a malicious link.

read more about this technique 

[Malicious Link](https://attack.mitre.org/techniques/T1204/001/)

[Malicious File](https://attack.mitre.org/techniques/T1204/002/)


Answer: ***Malicious File and Malicious Link***



--------------------------------------------------------------------------------------------------------


**4- If the above technique was successful, which scripting interpreters should Sunny search for to identify successful execution? (Answer format: <technique 1> and <technique 2>)**


![image](https://github.com/user-attachments/assets/29568784-2863-425c-ac8c-51f95089ead2)

[Powershell](https://attack.mitre.org/techniques/T1059/001/)

[Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

Answer: ***Powershell and Windows Command shell***


-------------------------------------------------------------------------------------------------------------

**5- While looking at the scripting interpreters identified in Q4, Sunny found some obfuscated scripts that changed the registry. Assuming these changes are for maintaining persistence, which registry keys should Sunny observe to track these changes?**


![image](https://github.com/user-attachments/assets/363f1269-b20e-44b7-8a22-3c47148a3234)

[Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

Answer:***Registry run keys***


-------------------------------------------------------------------------------------------------------------

**6- Sunny identified that the APT executes system binaries to evade defences. Which system binary’s execution should Sunny scrutinize for proxy execution?**

under the Defense Evasion Tactic

![image](https://github.com/user-attachments/assets/b80c9f8c-ca3e-48e8-a9cf-3a7418d29ac0)


what is [System Binary Proxy Execution?](https://attack.mitre.org/techniques/T1218/) 

Tactic: Defense Evasion

Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.[1] Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.

Similarly, on Linux systems adversaries may abuse trusted binaries such as split to proxy execution of malicious commands.

[System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)

Other sub-techniques of System Binary Proxy Execution (14)

Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads (ex: ```rundll32.exe {DLLname, DLLfunction}```).


Answer: ***Rundll32***


-------------------------------------------------------------------------------------------------------------

**7-Sunny identified tcpdump on one of the compromised hosts. Assuming this was placed there by the threat actor, which technique might the APT be using here for discovery?**

under Discovery Tactice you will see the Network Sniffing technique

![image](https://github.com/user-attachments/assets/07e0c776-264b-49da-a1a2-7df0326f85d0)

[Network Sniffing Technique](https://attack.mitre.org/techniques/T1040/) Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. ```tcpdump``` is a tool used for network sniffing

tcpdump is a data-network packet analyzer computer program that runs under a command line interface. It allows the user to display TCP/IP and other packets being transmitted or received over a network to which the computer is attached.

Answer: ***Network sniffing***


-------------------------------------------------------------------------------------------------------------


**8- It looks like the APT achieved lateral movement by exploiting remote services. Which remote services should Sunny observe to identify APT activity traces?**


under the Lateral Movement Tactic, in the remote services technique

![image](https://github.com/user-attachments/assets/72b5f844-5584-48a3-8f8b-42d90489500d)

[TSMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)


Answer: ***TSMB/Windows Admin Shares***


-------------------------------------------------------------------------------------------------------------

**9- It looked like the primary goal of the APT was to steal intellectual property from E-corp’s information repositories. Which information repository can be the likely target of the APT?**

under the Collection Tactic, in Data from Information Repository technique
![image](https://github.com/user-attachments/assets/ac1a831c-87e4-4654-be72-d8c068c7538b)

[Data from Information Repositories: Sharepoint](https://attack.mitre.org/techniques/T1213/002/)

Answer: ***THM{c8951b2ad24bbcbac60c16cf2c83d92c}***

-------------------------------------------------------------------------------------------------------------

**10- Although the APT had collected the data, it could not connect to the C2 for data exfiltration. To thwart any attempts to do that, what types of proxy might the APT use? (Answer format: <technique 1> and <technique 2>)**





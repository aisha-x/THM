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





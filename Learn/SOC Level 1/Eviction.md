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




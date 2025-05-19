# TryHackMe: ItsyBitsy Challenge

Room URL: https://tryhackme.com/room/itsybitsy

# Scenario - Investigate a potential C2 communication alert

## Scenario

During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern `THM:{ ________ }`. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the **connection_logs** index in Kibana.

Our task in this room will be to examine the network connection logs of this user, find the link and the content of the file, and answer the questions.

## Answer the questions below

---

### Q1. How many events were returned for the month of March 2022?

- Set the timeline on the first day of Mar 2022 to the last day of the month 

Ans: ***1482***

---

### Q2.What is the IP associated with the suspected user in the logs?

- There are only two `source_ip`: 192.166.65.52,192.166.65.54
- but if we click on the `user_agent`, there are two user_agents: 

![Screenshot 2025-05-19 113933](https://github.com/user-attachments/assets/6c273a8c-88cb-4bce-9c2d-14906bbc7c76)

- `bitsadmin` is a command-line tool used to manage **Background Intelligent Transfer Service (BITS)** jobs in Windows. BITS is used by the system (and other apps) to download or upload files in the background. 
- It can also used by attackers to download and execute payloads. for further information -> [Mandiant article](https://cloud.google.com/blog/topics/threat-intelligence/attacker-use-of-windows-background-intelligent-transfer-service/)

![Screenshot 2025-05-19 114456](https://github.com/user-attachments/assets/ec07a6c6-234c-4185-bec0-7e5c56f45aee)

Ans: ***192.166.65.54***

---

### Q3.The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

Ans: ***bitsadmin***

---

### Q4.The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

Ans: ***pastebin.com***


---

### Q5.What is the full URL of the C2 to which the infected host is connected?

- Take the domain `pastebin.com` and track the URI found in the log

![Screenshot 2025-05-19 113653](https://github.com/user-attachments/assets/da7214c5-c2a8-4c00-99e5-51c7252dde0d)


Ans: ***pastebin.com/yTg0Ah6a***

---

### Q6.A file was accessed on the filesharing site. What is the name of the file accessed?

Ans: ***secret.txt***

---

### Q7.The file contains a secret code with the format THM{_____}.

Ans: ***THM{SECRET__CODE}***

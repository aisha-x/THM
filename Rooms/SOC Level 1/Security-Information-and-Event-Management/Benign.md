# TryHackMe: Benign Challenge

Room URL: https://tryhackme.com/room/benign


# Scenario: Identify and Investigate an Infected Host

One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index win_eventlogs for further investigation.

## About the Network Information

The network is divided into three logical segments. It will help in the investigation.

1. **IT Department**: James, Moin, Katrina
2. **HR department**: Haroon, Chris, Diana
    - `HR_01`: Chris.fort
    - `HR_02`: haroon
    - `HR_03`: Daina
3. **Marketing department**: Bell, Amelia, Deepak

![Screenshot 2025-05-23 104550](https://github.com/user-attachments/assets/c7ac5b50-2821-4364-b38a-794bfba39324)


## Answer the questions below

### Q1.How many logs are ingested from the month of March, 2022?

- `index=win_eventlogs`

Ans: ***13959***

---

### Q2.Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

- First, lets list all usernames in the `win_eventlogs`, counting how many times each appears, and sort them by count in decsending order
```sql
index=win_eventlogs UserName="*" 
| stats count by UserName 
| sort - count
```
![image](https://github.com/user-attachments/assets/fb5bf2a4-3ff6-49a6-a1fa-652bba208050)

- Amel1a appears twice, and that suspicious

Ans: ***Amel1a***

---

### Q3.Which user from the HR department was observed to be running scheduled tasks?

```sql
index=win_eventlogs schtasks HostName="HR_0*"
```

![image](https://github.com/user-attachments/assets/53745ce7-fa17-4103-88f4-8c3ad33540d5)

- In the CommandLine field, the user Chris.fort executes a scheduled task.
- `OfficUpdater` — Misspelled to mimic "`OfficeUpdater`", a common trick to hide in plain sight.
- `update.exe` in `Temp` folder — This is unusual and often used by malware to persist on a system.
- `/sc onstart` — Ensures the file runs every time the system boots — a persistence mechanism.

Ans: ***Chris.fort***

---

### Q4. Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.

- **"Living Off The Land Binaries"** (LOLBins) refers to legitimate, pre-installed system tools in operating systems (usually Windows) that attackers abuse to carry out malicious activities without downloading custom malware.
- Explor -> [Living Off The Land Binaries, Scripts and Libraries](https://lolbas-project.github.io/) to find binaries used to download payloads
- [certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/) -> 	Certificate tool, download files from the internet
```sql
index=win_eventlogs certutil.exe | spath HostName | search HostName="HR_0*"
```
![Screenshot 2025-05-23 114544](https://github.com/user-attachments/assets/2f112b91-2b3d-4196-a1e4-3d6850fe972d)

- at **"2022-03-04T10:38:28Z"**, Haroon used `certutil.exe` tool to download a file from a URL and save it as `benign.exe`

Ans: ***haroon***

---
### Q5. To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?


Ans: ***certutil.exe***

---

### Q6. What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)


Ans: ***2022-03-04***

---

### Q7. Which third-party site was accessed to download the malicious payload?


Ans: ***controlc.com***

---

### Q8. What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?


Ans: ***benign.exe***

---

### Q9. The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

- Track this URL -> https://controlc.com/e4d11035 to find the flag

![Screenshot 2025-05-23 115454](https://github.com/user-attachments/assets/5e5948db-1495-487d-88ba-b38a7a57a3a9)

Ans: ***THM{KJ&*H^B0}***

---

### Q10. What is the URL that the infected host connected to?

Ans: ***https://controlc.com/e4d11035***


---

## Findings

1. at **2022-03-04 T10:38:28Z**, the user **haroon** (**HR_01**), used a LOLBIN tool to download a payload from a file-sharing website and save it in the system as `benign.exe`
2. the second day at **2022-03-05 T12:54:30Z**, A suspisious user named **Amel1a** was seen in the host **HR_02**(belongs to Chris.fort) executing some commands.
   ![Screenshot 2025-05-23 111229](https://github.com/user-attachments/assets/d39d0617-8639-479f-8f5f-7a25825af44d)
   
4. **2022-03-06 T13:52:37Z**, the suspicious user created a persistence on the **HR_02** machine using the task scheduler tool

# Friday Overtime : Tryhackme walkthrough

Room URL: 

---
# Task 1 Challenge Scenario

It’s a Friday evening at PandaProbe Intelligence when a notification appears on your CTI platform. While most are already looking forward to the weekend, you realise you must pull overtime because SwiftSpend Finance has opened a new ticket, raising concerns about potential malware threats. The finance company, known for its meticulous security measures, stumbled upon something suspicious and wanted immediate expert analysis.

As the only remaining CTI Analyst on shift at PandaProbe Intelligence, you quickly took charge of the situation, realising the gravity of a potential breach at a financial institution. The ticket contained multiple file attachments, presumed to be malware samples.

With a deep breath, a focused mind, and the longing desire to go home, you began the process of:

1. Downloading the malware samples provided in the ticket, ensuring they were contained in a secure environment.
2. Running the samples through preliminary automated malware analysis tools to get a quick overview.
3. Deep diving into a manual analysis, understanding the malware’s behaviour, and identifying its communication patterns.
4. Correlating findings with global threat intelligence databases to identify known signatures or behaviours.
5. Compiling a comprehensive report with mitigation and recovery steps, ensuring SwiftSpend Finance could swiftly address potential threats.

---

# Answer the questions below

**Q1- Who shared the malware samples?**

Ans: ***Oliver Bennett***

---
**Q2- What is the SHA1 hash of the file “pRsm.dll” inside samples.zip?**

1. Download the attachment file in the email sent *sample.zip*
2. unzip the malware sample using the password in the email
3. 
  ![image](https://github.com/user-attachments/assets/584b0c62-89dc-4fe3-9011-d3a86391b845)

4. open the terminal and run `sha1sum pRsm.dll` 

Ans: ***9d1ecbbe8637fed0d89fca1af35ea821277ad2e8***

# 🔐 Why Extract Hashes in Malware Analysis?

When analyzing malware, one of the **first steps** is to compute its hash. A hash is a **digital fingerprint** of a file, used widely in malware research and cybersecurity operations.

---

## ✅ Why Extract a Hash?

### 1. 🔍 File Identification

- A hash **uniquely identifies** a malware sample.
- Analysts can look up hashes in platforms like **VirusTotal**, **Hybrid Analysis**, or internal databases.
- Helps determine if the file is **already known** and what behavior is associated with it.

### 2. 📑 Verification & Integrity

- Verifies that the file hasn't been **altered** during transfer or analysis.
- Confirms that analysts are working with the **exact same binary**.
- Useful when submitting samples to multiple tools or sharing across teams.

### 3. 📁 Deduplication

- Large repositories of malware samples often contain duplicates.
- Hashing helps in **identifying and removing duplicate files** efficiently.

### 4. 🚨 Threat Intelligence Sharing

- Malware researchers often share file hashes (especially **SHA-256**) as **Indicators of Compromise (IOCs)**.
- Other organizations can then **block** or **search for** these files on their systems.

### 5. ⛔ Detection and Blocking

- Antivirus and EDR tools use **hash-based signatures** to detect or block known malicious files.
- If a file's hash matches a known threat, it's flagged immediately.

---

## 🔐 Common Hash Algorithms

| Algorithm | Purpose        | Notes                         |
|-----------|----------------|-------------------------------|
| MD5       | Fast lookup     | Weak but widely used          |
| SHA-1     | More secure     | Being phased out              |
| SHA-256   | Strong security | **Recommended** for analysis |

---

**Q3- Which malware framework utilizes these DLLs as add-on modules?**

- Search for pRsm.dll malware framework
- You will see this article [Evasive Panda APT ](https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/#h2-6) 
- ![image](https://github.com/user-attachments/assets/7af2e7c6-3def-46f9-8ecf-b100d970f201)

Ans: ***MgBot***

---
**Q4- Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?**

- search in MITRE ATT&CK techniques section in the same article for prsm.dll module 
- ![image](https://github.com/user-attachments/assets/1ce14fbd-3d84-4ffa-b748-5047be45ef17)

Ans: ***T1123***

---
**Q5- What is the CyberChef defanged URL of the malicious download location first seen on 2020–11–02?**

- we need to defang a URL to prevent anyone from accidentally clicking on it
- Search for the malicious download location 
- ![image](https://github.com/user-attachments/assets/6caaa085-e759-4f6e-86fc-fd79a32ef5aa)
- defang the URL using [CyberChef](https://gchq.github.io/CyberChef/) 
- ![image](https://github.com/user-attachments/assets/8c01648c-0d86-4403-bf02-d7568aa3f957)

Ans: ***hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296[.]exe***

---
**Q6- What is the CyberChef defanged IP address of the C&C server first detected on 2020–09–14 using these modules?**

- we can simple `Ctr + f` to search for 2020 
-![image](https://github.com/user-attachments/assets/8131b423-d682-4a62-a7c4-051e66bc6406)

- then go to CyberChef and select defang IP Addresses, you need to remove the brackets around the last period so the output change
  
-![image](https://github.com/user-attachments/assets/89510edf-17bf-49d1-a821-4178171b56e8)

Ans: ***122[.]10[.]90[.]12***

---
**Q7- What is the SHA1 hash of the spyagent family spyware hosted on the same IP targeting Android devices on November 16, 2022?**

- Go to [VirusTotal]() and search for the this ip address `122.10.90.12`
- ![image](https://github.com/user-attachments/assets/099eba24-51cb-4cfd-8334-08a582d36f17)


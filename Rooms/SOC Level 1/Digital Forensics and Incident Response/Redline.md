# TryHackMe: Redline Room Summary

Room URL: https://tryhackme.com/room/btredlinejoxr3d




---
# Redline Tool Overview

**Redline** is a powerful forensics and incident response tool developed by FireEye. It enables security analysts and incident responders to perform memory and endpoint analysis quickly and effectively, especially during triage when time is critical.


## Why Use Redline?

While tools like **[Volatility](https://tryhackme.com/room/volatility)** provide in-depth analysis of memory artifacts, they can be time-consuming. [Redline,](https://fireeye.market/apps/211364) on the other hand, offers a **high-level (30,000-foot view)** of an endpoint, making it ideal for **quick assessments** to determine the nature of a security event.


## Supported Platforms

- Windows
- Linux
- macOS


## What Can You Do With Redline?

- Collect Registry Data (Windows hosts only)
- Collect Running Processes
- Collect Memory Images (supported for pre-Windows 10 systems)
- Collect Browser History
- Search for Suspicious Strings
- Analyze Various File Structures
- Review Timeline and Audit Data
- IOC-Based Scanning


## Interface Highlights

- User-Friendly GUI (Graphical User Interface)
- Visual Tools for Identifying Malicious Artifacts
- Organized View of System and Memory Data


Redline is ideal for analysts who need speed and visibility in early-stage incident response and triage. It pairs well with other tools like Volatility for more detailed investigations.


## Data Collection


Redline offers multiple data collection methods tailored to different analysis needs. Choosing the right method depends on how much data you want to collect and how quickly you need results.



## 1. Standard Collector

- **Purpose**: Gathers a minimum amount of data for initial analysis.
- **Usage**: This is the **preferred method** for quick triage and is ideal for most use cases in this room.
- **Speed**: Fast — typically takes only a few minutes.
- **Best for**: Rapid assessments where time is critical.


## 2. Comprehensive Collector

- **Purpose**: Gathers the **maximum** amount of data from the system for deep analysis.
- **Usage**: Choose this method when a **full system analysis** is needed.
- **Speed**: Slow — may take an hour or more to complete.
- **Best for**: Thorough investigations and post-incident reviews.


## 3. IOC Search Collector *(Windows only)*

- **Purpose**: Collects data that matches known **Indicators of Compromise (IOCs)**.
- **Usage**: Use this method when you have IOCs gathered from:
  - Threat intelligence feeds
  - Narrative reports
  - Malware analysis
  - Previous incident responses
- **Tools Required**: IOCs must be created or imported using **IOC Editor**.
- **Best for**: Targeted searches for known threats and adversary behaviors.


---
# Standard Collector Analysis

---

## Answer the questions below


### Q1. Provide the Operating System detected for the workstation.

![Screenshot 2025-05-28 144330](https://github.com/user-attachments/assets/d4c59ce0-47e1-4fe3-a9ea-c0a36745fc73)

Ans: ***Windows Server 2019 Standard 17763***


### Q2. What is the suspicious scheduled task that got created on the computer? 

- select the **task** option

![Screenshot 2025-05-28 145105](https://github.com/user-attachments/assets/48b618ac-159b-43b5-81ca-837fc7f7cdf3)

Ans: ***MSOfficeUpdateFa.ke***

### Q3. Find the message that the intruder left for you in the task.

Ans: ***THM-p3R5IStENCe-m3Chani$m***

### Q4.There is a new System Event ID created by an intruder with the source name "THM-Redline-User" and the Type "ERROR". Find the Event ID #.

- the **EventID** section, search for the source name "THM-Redline-User"

![Screenshot 2025-05-28 145409](https://github.com/user-attachments/assets/5a0ad07d-2a91-440e-8597-62ae5002d1bc)


Ans: ***546***

### Q5.Provide the message for the Event ID.

Ans: ***Someone cracked my password. Now I need to rename my puppy-++-***

### Q6.It looks like the intruder downloaded a file containing the flag for Question 8. Provide the full URL of the website.

- from the **file Download history** section

![Screenshot 2025-05-28 145927](https://github.com/user-attachments/assets/5311706f-257e-430b-8bca-b57581f3aec7)


Ans: ***https://wormhole.app/download-stream/gI9vQtChjyYAmZ8Ody0AuA***

### Q7.Provide the full path to where the file was downloaded to including the filename.

Ans: ***C:\Program Files (x86)\Windows Mail\SomeMailFolder\flag.txt***

### Q8.Provide the message the intruder left for you in the file.

- click on the **Timeline** option, then search for flag.txt file
- on the bottom right, click on the **Show Details**, select string option to view the content of the file

![Screenshot 2025-05-28 150518](https://github.com/user-attachments/assets/117d82db-849e-4285-a90e-39055fac96f8)

Ans: ***THM{600D-C@7cH-My-FR1EnD}***


---

# TASK-6: IOC Search Collector Analysis

**Scenario**: You are assigned to do a threat hunting task at Osinski Inc. They believe there has been an intrusion, and the malicious actor was using the tool to perform the lateral movement attack, possibly a "[pass-the-hash](https://secureteam.co.uk/articles/information-assurance/what-is-a-pass-the-hash-attack/)" attack.

Task: Can you find the file planted on the victim's computer using IOC Editor and Redline IOC Search Collector? 

So far, you only know the following artifacts for the file: 

**File Strings:** 
- 20210513173819Z0w0=
- <?<L<T<g=
**File Size (Bytes):**
- 834936

> Note: Use the existing Redline Session found in: C:\Users\Administrator\Documents\Analysis\Sessions\AnalysisSession1.

- creat IOC file using IOC Editor and add the artifcats

![Screenshot 2025-05-28 162854](https://github.com/user-attachments/assets/c517c59a-6568-434c-b817-406efa328da3)

- then open the Redline Session found in -> `C:\Users\Administrator\Documents\Analysis\Sessions\AnalysisSession1` 
- click on the **IOC Reports** and add your IOC file from **Creat a New IOC Report** option

![Screenshot 2025-05-28 164020](https://github.com/user-attachments/assets/7d4d672d-d7f5-4b21-b130-94f296ec7727)


---

## Answer the questions below


### Q1. Provide the path of the file that matched all the artifacts along with the filename.

![Screenshot 2025-05-28 164812](https://github.com/user-attachments/assets/aaa876bf-eff5-467e-b8a1-40ff404f815e)

Ans: ***C:\Users\Administrator\AppData\Local\Temp\8eJv8w2id6IqN85dfC.exe***

### Q3. Who is the owner of the file?

![Screenshot 2025-05-28 164907](https://github.com/user-attachments/assets/3e9ad9bd-d9a5-404f-9397-db21e1133fc1)

Ans: ***BUILTIN\Administrators***

### Q4. Provide the subsystem for the file.

- click on the *i* option, under the PE Info, copy the subsystem

![Screenshot 2025-05-28 165009](https://github.com/user-attachments/assets/9e0c5efc-51b2-4ddf-986e-a6a656f29e7c)


Ans: ***Windows_CUI***

### Q5. Provide the Device Path where the file is located.

- same location as the previous quetion, under File Info, copy the device path

Ans: ***\Device\HarddiskVolume2***

### Q6. Provide the hash (SHA-256) for the file.

- copy the MD5 hash under the file info and search for this md5 hash in the [VirusTotal](https://www.virustotal.com/gui/home/upload)

![Screenshot 2025-05-28 170258](https://github.com/user-attachments/assets/253160d8-4c22-4d39-8497-f542e7ed78bd)

Ans: ***57492d33b7c0755bb411b22d2dfdfdf088cbbfcd010e30dd8d425d5fe66adff4***

### Q7. The attacker managed to masquerade the real filename. Can you find it having the hash in your arsenal? 

- continue from the previous question and look under names option

![Screenshot 2025-05-28 170612](https://github.com/user-attachments/assets/a3cf0be5-ec9b-4d66-8d6e-2b3258c1b1bd)

Ans: ***PsExec.exe***


---
# TASK-7: Endpoint Investigation

Scenario : A Senior Accountant, Charles, is complaining that he cannot access the spreadsheets and other files he has been working on. He also mentioned that his wallpaper got changed with the saying that his files got encrypted. This is not good news!

Are you ready to perform the memory analysis of the compromised host? You have all the data you need to do some investigation on the victim's machine. Let's go hunting!

---

## Answer the questions below



### Q1.Can you identify the product name of the machine?

![Screenshot 2025-05-29 111546](https://github.com/user-attachments/assets/a221de73-33d8-459c-b890-ae67e1499b69)

Ans: ***Windows 7 Home Basic***

### Q2.Can you find the name of the note left on the Desktop for the "Charles"?

- search in the **processes** for notepad.exe

![Screenshot 2025-05-29 111822](https://github.com/user-attachments/assets/1c8c984f-adaa-41f1-98ad-af569c9dac27)

Ans: ***_R_E_A_D___T_H_I_S___AJYG1O_.txt***

### Q3.Find the Windows Defender service; what is the name of its service DLL? 

- search for windows defender in **windows services** section

![Screenshot 2025-05-29 112917](https://github.com/user-attachments/assets/e355fb2c-866d-447a-86fa-4c6eb15a4a0a)


Ans: ***MpSvc.dll***

### Q4.The user manually downloaded a zip file from the web. Can you find the filename? 

- search in the **File Download History** section for `.zip` file extention, then show details of that file

![Screenshot 2025-05-29 113200](https://github.com/user-attachments/assets/38f1955b-e60f-40da-b24f-b7912c62eeb0)

Ans: ***eb5489216d4361f9e3650e6a6332f7ee21b0bc9f3f3a4018c69733949be1d481.zip***

### Q5. Provide the filename of the malicious executable that got dropped on the user's Desktop.

- search in the **File System** section for files under desktop folder

![Screenshot 2025-05-29 121058](https://github.com/user-attachments/assets/dc415516-14f2-459a-ba4d-f42346e1f657)


Ans: ***Endermanch@Cerber5.exe***

### Q6. Provide the MD5 hash for the dropped malicious executable.

- the MD5 hash is under the file hashes in the details of `Endermanch@Cerber5.exe` file

Ans: ***fe1bc60a95b2c2d77cd5d232296a7fa4***

### Q7.What is the name of the ransomware? 

- [Virustotal](https://www.virustotal.com/gui/file/b3e1e9d97d74c416c2a30dd11858789af5554cf2de62f577c13944a19623777d/details)

Ans: ***Cerber***



# Refernces:

- *[Redline User Guide](https://fireeye.market/assets/apps/211364/documents/877936_en.pdf)*
- *[IOC Editor User Guide](https://fireeye.market/assets/apps/S7cWpi9W//9cb9857f/ug-ioc-editor.pdf)*

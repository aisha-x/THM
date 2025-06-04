# TryHackMe: Secret Recipe Challenge

Room URL: https://tryhackme.com/room/registry4n6


# Introduction

**Storyline**

Jasmine owns a famous New York coffee shop **Coffely** which is famous city-wide for its unique taste. Only Jasmine keeps the original copy of the recipe, and she only keeps it on her work laptop. Last week, James from the IT department was consulted to fix Jasmine's laptop. But it is suspected he may have copied the secret recipes from Jasmine's machine and is keeping them on his machine.Image showing a Laptop with a magnifying glass

His machine has been confiscated and examined, but no traces could be found. The security department has pulled some important **registry artifacts** from his device and has tasked you to examine these artifacts and determine the presence of secret files on his machine.


# Windows Registry Forensics

**Registry Recap**

Windows Registry is like a database that contains a lot of juicy information about the system, user, user activities, processes executed, the files accessed or deleted, etc.Image showing Registry icon

Following Registry Hives have been pulled from the suspect Host and placed in the `C:\Users\Administrator\Desktop\Artifacts` folder. All required tools are also placed on the path. `C:\Users\Administrator\Desktop\EZ Tools`.

Your challenge is to examine the registry hives using the tools provided, observe the user's activities and answer the questions.

**Registry Hives**

- SYSTEM
- SECURITY
- SOFTWARE
- SAM
- NTUSER.DAT
- UsrClass.dat

![Screenshot 2025-06-04 120917](https://github.com/user-attachments/assets/624a7e45-cc1d-443e-b6fe-c945f6d42964)

[Windows Forensics Cheat Sheet ](https://assets.tryhackme.com/cheatsheets/Windows%20Forensics%20Cheatsheet.pdf)


---

### Q1. What is the computer name of the machine found in the registry?

- Load the SYSTEM hive 
- location: `SYSTEM\ControlSet001\Control\ComputerName\ComputerName`

![Screenshot 2025-06-04 121614](https://github.com/user-attachments/assets/2811cd67-1da8-4844-895d-2054d74d044b)


Ans: ***JAMES***

---

### Q2.When was the Administrator account created on this machine? (Format: yyyy-mm-dd hh:mm:ss)

- load the SAM hive
- location: `SAM\Domains\Account\Users\Names\Administrator`

![Screenshot 2025-06-04 122233](https://github.com/user-attachments/assets/909fe029-1b22-411a-9bef-7d6e9fca3852)


Ans: ***2021-03-17 14:58:48***

---

### Q3.What is the RID associated with the Administrator account?

![Screenshot 2025-06-04 123715](https://github.com/user-attachments/assets/7a18da82-7597-48ab-b8d4-278adc11c02f)

Ans: ***500***

---

### Q4.How many user accounts were observed on this machine?

![Screenshot 2025-06-04 125101](https://github.com/user-attachments/assets/23126eaf-ef13-4c7d-afb6-1dcde9e5a060)


Ans: ***7***

---

### Q5.There seems to be a suspicious account created as a backdoor with RID 1013. What is the account name?

![Screenshot 2025-06-04 125149](https://github.com/user-attachments/assets/1763fcd2-49a5-4154-8cd9-63a61642209b)


Ans: ***bdoor***

---

### Q6. What is the VPN connection this host connected to?

- load the SOFTWARE hive
- location: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`

![Screenshot 2025-06-04 130428](https://github.com/user-attachments/assets/0f8a1e1f-c21c-4b2f-8fce-1e5b98c2fc03)


Ans: ***ProtonVPN***

---

### Q7.When was the first VPN connection observed? (Format: YYYY-MM-DD HH:MM:SS)

- location: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`

![Screenshot 2025-06-04 131004](https://github.com/user-attachments/assets/0757062c-d866-4d3f-aa5f-c64043693533)


Ans: ***2022-10-12 19:52:36***

---

### Q8. There were three shared folders observed on his machine. What is the path of the third share?

- in the SYSTEM hive
- location: `SYSTEM\ControlSet001\Services\LanmanServer\Shares`

![Screenshot 2025-06-04 131618](https://github.com/user-attachments/assets/657a5739-a951-4002-84a4-841c5a72d808)


Ans: ***C:\RESTRICTED FILES***

---

### Q9.What is the last DHCP IP assigned to this host?

- in the SYSTEM hive
- location: `SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{..}`

![Screenshot 2025-06-04 132221](https://github.com/user-attachments/assets/d930814c-28d6-46e6-866f-2979c4f98f83)

Ans: ***172.31.2.197***

---

### Q10. The suspect seems to have accessed a file containing the secret coffee recipe. What is the name of the file?


- location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf`

![Screenshot 2025-06-04 132938](https://github.com/user-attachments/assets/5c26f0f3-9600-4c32-86c7-4a3479e90cf6)


Ans: ***secret-recipe.pdf***

---

### Q11. The suspect executed multiple commands using the Run window. What command was used to enumerate the network interfaces?

- location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

![Screenshot 2025-06-04 135529](https://github.com/user-attachments/assets/6185cbbf-ce84-4048-a861-9d034bbf9998)

Ans: ***pnputil /enum-interfaces***

---


### Q12.The user searched for a network utility tool to transfer files using the file explorer. What is the name of that tool?

- location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

![Screenshot 2025-06-04 135654](https://github.com/user-attachments/assets/c5a73665-878d-4f5e-aa23-3605fec51819)

Ans: ***netcat***

---

### Q13. What is the recent text file opened by the suspect?

- location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt` 

![Screenshot 2025-06-04 135855](https://github.com/user-attachments/assets/b61f35a4-6169-4336-9580-06d8f1d4f8fd)


Ans: ***secret-code.txt***

---

### Q14. How many times was PowerShell executed on this host?

- location: `SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache`

![Screenshot 2025-06-04 141036](https://github.com/user-attachments/assets/edc28f3a-d7d7-4bca-865d-f2fe5fcea9d0)

- another location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`

![Screenshot 2025-06-04 142230](https://github.com/user-attachments/assets/5e0f69fe-0545-4e00-9c27-ae45a80754d6)

Ans: ***3***

---

### Q15. The suspect also executed a network monitoring tool. What is the name of the tool?

- location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`

![Screenshot 2025-06-04 142619](https://github.com/user-attachments/assets/b0e9b575-cddf-4dab-84e7-ed8bffa27d27)

Ans: ***wireshark***

---

### 16. Registry Hives also note the amount of time a process is in focus. Examine the Hives and confirm for how many seconds was ProtonVPN executed?

- location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`

![Screenshot 2025-06-04 143517](https://github.com/user-attachments/assets/071f79da-7eb3-4c5e-9247-73f29f3f93a0)

- another location: `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`

Ans: ***343***

---

### Q17. Everything.exe is a utility used to search for files in a Windows machine. What is the full path from which everything.exe was executed?

- location: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`

![Screenshot 2025-06-04 143838](https://github.com/user-attachments/assets/fbdab0cc-b1e4-420a-a4b7-00c4ed5bfbdf)

Ans: ***C:\Users\Administrator\Downloads\tools\Everything\Everything.exe***

---

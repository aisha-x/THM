# TryHackMe: Boogeyman 2 Challenge

Room URL: https://tryhackme.com/room/boogeyman2

# Introduction

After having a severe attack from the Boogeyman, Quick Logistics LLC improved its security defences. However, the Boogeyman returns with new and improved tactics, techniques and procedures

## Artefacts

For the investigation, you will be provided with the following artefacts:

- Copy of the phishing email.
- Memory dump of the victim's workstation.

# Tools:
- **Volatility** - an [open-source framework](https://github.com/volatilityfoundation/volatility3) for extracting digital artefacts from volatile memory (RAM) samples.
- **Olevba** - a tool for analysing and extracting VBA macros from Microsoft Office documents. This tool is also a part of the [Oletools suite.](https://github.com/decalage2/oletools)



---
# Spear Phishing Human Resources
The Boogeyman is back!

analyse and assess the impact of the compromise.

## Analysis Steps:

- cat the content of the email and save it in a txt file. 
- I used [Message Header Analyzer](https://mha.azurewebsites.net/) to paste the content of the email.
- the email sent from `westaylor23@outlook.com` to `maxine.beck@quicklogisticsorg.onmicrosoft.com`
- the attachment is named: **Resume_WesleyTaylor.doc**.

![Screenshot 2025-06-13 111611](https://github.com/user-attachments/assets/02c30ed5-4722-41e5-948a-c33fc53ea58a)

Copy the base64-encoding from the email content and rebuild the document file.

![Screenshot 2025-06-13 112525](https://github.com/user-attachments/assets/4f805700-d839-48fa-bda5-c55027471235)

Use this tool `olevba` to analyse and extract **Visual Basic macro** from the `.doc` file

![Screenshot 2025-06-13 113702](https://github.com/user-attachments/assets/cebe24f2-47b4-4a1a-ac1f-3eb83fd7f6b9)
![Screenshot 2025-06-13 113712](https://github.com/user-attachments/assets/c9d08c3a-063c-454f-8875-344f34198fdc)
![Screenshot 2025-06-13 113906](https://github.com/user-attachments/assets/a777b95b-a534-4d2d-94f4-cae489cae53f)


in **VirousTotal**, the code already have been analyzed. The macro downloaded a payload from the remote server, and saved it as a JavaScript file `js` in this path (`C:\ProgramData\update.js`), then used the process `wscript.exe` to execute `update.js` -> (`wscript.exe C:\ProgramData\update.js`). Now let's analyze the RAM. Use `vol <.raw> windows.pstree` to return the processes and their parent process.

![Screenshot 2025-06-13 134445](https://github.com/user-attachments/assets/03279983-3aa5-4396-ba35-4ac199c3be2e)
![Screenshot 2025-06-13 115639](https://github.com/user-attachments/assets/3de758d5-cf2b-47af-b469-8328883b5a8a)

At `2023-08-21 14:12:31`, the `.doc` file opened, which spawned the process `wscript.exe`. After the execution of the `wscript.exe`, it created a process to be used for **C2** connection, `updater.exe`. I used this plugin `windows.cmdline` to view the command-line used to launch a process.

![Screenshot 2025-06-13 121910](https://github.com/user-attachments/assets/48909dcb-4e67-465d-9791-f2ff744fd6db)

Use this plugin `windows.netscan` to view the IP address and port used for the C2 connection established by `updater.exe` process

![Screenshot 2025-06-13 124659](https://github.com/user-attachments/assets/0ddf7e16-adf5-43ba-bf6f-6dfe9a581e7b)

the ip address used for **C2** connection is `128.199.95.189` on port `8080`. To see if there is any persistence on the machine. Use `windows.memmap.Memmap` plugin to view memory mapping information for `updater.exe` process  

```bash 
vol -f WKSTN-2961.raw -o updater_dump/  windows.memmap.Memmap --pid 6216 --dump
```

Use `strings` command to look for ASCII strings, with option `-el` which allows you to extract **Unicode-encoded strings**. On Windows systems, many strings (like **file paths**, **commands**,**registry keys**) are stored in **UTF-16LE** format, where each character is stored as 2 bytes (little-endian). 
```bash
strings -el updater_dump/pid.6216.dmp | grep -iC 4 "powershell.exe"
```
![Screenshot 2025-06-13 142306](https://github.com/user-attachments/assets/601eff03-96b6-462d-999c-7346a19edf23)

This command creates a scheduled task named **"Updater"** that runs daily at **9:00 AM**. The task executes a hidden PowerShell command that:
   - Reads a value called **debug** from the Windows registry
   - Decodes that value from **Base64** (encoded as Unicode)
   - Executes the decoded code using **Invoke-Expression (IEX)**

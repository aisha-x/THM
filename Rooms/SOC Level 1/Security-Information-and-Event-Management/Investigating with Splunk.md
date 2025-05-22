# TryHackMe: Investigating with Splunk Challenge


Room URL: https://tryhackme.com/room/investigatingwithsplunk


# Investigating with Splunk
SOC Analyst Johny has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

## Answer the questions below

### Q1.How many events were collected and Ingested in the index main?

- `index="main"`

Ans: ***12256***

---

### Q2.On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?

- in the `sourcetype` field, there is only one log source, which is "event_logs"
- search in the logs for event id that relates to the creation of a new user on the system.
- 4720 ->  A user account was created. [source](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4720)
- `index="main" EventID=4720`

![Screenshot 2025-05-22 103907](https://github.com/user-attachments/assets/1e6c3a28-7cf8-4ec2-bcaa-5a15d983125d)

Ans: ***A1berto***

---

### Q3.On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

- `index="main" EventID="13" A1berto | spath Hostname | search Hostname="Micheal.Beaven"`
- 13 -> Registry value set. [source](https://learn.microsoft.com/ar-sa/sysinternals/downloads/sysmon)

![Screenshot 2025-05-22 105130](https://github.com/user-attachments/assets/6daad650-45e7-4024-af0c-6f8538d64801)

- `sass.exe` set a registry value under `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`
- The timestamp matches exactly: `2022-02-14 08:06:02` the user creation 

Ans: ***HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto***

---

### Q4.Examine the logs and identify the user that the adversary was trying to impersonate.

- `index="main"` 
- if we look in the "User" field, we will find a user named "Cybertees\Alberto"
- The real Alberto is located in the "James.browne" machine. 

Ans: ***Alberto***

---

### Q5.What is the command used to add a backdoor user from a remote computer?

- `index="main" "powershell.exe" EventID="1"`
- 1 -> process creation

![Screenshot 2025-05-22 122844](https://github.com/user-attachments/assets/9ddc0378-f977-4dd2-af76-4fecb5edffa0)

- An account named `A1berto` was added remotely to the system `WORKSTATION6` by issuing this `WMI` command
- `WMIC.exe` Windows Management Instrumentation Command-line tool. It's used to execute management tasks locally or remotely.
- The creation of a new user (`A1berto`) using a hardcoded password (`paw0rd1`) shows manual or scripted control.
- The use of `/node:<target>` shows remote execution.

Ans: ***C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1***

---

### Q6.How many times was the login attempt from the backdoor user observed during the investigation?

- `index="main"  EventID="4625"`
- 4625 -> An account failed to log on. [source](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j)

Ans: ***0***

---

### Q7.What is the name of the infected host on which suspicious PowerShell commands were executed?


Ans: ***James.browne***

---

### Q8.PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

- `index="main" powershell.exe`
- Inspect the Channel field

![Screenshot 2025-05-22 135059](https://github.com/user-attachments/assets/a9c11894-9bcd-4d05-bacb-1fbbc7284e20)

- There are two channel logging Powershell execution, and the channel -> **Microsoft-Windows-PowerShell/Operational** is the answer
- `index="main" powershell.exe  Channel="Microsoft-Windows-PowerShell/Operational"`
- 4103 ->  Module logging – Attackers uses several obfuscated commands and calls self-defined variables and system commands. [Source ](https://www.iblue.team/incident-response-1/logging-powershell-activities)

Ans: ***79***

---

### Q9.An encoded Powershell script from the infected host initiated a web request. What is the full URL?

- `index="main" "powershell.exe" A1berto`

![Screenshot 2025-05-22 131321](https://github.com/user-attachments/assets/6f995b86-809f-46c2-8416-7802973e40d8)

- in the "Host Application" field, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc <Base64String>`
- `-NoProfile` –> Prevents PowerShell from loading the user's profile script. Used to make execution faster and stealthier.
- `-STA ` –> Uses Single Threaded Apartment mode (required for certain .NET components). Not suspicious alone.
- `-WindowStyle Hidden` –> Hides the PowerShell window to avoid user noticing.
- `-EncodedCommand` –> Runs a Base64-encoded UTF-16LE PowerShell command (often obfuscated).

- use [base64decode](https://www.base64decode.org/) to decode base64-encoded command

![Screenshot 2025-05-22 132135](https://github.com/user-attachments/assets/b84feaf4-cffc-42cb-bee5-e82968a73c28)

- In the decoded command, there is also base64-encoded, decode this encoding part

![Screenshot 2025-05-22 132335](https://github.com/user-attachments/assets/f317ce62-a55f-4098-9bd4-784bf8977edb)

- `http://10.10.10.5` add this part also `/news.php` and use [CyberChef](https://gchq.github.io/CyberChef/) to URL defang 

Ans: ***hxxp[://]10[.]10[.]10[.]5/news[.]php***

---
# Finding

## in the log:
- **Three Machine**: James.browne, Micheal.Beaven and Salena.Adam
- **Four Users**: NT AUTHORITY\SYSTEM, Cybertees\Alberto, NT AUTHORITY\NETWORK SERVICE and Cybertees\James
- **Domain**: NT AUTHORITY, and Cybertees


## Findings

1. `2022-02-14 08:06:01`, the attacker executed a PowerShell command to create a new user account named A1berto from `James.browne` machine, using Cybertees\James account 
2. This command executed on the Micheal.Beaven machine and updated the registry key 
3. Now both the machines "Micheal.Beaven and James.browne" are infected 
4. The attacker is trying to impersonate a legitimate account `Cybertees\Alberto`
5. Lastly, the attacker used James, who is from the Cybertees domain to execute a malicious pwershell command 
   - `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc SQBGACgAJABQAFMA...`
   - What does this command do?
      - Disable PowerShell Script Block Logging to evade detection.
      - Download and execute a remote payload via PowerShell WebClient or a proxy.
      - Use multiple layers of obfuscation with: Random variable names, Encoded strings, Reflection, and System.Management.Automation classes
      - Manipulate PowerShell environment settings (e.g., ExecutionPolicy, logging).
      - Potentially load shellcode or perform memory injection 

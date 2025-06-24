
# TryHackMe: Sighunt Challenge

Room URL: https://tryhackme.com/room/sighunt



----
# Scenario

You are hired as a Detection Engineer for your organization. During your first week, a ransomware incident has just concluded, and the Incident Responders of your organization have successfully mitigated the threat. With their collective effort, the Incident Response (IR) Team provided the IOCs based on their investigation. Your task is to create Sigma rules to improve the detection capabilities of your organization and prevent future incidents similar to this.

**Indicators of Compromise**

Based on the given incident report, the Incident Responders discovered the following attack chain:

- Execution of malicious HTA payload from a phishing link.
- Execution of Certutil tool to download Netcat binary.
- Netcat execution to establish a reverse shell.
- Enumeration of privilege escalation vectors through PowerUp.ps1.
- Abused service modification privileges to achieve System privileges.
- Collected sensitive data by archiving via 7-zip.
- Exfiltrated sensitive data through cURL binary.
- Executed ransomware with huntme as the file extension. 



---

**1. HTA payload**:

```yml
title: HTA payload
id: 10000004
status: experimental
description: Execution of malicious HTA payload from a phishing link
author: Aisha
date: 24/6/2025
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    ParentImage|endswith: 'chrome.exe'
    Image|endswith: 'mshta.exe'
    CommandLine|contains: '.hta'
  condition: selection 
fields: 
  - Image
  - ParentImage
  - CommandLine
  - EventID
```

---

**2. Certutil Download**: 

```yml
title: Certutil Download
id: 10000005
status: experimental
description: Execution of Certutil tool to download Netcat binary
author: Aisha 
date: 24/6/2025
logsource: 
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: 'certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-split'
      - '-f'
  condition: selection 
fields: 
  - Image
  - CommandLine
  - ParentCommandLine
  - ParentImage
```

----


**3. Netcat Reverse Shell**:

```yml
title: Netcat Reverse Shell
id: 10000006
status: experimental
description: Netcat execution to establish a reverse shell
author: Aisha 
date: 2025/06/24
logsource: 
  product: windows
  service: sysmon

detection:
  selection_1:
    EventID: 1
    Image|endswith: 'nc.exe'
    CommandLine|contains|all: 
      - ' -e '

  selection_hashes:
    EventID: 1
    Hashes|contains:
      - "MD5=523613A7B9DFA398CBD5EBD2DD0F4F38"
      - "SHA256=3E59379F585EBF0BECB6B4E06D0FBBF806DE28A4BB256E837B4555F1B4245571"
      - "IMPHASH=567531F08180AB3963B70889578118A3"

  condition: selection_1 OR selection_hashes

fields: 
  - EventID
  - Image
  - CommandLine
  - Hashes
```

----

**4. PowerUp Enumeration**:

```yml
title: PowerUp Enumeration
id: 10000007
status: experimental
description: Enumeration of privilege escalation vectors through PowerUp.ps1.
author: Aisha 
date: 24/6/2025
logsource: 
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: 'powershell.exe'
    CommandLine|contains:
      - 'Invoke-AllChecks'
      - 'PowerUp.ps1'
  condition: selection 
fields: 
  - Image
  - CommandLine
  - EventID
```

---

**5. Service Binary Modification**

```yml
title: Service Binary Modification
id: 10000008
status: experimental
description: Abused service modification privileges to achieve System privileges
author: Aisha 
date: 24/6/2025
logsource: 
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: 'sc.exe'
    CommandLine|contains|all:
      - ' config '
      - ' binPath= '
  condition: selection 
fields: 
  - Image
  - CommandLine
  - EventID
```


----

**6. RunOnce Persistence**	


```yml
title: RunOnce Persistence
id: 10000009
status: experimental
description: A potentially malicious executable is set to run on next boot
author: Aisha 
date: 24/6/2025
logsource: 
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: 'reg.exe'
    CommandLine|contains:
      - '\RunOnce'
      - ' add '
  condition: selection 
fields: 
  - Image
  - CommandLine
  - EventID
```


---

**7. 7-zip Collection**	

```yml
title: 7-zip Collection	
id: 100000010
status: experimental
description: Collected sensitive data by archiving via 7-zip.
author: Aisha 
date: 24/6/2025
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: '7z.exe'
    CommandLine|contains|all:
      - ' a '
      - ' -p'
  condition: selection 
fields: 
  - Image
  - CommandLine
  - EventID
```

---

**8. cURL Exfiltration**:

```yml
title: cURL Exfiltration
id: 100000011
status: experimental
description: Exfiltrated sensitive data through cURL binary.
author: Aisha 
date: 24/6/2025
logsource: 
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: 'curl.exe'
    CommandLine|contains:
      - ' curl '
      - ' -d '
  condition: selection 
fields: 
  - Image
  - CommandLine
  - EventID
```


---

**9. Ransomware File Encryption**:

```yml
title: Ransomware File Encryption
id: 100000012
status: experimental
description: Executed ransomware with huntme as the file extension. 
author: Aisha 
date: 24/6/2025
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
      - 11 
    TargetFilename|contains|all:
      - '*.huntme'
  condition: selection 
fields: 
  - Image
  - TargetFilename
  - EventID
```

# TryHackMe: Volatility Room Summary

Room URL: https://tryhackme.com/room/volatility


1. [Volatility3 Forensics Summary](#volatility3-forensics-summary)
2. [Practical Investigations](#practical-investigations)



---
# Volatility3 Forensics Summary


- **Volatility3** is the updated version of Volatility (rewritten in Python 3).
- Old **OS profiles are deprecated**; Volatility3 **automatically detects OS and build**.
- Plugin structure now requires specifying the OS:
  - `windows.<plugin>`
  - `linux.<plugin>`
  - `mac.<plugin>`
- Use the help menu to explore available plugins:
```bash
  python3 vol.py -h
 ```

## Memory Image Detection

- In **Volatility2**, you needed exact OS profiles.
- In **Volatility3**, use the following plugins to identify host info:
  - `windows.info`
  - `linux.info`
  - `mac.info`
```bash
  python3 vol.py -f <file> windows.info
```
- Deprecated in Volatility3: `imageinfo`

## Process and Network Plugins

### 1. **pslist**
- Lists processes from the doubly-linked list (like Task Manager).
- Shows current + terminated processes.
```bash
python3 vol.py -f <file> windows.pslist
```

### 2. **psscan**
- Scans memory for `_EPROCESS` structures.
- Useful for detecting hidden/malicious processes (e.g., rootkits).
```bash
python3 vol.py -f <file> windows.psscan
```

### 3. **pstree**
- Displays processes in parent-child hierarchy.
- Helps understand process lineage and behavior.
```bash
python3 vol.py -f <file> windows.pstree
```

### 4. **netstat**
- Shows active network connections from memory.
- May be unstable on old Windows versions.
```bash
python3 vol.py -f <file> windows.netstat
```
- For better PCAP extraction: consider using `bulk_extractor`.

### 5. **dlllist**
- Lists all DLLs associated with running processes.
- Useful in malware investigation.
```bash
python3 vol.py -f <file> windows.dlllist
```

## Malware Hunting & Detection

### 1. **malfind**
- Detects code injection in memory (e.g., shellcode, fileless malware).
- Displays Hex, ASCII, and disassembly of suspicious regions.
```bash
python3 vol.py -f <file> windows.malfind
```

### 2. **yarascan**
- Scans memory using custom or predefined **YARA rules**.
```bash
python3 vol.py -f <file> windows.yarascan
```

## Advanced Memory Analysis

### Hooking Techniques:
Common evasion method used by rootkits. Types include:
- SSDT Hooks ✅
- IRP Hooks
- IAT Hooks
- EAT Hooks
- Inline Hooks

We focus on **SSDT Hooking**.

### 1. **ssdt**
- Dumps System Service Descriptor Table entries.
- Detects modifications (hooks) made by malware.
```bash
python3 vol.py -f <file> windows.ssdt
```

## Driver Analysis

### 1. **modules**
- Lists **loaded kernel modules** (active drivers).
- Useful for identifying suspicious drivers.
```bash
python3 vol.py -f <file> windows.modules
```

### 2. **driverscan**
- Scans memory for driver structures that may not be active.
- Useful when `modules` misses something.
```bash
python3 vol.py -f <file> windows.driverscan
```

## Additional Useful Plugins

Some may be Volatility2-only or require third-party modules:

- `modscan` – scans for hidden modules  
- `driverirp` – analyzes driver I/O routines  
- `callbacks` – inspects system callbacks  
- `idt` – analyzes interrupt descriptor table  
- `apihooks` – detects API hooking in memory  
- `moddump` – dumps kernel modules to disk  
- `handles` – lists open handles in memory

>  **Tip**: Combine these tools with contextual investigation for best results. Not all suspicious entries are malicious—your judgment as an analyst matters most.


---
# Practical Investigations




---

## CASE-1: BOB! THIS ISN'T A HORSE!

Your SOC has informed you that they have gathered a memory dump from a quarantined endpoint thought to have been compromised by a banking trojan masquerading as an Adobe document. Your job is to use your knowledge of threat intelligence and reverse engineering to perform memory forensics on the infected host. 

You have been informed of a suspicious IP in connection to the file that could be helpful. 41.168.5.140

The memory file is located in `/Scenarios/Investigations/Investigation-1.vmem `


### Q1. What is the build version of the host machine in Case 001?

```bash
python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem  windows.info
```
![Screenshot 2025-05-30 132251](https://github.com/user-attachments/assets/5365cb6f-9a3d-489c-9a80-2b7b75655295)

Ans: ***2600.xpsp.080413-2111***

### Q2. At what time was the memory file acquired in Case 001?

- in the SystemTime value from the preivous question
Ans: ***2012-07-22 02:45:08***


### Q3.What process can be considered suspicious in Case 001? Note: Certain special characters may not be visible on the provided VM. When doing a copy-and-paste, it will still copy all characters.

```bash
python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem  windows.psscan
```
![Screenshot 2025-05-30 132948](https://github.com/user-attachments/assets/7b93df71-3f72-4c5f-99b1-3bbd32adb21a)


Ans: ***reader_sl.exe ***


### Q4. What is the parent process of the suspicious process in Case 001?

```bash
python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem  windows.pstree
```
![Screenshot 2025-05-30 133223](https://github.com/user-attachments/assets/171d0b5c-584f-48fb-8fb8-c53507a8de61)

- inspect the PPID
Ans: ***explorer.exe***



### Q5. What is the PID of the suspicious process in Case 001?

Ans: ***1640***


### Q6. What is the parent process PID in Case 001?

Ans: ***1484***


### Q7. What user-agent was employed by the adversary in Case 001?

- use `windows.memmap.Memmap` plugin:
    - It shows all virtual memory pages mapped to a process.
    - It helps identify where in memory a process has loaded code, data, DLLs, etc.
    - With `--dump`, it saves each memory region for further offline analysis (e.g., reverse engineering malware).

```bash
sudo python3 vol.py -f /Scenarios/Investigations/Investigation-1.vmem -o case-1 windows.memmap.Memmap --pid 1484 --dump
```
- then use `strings` command to extract readable strings

```bash
sudo strings case-1/pid.1484.dmp  | grep -i "user-agent"
```

![Screenshot 2025-05-30 134531](https://github.com/user-attachments/assets/4314d3fc-2c01-4d11-85d7-d63da3fa3ad9)


Ans: ***Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)***


### Q8.Was Chase Bank one of the suspicious bank domains found in Case 001? (Y/N)

- search in the dump for the chase bank and if any result returned, then it is suspicious
```bash
sudo strings case-1/pid.1484.dmp  | grep "chase"
```
Ans: ***y***

---

## CASE-2: That Kind of Hurt my Feelings
You have been informed that your corporation has been hit with a chain of ransomware that has been hitting corporations internationally. Your team has already retrieved the decryption key and recovered from the attack. Still, your job is to perform post-incident analysis and identify what actors were at play and what occurred on your systems. You have been provided with a raw memory dump from your team to begin your analysis.

The memory file is located in `/Scenarios/Investigations/Investigation-2.raw`


### Q9. What suspicious process is running at PID 740 in Case 002?


```bash
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.psscan | grep "740"
```
![Screenshot 2025-05-30 141221](https://github.com/user-attachments/assets/e0a01fc0-64e2-4dbe-972d-44c294ae1e06)


Ans: ***@WanaDecryptor@***

### Q10. What is the full path of the suspicious binary in PID 740 in Case 002?

```bash
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.dlllist | grep "740"
```
![Screenshot 2025-05-30 141504](https://github.com/user-attachments/assets/e337117d-321c-4568-9af1-576b05d31ff7)


Ans: ***C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe***


### Q11. What is the parent process of PID 740 in Case 002?

- first use `pstree` plugin to list parent processes and grep the suspicious process `740`, it will return the PPID.
- grep the PPID to view the process that initiated this suspicious process

```bash
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.pstree | grep "1940"
```
![Screenshot 2025-05-30 141657](https://github.com/user-attachments/assets/d9ab0524-eae0-4a4c-8d69-72d1b587ef7b)


Ans: ***tasksche.exe***


### Q12. What is the suspicious parent process PID connected to the decryptor in Case 002?


Ans: ***1940***

### Q13. From our current information, what malware is present on the system in Case 002?

- WanaDecryptor is the name of the ransomware interface used by the WannaCry ransomware.
- WannaCry is a type of ransomware worm that spreads rapidly across networks.
- for more info visit-> [wikipedia](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack)

Ans: ***WannaCry***


### Q14. What DLL is loaded by the decryptor used for socket creation in Case 002?

- search for [WanaDecryptor virustotal](https://www.virustotal.com/gui/file/d013be1440f64e234c7631f2a3bb1b4d7c12bcb97d3804dc0e66753cde13ebc8/details).
- in the Details tab, under the imports section.

![Screenshot 2025-05-30 145638](https://github.com/user-attachments/assets/0c666b55-9fb8-481f-a786-aa96c1fb0911)

- **WS2_32.dll** is the Windows Sockets API (Winsock) 2.0 dynamic link library. It provides the core functions needed for network communication on Windows systems.

Ans: ***WS2_32.dll***


### Q15. What mutex can be found that is a known indicator of the malware in question in Case 002?

- In Windows, a **Mutant** (short for Mutual Exclusion Object, also known as a **Mutex**) is a type of synchronization object used to prevent multiple processes or threads from accessing a shared resource at the same time.

```bash
python3 vol.py -f /Scenarios/Investigations/Investigation-2.raw windows.handles |grep -i "mutant" |grep 1940
```
![Screenshot 2025-05-30 150811](https://github.com/user-attachments/assets/0fe4ad31-5320-4b07-9ca2-d3c6681eb843)

Ans: ***MsWinZonesCacheCounterMutexA***


### Q16. What plugin could be used to identify all files loaded from the malware working directory in Case 002?

- windows.filescan -> Scans for file objects present in a particular windows
Ans: ***windows.filescan***



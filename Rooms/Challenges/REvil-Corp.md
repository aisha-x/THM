# Tryhackme: REvil Corp Challenge

Room URL: https://tryhackme.com/room/revilcorp

## Scenario

**Scenario**: One of the employees at Lockman Group gave an IT department the call; the user is frustrated and mentioned that all of his files are renamed to a weird file extension that he has never seen before. After looking at the user's workstation, the IT guy already knew what was going on and transferred the case to the Incident Response team for further investigation.

Your Task: Investigate the incident using **Redline** tool.

## Before Analyzing: Redline Overview

**Redline** is a powerful free tool by FireEye, used for host-based forensic investigations—especially focused on memory and file system analysis

Based on [the Redline user guide](https://fireeye.market/assets/apps/211364/documents/700848_en.pdf), follow this approach:

1. **Preparation Phase**:
   - Install Redline on your analysis machine.
   - Determine whether you’ll:
      - Use Live Response (pull data from a live host over the network).
      - Or do dead disk/memory analysis (collect data then analyze separately).

2. **Collection Phase** (using Redline Collector)
   - Redline has three collector types:
      - Standard Collector
      - Comprehensive Collector
      - IOC Search Collector
   - Once you have selected the collector type, you can select the data you want to collect from the target host. Such as:
      - Memory dump (if possible)
      - File system metadata
      - Registry
      - Services, processes, drivers, scheduled tasks
      - Network connections
      - Browser history, etc.
3. **Analysis Phase**:
Use Analysis Session in Redline to:
   - Load the memory or data dump.
   - Look at:
      - **Processes**: Unusual names, unsigned binaries, suspicious paths (e.g., C:\Users\Public\).
      - **Network connections**: Unexpected IPs, uncommon ports.
      - **Services and Drivers**: Check for untrusted entries or persistence.
      - **Scheduled tasks and Autostart locations**.
      - **Loaded modules and injected code**.
      - **Use Indicators of Compromise (IOC)** if you have any YARA rules or hashes.
4. **Pivot & Correlate**
   - Based on findings, pivot deeper:
      - Find parent/child process anomalies (e.g., Word spawning PowerShell).
      - Trace registry or scheduled task persistence.
      - Check timestamps and correlate with alert/incident timeline.
5. **Export Evidence / Reporting**
   - Export IOC hits, memory indicators, and suspicious artifacts.
   - Write a timeline of events and map to MITRE ATT&CK if possible.
   - Optionally import into tools like IOC Editor or Mandiant MIR for further analysis.

## System Information

**System Information**: includes operating system, the user account used to collect the data (e.g., run
the Redline Collector), and BIOS information. To view system information, select System Information on the Analysis Data window’s Host tab.

<img width="1434" height="734" alt="Screenshot 2025-07-23 130533" src="https://github.com/user-attachments/assets/b20c254b-f553-432e-ae1e-84e5e3542c8d" />

- The username: John Coleman
- Operating system: Windows 7 Home Premium 7601 Service Pack 1
- System Time: `2021-08-02 23:05:05Z` -> the collection occurred

## Initial infection

**File Download History**: Search for downloaded files

<img width="1914" height="750" alt="Screenshot 2025-07-23 225006" src="https://github.com/user-attachments/assets/ff74d34b-0a4f-4b9f-b9b0-3d14d44f2558" />

Suspicious Executable:
- Execution Time: `2021-08-02 19:42:16Z`
- The executable:` WinRAR2021.exe`
- Full path: `http[://]192.168.75.129[:]4748/Documents/WinRAR2021.exe`
- MD5 Hash: `890a58f200dfff23165df9e1b088e58f`
- [Malware Analysis on AlienVault OTX](https://otx.alienvault.com/indicator/file/5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93/)

Redline shows this file as the entry point of the infection. The next step is to investigate how far this malware speared and what did it effect.  

<img width="1883" height="649" alt="Screenshot 2025-07-23 224506" src="https://github.com/user-attachments/assets/80fd1bda-e11f-4788-a786-e5e821120ec0" />


### Malware Behavior

The ransomware created the following artifacts:
- `d60dff40.lock` – Hidden, Archive file (possibly encrypted file or marker)
- `t48s39la-readme.txt` – Likely the ransom note

**Timeline**: This tab provides a list of events sorted by time, which can be an overwhelming number of events. Adjust the event by checking how many files got affected and renamed to this extension `.48s39la` . Under files, check modified and changed, and set this regex filter -> `^.*\.*\.t48s39la`.

<img width="1904" height="776" alt="Screenshot 2025-07-23 231817" src="https://github.com/user-attachments/assets/0d3d5590-007c-49a9-b894-cde1c519a2f3" />

This reveals 48 encrypted files.

### Dropped Ransom Note

The ransomware appears to have dropped a ransom note in various folders, including system favorites. This `.url.t48s39la` file was likely created to overwrite or confuse the victim. Inspect the File System tab and look under the Favorites folder to view more modified files.

<img width="1528" height="754" alt="image" src="https://github.com/user-attachments/assets/0c5d748d-1658-4805-9722-faae5e7f679b" />
<img width="1821" height="849" alt="Screenshot 2025-07-23 233558" src="https://github.com/user-attachments/assets/4b7b2244-6e71-4f37-a8a0-f850eaec72a8" />


## Second Infection

The second infection happened when the user downloaded a **decryptor** hoping to recover all the files, but instead downloaded another malware.

<img width="1917" height="897" alt="Screenshot 2025-07-23 234230" src="https://github.com/user-attachments/assets/f6fbcf42-e4a4-4f99-9836-cf34c0fdc321" />


- Binary name -> `d.e.c.r.yp.tor.exe`
- Execution time -> `2021-08-02 19:50:07Z`
- [VirusTotal Report](https://www.virustotal.com/gui/file/e0ae340425fbb9afd4a463345d1fb470bd81110c4ae6a89f1727a8307a4070db)

**Browser URL History**: Redline displays information about URLs viewed using Microsoft Internet Explorer, Firefox, and Chrome. Check this tab to confirm this activity

<img width="1654" height="712" alt="Screenshot 2025-07-23 235255" src="https://github.com/user-attachments/assets/a20d0652-5ba6-4f09-9a0a-82d3e6d0e193" />


The user visited the following suspicious domain before downloading the fake decryptor:
- `http[:]//decryptor[.]top/644E7C8EFA02FBB7` at `2021-08-02 19:48:23Z`



## Timeline of Events

- `2021-08-02 19:42:16Z`: User executed **WinRAR2021.exe**
- `2021-08-02 19:46:00Z`: Ransom note created in Desktop/Documents
- `2021-08-02 19:46:00Z`: 48 files begin renaming to `*.t48s39la`
- `2021-08-02 19:48:23Z`: Visited a suspicious website `http[://]decryptor[.]top/644E7C8EFA02FBB7`
- `2021-08-02 19:50:07Z`: Executed **d.e.c.r.yp.tor.exe**


## Reference
- *[Incident Response & Computer Forensics](https://www.ibm.com/think/topics/dfir)*
- *[Typical Incident Response Approach with Redline](https://fireeye.market/assets/apps/211364/documents/700848_en.pdf)*

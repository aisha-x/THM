# TryHackMe: Windows Forensics 2 Room Summary

Room URL: https://tryhackme.com/room/windowsforensics2

---
# TASSK-2: File Systems: FAT and exFAT Overview

Storage devices like hard drives and USB devices are just collections of bits. To make this data meaningful, it must be organized using file systems. One such system is the **File Allocation Table (FAT)**.


## The File Allocation Table (FAT)

Developed in the late 1970s, FAT has been widely used in Microsoft operating systems and is still found in USB drives and digital cameras today.

### Data Structures in FAT:

- **Clusters**: Basic storage units. A file is made up of one or more clusters.
- **Directory**: Contains metadata like file name, starting cluster, and file length.
- **File Allocation Table**: A linked list indicating the status of each cluster and pointing to the next cluster.

### How it Works:

- Files are stored in **clusters**.
- File metadata is stored in **directories**.
- The structure and location of file data are tracked using the **File Allocation Table**.


## FAT Variants: FAT12, FAT16, FAT32

| Attribute                 | FAT12        | FAT16         | FAT32             |
|--------------------------|--------------|---------------|-------------------|
| Addressable bits         | 12-bit       | 16-bit        | 28-bit (actual)   |
| Max number of clusters   | 4,096        | 65,536        | 268,435,456       |
| Cluster size             | 512B - 8KB   | 2KB - 32KB    | 4KB - 32KB        |
| Max volume size          | 32MB         | 2GB           | 2TB (Windows: 32GB limit) |

> **Note**: Actual file size limit is ~4GB for both FAT16 and FAT32. FAT12 is now obsolete.


## The exFAT File System

To overcome FAT32 limitations, especially for high-res media, Microsoft developed **exFAT**.

### Features:

- **Cluster size**: 4KB – 32MB
- **Max file size**: 128PB
- **Max volume size**: 128PB
- **Max files per directory**: 2,796,202
- Designed for efficiency and lower overhead.
- Widely used in SD cards >32GB and digital cameras.

## Summary

- **FAT12**: Rare today, very small storage.
- **FAT16**: Still used, but has limits.
- **FAT32**: Popular but limited to 4GB max file size.
- **exFAT**: Modern replacement, supports massive file sizes and volumes with reduced overhead.


---
# TASK-3: The NTFS File System

As storage demands and the need for reliability, security, and recovery grew beyond the capabilities of the FAT file system, Microsoft introduced the **New Technology File System (NTFS)** in 1993 with Windows NT 3.1. It became widely used starting with **Windows XP**.


## Key Features of NTFS

### Journaling
- NTFS maintains a **log of metadata changes**.
- Helps recover from crashes and defragmentation events.
- The log is stored in a special file called **`$LOGFILE`**.
- Enables NTFS to be categorized as a **journaling file system**.

### Access Controls
- Supports **per-user file and folder permissions**.
- Adds **security and ownership** features not available in FAT.
- Essential for **multi-user environments** and enterprise systems.

### Volume Shadow Copy
- Tracks file changes using **shadow copies**.
- Allows **restoration of previous versions** of files.
- Frequently targeted by **ransomware**, which deletes shadow copies to block recovery.

### Alternate Data Streams (ADS)
- Allows multiple **data streams in a single file**.
- Used by browsers (e.g., Internet Explorer) to add metadata such as zone identifiers.
- Sometimes **abused by malware** to hide malicious code.


## Master File Table (MFT)

Unlike FAT, NTFS uses the **Master File Table (MFT)** — a structured database that contains metadata and tracks all objects in the file system.

### Key MFT Files

| MFT File     | Description |
|--------------|-------------|
| **`$MFT`**     | First record in a volume; tracks all files and directories. |
| **`$LOGFILE`** | Stores the metadata transaction log. |
| **`$UsnJrnl`** | Update Sequence Number (USN) Journal that logs file system changes. Found under the **`$Extend`** record. |

> The **Volume Boot Record (VBR)** points to the `$MFT` location.


## Forensic Tool: MFTECmd

**MFT Explorer** and **MFTECmd** by *Eric Zimmerman* allow forensic analysis of NTFS file structures.

### MFTECmd Usage
```bash
MFTECmd.exe -f <path-to-$MFT-file> --csv <path-to-save-results-in-csv>
```
- Parses ``$MFT``, `$Boot`, and other NTFS files.
- Outputs parsed data into CSV format for easy analysis.

### Where to find $MFT (Master File Table) on an NTFS volume:

- `$MFT` is stored in the root directory of every NTFS partition.
- It is a hidden system file, so you won’t see it in File Explorer even with "Show hidden files" enabled.
  However, it’s always there. NTFS requires $MFT to function.

**Typical Path (not visible to normal users):**
```bash
C:\$MFT
```
## How to Access or Extract $MFT
1. FTK Imager (Windows GUI tool)
2. Using `MFTECmd` by Eric Zimmerman
```bash
MFTECmd.exe -f "$MFT" --csv output_folder
```
---

## Answer the questions below

### Q1. Parse the $MFT file placed in C:\users\THM-4n6\Desktop\triage\C\ and analyze it. What is the Size of the file located at .\Windows\Security\logs\SceSetupLog.etl
- parse the `$MFT` file and extracted it as csv using `MFTECmd.exe`
```bash
MFTECmd.exe -f "C:\users\THM-4n6\Desktop\triage\C\$MFT" --csv "C:\users\THM-4n6\Desktop\Task-2"
```
- then use EZviewer tool to view the csv file

![Screenshot 2025-05-25 161438](https://github.com/user-attachments/assets/804c1fb9-132a-4447-83e9-c41790b5be66)


Ans: ***49152***

### Q2. What is the size of the cluster for the volume from which this triage was taken?

- parse the `$Boot` file
```bash
MFTECmd.exe -f "C:\users\THM-4n6\Desktop\triage\C\$Boot" --csv "C:\users\THM-4n6\Desktop\Task-2"
```

![Screenshot 2025-05-25 162045](https://github.com/user-attachments/assets/ffc1c274-6460-40de-b0e1-cb4408c90587)


| Field              | Meaning                     | Why It Matters in Forensics                 |
|--------------------|-----------------------------|---------------------------------------------|
| `$MFT cluster`     | Start of file metadata      | Locate or extract MFT                       |
| `Cluster size`     | 4 KB                        | File carving, slack space                   |
| `Boot code`        | `EB 52 90`                  | Validate bootable code                      |
| `Volume serial`    | Disk ID                     | Timeline correlation, volume ID matching    |
| `$MFTMirr`         | Redundancy for $MFT         | Recovery, anti-forensics analysis           |
| `FILE entry size`  | 1024 bytes per MFT record   | Understand structure of MFT entries         |
| `Index entry size` | 4 KB for directories        | Analyze and parse directory structures      |
| `55 AA`            | Boot sector valid signature | Verifies this is a bootable NTFS partition  |

Ans: ***4096***



---
# TASK-4: Deleted Files and Data Recovery

Understanding how file systems work helps in grasping **how files are deleted, recovered, or permanently wiped**.


## What Happens When a File is Deleted?

- File systems store the **location of file data** in a table/database (e.g., FAT, MFT).
- **Deleting a file** removes its **entry in the table**, not the actual file content.
- The clusters where the file resided are marked **unallocated** and **available for reuse**.
- Until the data is **overwritten**, it can often be **recovered**.

## Key Concepts

### Unallocated Clusters
- Portions of disk space that were used but are now marked free.
- May still contain remnants of deleted files.
- Can be examined to recover deleted data.

### File Recovery via File Signatures
- File recovery tools recognize known **file signatures** (headers/footers) in raw data.
- Tools can **scan hex data** to detect and recover files without relying on file system structures.


## Disk Image Files

A **disk image** is a **bit-by-bit copy** of an entire disk.

### Benefits:
1. **Preserves evidence** — forensic analysis does not affect the original disk.
2. **Reusability** — disk images can be analyzed multiple times or shared with others.

### Disk Image Formats
- `.img`, `.dd`, `.iso`, `.E01` and others depending on the tool used.

---

## File Recovery with Autopsy

[**Autopsy**](https://www.sleuthkit.org/autopsy/) is a **GUI-based digital forensics tool** built on top of The Sleuth Kit (TSK).

### Steps to Recover Deleted Files Using Autopsy:

1. **Install Autopsy** (available for Windows, macOS, and Linux).
2. **Launch Autopsy** and create a new case:
   - Provide a case name, number, and examiner details.
3. **Add a data source**:
   - Choose **“Disk Image or VM File”** and browse to select the disk image file.
4. Autopsy will parse the image and identify file systems (e.g., FAT32, NTFS).
5. Go to the **“Deleted Files”** or **“File Type”** tab to review recoverable files.
6. **Export or carve files** that are still intact and recoverable.

### Features of Autopsy:
- Carves deleted files based on file signatures.
- Allows timeline and keyword searches.
- Extracts metadata, browser history, emails, and more.


---
# TASK-5: Evidence of Execution

## Execution Artifacts in File System

These artifacts help determine program execution and user activity.

### 1. **Windows Prefetch Files**

Location:

```
C:\Windows\Prefetch
```

Extension: `.pf`

Contains:

* Application name
* Run count
* Last run times (up to 8)

Tool: **PECmd.exe**

```bash
PECmd.exe -f <path> --csv <output>
PECmd.exe -d <directory> --csv <output>
```

---

### 2. **Windows 10 Timeline**

Location:

```
C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<random>\ActivitiesCache.db
```

Contains:

* Application usage
* Focus time
* SQLite database format

Tool: **WxTCmd.exe**

```bash
WxTCmd.exe -f <path> --csv <output>
```

---

### 3. **Windows Jump Lists**

Location:

```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
```

Contains:

* Recent files by app
* Execution timestamps
* AppID-based mapping

Tool: **JLECmd.exe**

```bash
JLECmd.exe -f <path> --csv <output>
```

---

## Answer the questions below

### Q1.How many times was gkape.exe executed?

- the file is located under `C:\Users\THM-4n6\Desktop\triage\C\Windows\prefetch`

![Screenshot 2025-05-25 224238](https://github.com/user-attachments/assets/2d4a3ef5-625b-4928-9c9e-6733291ad6fd)

```bash
PECmd.exe -f "C:\Users\THM-4n6\Desktop\triage\C\Windows\prefetch\GKAPE.EXE-E935EF56.pf" --csv "C:\Users\THM-4n6\Desktop\Task-5"
```
![Screenshot 2025-05-25 224629](https://github.com/user-attachments/assets/177cb4cd-027a-4eb0-8bb2-18173c6c6d5e)


Ans: ***2***
### Q2.What is the last execution time of gkape.exe


Ans: ***12/01/2021 13:04***
### Q3.When Notepad.exe was opened on 11/30/2021 at 10:56, how long did it remain in focus?

```bash
WxTCmd.exe -f "C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Local\ConnectedDevicesPlatform\L.THM-4n6\ActivitiesCache.db" --csv "C:\Users\THM-4n6\Desktop\Task-5"
```
![Screenshot 2025-05-25 230331](https://github.com/user-attachments/assets/da7d4511-7572-45f3-9988-ad3155fcc0c8)

Ans: ***00:00:41***
### Q4. What program was used to open C:\Users\THM-4n6\Desktop\KAPE\KAPE\ChangeLog.txt?

```bash
JLECmd.exe -d "C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\Users\THM-4n6\Desktop\Task-5"
```

![Screenshot 2025-05-25 232553](https://github.com/user-attachments/assets/6763cf64-dc60-4c95-ac08-cae641e2abfb)


Ans: ***Notepad.exe***


---
# TASK-6: File/folder knowledge

## Shortcut Files (.lnk)

Windows creates a shortcut file for each file opened either locally or remotely. These `.lnk` files contain valuable metadata useful in forensic analysis.

### Key Information Stored

* First opened date/time
* Last accessed date/time (modification time of the .lnk file)
* Original file path
* Additional metadata

### Common Locations

* `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\`
* `C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\`

### Parsing with Eric Zimmerman's Tool

Use **LECmd.exe** to parse shortcut files:

```bash
LECmd.exe -f <path-to-shortcut-files> --csv <path-to-save-csv>
```

---

## IE/Edge History

Internet Explorer and Microsoft Edge maintain a browsing history that also logs **file access activity**, even if files were not accessed directly through the browser.

### Key Details

* Tracks websites and local file access
* Files accessed are shown with a `file:///` prefix

### Location

* `C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat`

This makes IE/Edge history a valuable source for investigating file usage and access patterns on a system.


---

## Answer the questions below

### Q1. When was the folder C:\Users\THM-4n6\Desktop\regripper last opened?

```bash
JLECmd.exe -d "C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv "C:\Users\THM-4n6\Desktop"
```

![Screenshot 2025-05-26 113842](https://github.com/user-attachments/assets/31646fc1-57e9-46f3-9717-ea89e505d3c2)


Ans: ***12/1/2021 13:01***

### Q2. When was the above-mentioned folder first opened?

Ans: ***12/1/2021 12:31***


---
# TASK-7: External Devices/USB device forensics

## Setupapi.dev.log (USB Device Connection Log)

Whenever a **new device** is connected to a Windows system, the system records installation and configuration details in the `setupapi.dev.log` file.

### Location

* `C:\Windows\inf\setupapi.dev.log`

### Key Details Logged

* **Device serial number**
* **Timestamps** for first and last connection
* **Driver installation details**
* **Hardware IDs**

This file is a vital artifact for determining when a USB device was first or last used on a system.

---

## Shortcut Files and USB Traces

As noted earlier, **shortcut files** (`.lnk`) are created when files are opened. In addition to their usual forensic value, these files can sometimes provide information about **connected USB storage devices**.

### Useful USB Details from Shortcut Files

* Volume name
* Volume type (e.g., removable)
* Serial number of the USB device

### Locations

* `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\`
* `C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\`

Using tools like **LECmd.exe**, you can extract and correlate this metadata to identify specific removable devices previously connected to the system.



---
# Forensic Tools Summary

| Tool Name  | Executable     | Purpose                                                                                  | Usage Example                                                |
|------------|----------------|------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| **MFTECmd**| `MFTECmd.exe`  | Parses the NTFS Master File Table (MFT) to recover metadata about files and directories. | `MFTECmd.exe -f <path-to-$MFT-file> --csv <output-path>`     |
| **PECmd**  | `PECmd.exe`    | Parses Windows Prefetch (`.pf`) files to identify application execution history.          | `PECmd.exe -f <path-to-Prefetch-files> --csv <output-path>`  |
| **WxTCmd** | `WxTCmd.exe`   | Parses Windows 10 Timeline database (`ActivitiesCache.db`) for app usage and focus time. | `WxTCmd.exe -f <path-to-timeline-file> --csv <output-path>`  |
| **JLECmd** | `JLECmd.exe`   | Parses Windows Jump List files to show recently accessed files.                          | `JLECmd.exe -f <path-to-Jumplist-file> --csv <output-path>`  |
| **LECmd**  | `LECmd.exe`    | Parses Windows Shortcut (`.lnk`) files to recover file access times and device metadata. | `LECmd.exe -f <path-to-shortcut-files> --csv <output-path>`  |
| **Autopsy**| GUI Application| Digital forensics platform to examine disk images and recover deleted files.            | GUI-based; load disk image and explore evidence               |

# TryHackMe: Windows Forensics 1 Room Summary

Room URL: https://tryhackme.com/room/windowsforensics1

---
# Introduction to Computer Forensics for Windows

## What is Computer Forensics?

Computer forensics is a crucial branch of cybersecurity focused on collecting evidence from computer systems. It falls under the broader field of Digital Forensics, which involves recovering, examining, and analyzing data from digital devices.

### Applications
- **Legal:** Supports or refutes hypotheses in civil or criminal cases.
- **Corporate:** Used in internal investigations, incident analysis, and intrusion detection.

## What Are Forensic Artifacts?

In forensics, an *artifact* is any piece of evidence indicating human activity. In traditional crime scenes, these might be fingerprints or broken items. Similarly, in computer forensics, artifacts are traces of digital activity left behind on systems.

### Examples on Windows
Windows systems automatically generate artifacts from user actions. These may reside in places most users do not access but are valuable for investigators trying to reconstruct events.

### Forensics Use:
These same preferences serve as forensic artifacts during investigations. They are stored in various system locations such as:
- **Windows Registry**
- **User Profile Directories**
- **Application-Specific Files**

---
# Windows Registry and Forensics

## Windows Registry

The **Windows Registry** is a set of databases that store configuration settings for the Windows operating system. It includes information about:

- Hardware
- Software
- User settings
- Recently used files and programs
- Connected devices

This data is highly valuable in **computer forensics** to track system and user activity.

### Accessing the Registry

You can view and edit the registry using **`regedit.exe`**, a built-in Windows utility. Additional tools can also help analyze the registry, which will be explored in future tasks.

### Registry Structure

The registry is organized into **Keys** and **Values**:
- **Registry Keys** act like folders.
- **Registry Values** are the data entries stored within these keys.
- A **[Registry Hive](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-hives#:~:text=Registry%20Hives.%20A%20hive%20is%20a%20logical%20group,with%20a%20separate%20file%20for%20the%20user%20profile.)** is a set of keys, subkeys, and values stored in a single file on disk.

### Root Keys

Every Windows registry is built around five main root keys:

- `HKEY_CURRENT_USER`  
  Stores settings for the currently logged-in user.

- `HKEY_USERS`  
  Contains user profiles on the system.

- `HKEY_LOCAL_MACHINE`  
  Holds system-wide settings related to hardware and software.

- `HKEY_CLASSES_ROOT`  
  Stores information about file associations and Object Linking and Embedding (OLE).

- `HKEY_CURRENT_CONFIG`  
  Contains hardware profile information used at system startup.

> For more detail and information about Windows registry keys, please visit  [Microsoft's documentation ](https://docs.microsoft.com/en-US/troubleshoot/windows-server/performance/windows-registry-advanced-users)


---
# Accessing registry hives offline

### Live System Access

On a live Windows system, you can access the registry using **`regedit.exe`**, which shows all the standard root keys.

### Access via Disk Image

If you're analyzing a **disk image**, you’ll need to locate the actual registry hive files. Most hives are stored in: `C:\Windows\System32\Config`

### Core Registry Hives and Their Mount Points

| Hive File      | Mounted At                          |
|----------------|--------------------------------------|
| `DEFAULT`      | `HKEY_USERS\DEFAULT`                 |
| `SAM`          | `HKEY_LOCAL_MACHINE\SAM`             |
| `SECURITY`     | `HKEY_LOCAL_MACHINE\Security`        |
| `SOFTWARE`     | `HKEY_LOCAL_MACHINE\Software`        |
| `SYSTEM`       | `HKEY_LOCAL_MACHINE\System`          |

### User-Specific Hives

Located in each user's profile directory (from Windows 7 onward): `C:\Users<username>\`

- **NTUSER.DAT**  
  - Mounted on `HKEY_CURRENT_USER`
  - Located at: `C:\Users\<username>\NTUSER.DAT`
  
- **USRCLASS.DAT**  
  - Mounted on `HKEY_CURRENT_USER\Software\CLASSES`
  - Located at: `C:\Users\<username>\AppData\Local\Microsoft\Windows\USRCLASS.DAT`

>  Both `NTUSER.DAT` and `USRCLASS.DAT` are **hidden files**.

### The Amcache Hive

- **File Path:**  
  `C:\Windows\AppCompat\Programs\Amcache.hve`
- **Purpose:**  
  Stores details of **recently run programs** on the system.



## Additional Forensic Sources

### Transaction Logs

- Act as a **journal of registry changes**.
- Stored in the same directory as their respective hives.
- File extension: `.LOG`, `.LOG1`, `.LOG2`, etc.
  
**Example:**  
`C:\Windows\System32\Config\SAM.LOG`

These may contain **recent changes** not yet written into the main registry hive.

### Registry Backups

- **Stored in:**  
  `C:\Windows\System32\Config\RegBack`
- These are **periodic backups** (usually every 10 days).
- Useful for identifying **deleted or modified keys**.


---
# Data Acquisition

When conducting forensic analysis, it's important to work from a **forensically sound copy** of the data rather than the live system itself. This process is known as **data acquisition**.

### Live System vs Disk Image

- **Live System:** System is running; risk of data modification.
- **Disk Image:** Snapshot of the system at a specific point in time; safer for analysis.

### Forensic Best Practice

Even though you can view the registry using `regedit.exe`, it’s **not forensically sound** to analyze live data directly. Instead, create a copy of the registry hives.

>  **Registry hives in `%WINDIR%\System32\Config` are restricted** and cannot be copied directly.


## Tools for Registry Acquisition

1. [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) (Kroll Artifact Parser and Extractor)
2. [Autopsy](https://www.autopsy.com/)
3. [FTK Imager](https://www.exterro.com/ftk-imager)
  
>  Does **not** extract `Amcache.hve`. You’ll need to manually retrieve this file if it’s part of your investigation.

##  Exploring Windows Registry
Once we have extracted the registry hives, we need a tool to view these files as we would in the registry editor. Since the registry editor only works with live systems and can't load exported hives, we can use the following tools:

1. [Registry Viewer](https://www.exterro.com/)
2. [Zimmerman's Registry Explorer](https://ericzimmerman.github.io/#!index.md)
3. [RegRipper](https://github.com/keydet89/RegRipper3.0)


# References

- *[Windows Registry Analysis Cheat Sheet](https://github.com/Ahmed-AL-Maghraby/Windows-Registry-Analysis-Cheat-Sheet?tab=readme-ov-file)*
- *[Windows Forensics Cheatsheet](https://assets.tryhackme.com/cheatsheets/Windows%20Forensics%20Cheatsheet.pdf)*
- *[Cheatsheet: Windows Forensics Analysis ](https://fareedfauzi.github.io/2023/12/22/Windows-Forensics-checklist-cheatsheet.html)*
- *[Windows Registry: Structure, Forensic Challenges, and Acquisition](https://belkasoft.com/windows-registry-forensics-structure-and-aquisition)*

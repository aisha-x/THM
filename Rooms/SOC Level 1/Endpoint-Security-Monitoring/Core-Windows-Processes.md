# TryHackMe: Core Windows Processes Room Summary

# Introducation

## Before We Begin...

Before diving into the details of this room, here are some key concepts you need to understand.

## What is a Process?

A **process** is a running instance of a program.

- When you open a program (like Chrome or Notepad), the OS creates a process for it.
- A process includes:
  - **Program code**
  - **Memory space**
  - **System resources** (e.g., file handles, threads)
  - A **Process ID (PID)** assigned by the OS

> Think of a process as a container that manages everything needed to run that specific program.

---

## What is a Parent Process?

A **parent process** is the process that **creates (or spawns)** another process.

- This is done using:
  - `fork()` on Linux/Unix
  - `CreateProcess()` on Windows
- The parent process is associated with a **Parent Process ID (PPID)**.

**Example:**

If you open **CMD** and type `notepad`, the CMD process is the **parent**, and Notepad becomes the **child process**.

---

## What is a Child Process?

A **child process** is a process that is **created by another process** (the parent).

- It often inherits environment variables and file handles from the parent.
- It runs independently but may be monitored or controlled by the parent.

---

## Real-World Example

1. You boot your computer.
2. The OS starts the **init/systemd** process → becomes the root parent.
3. That spawns other processes like `explorer.exe` or `login`, which then spawn their own children (e.g., Chrome, Terminal).
4. Chrome itself can spawn **multiple child processes** (for tabs, extensions, etc.).

---

## Why Is This Important?

- In **malware analysis**, understanding parent-child relationships helps track suspicious activity.
- In **forensics**, abnormal parent-child behavior (e.g., Word spawning PowerShell) can signal an attack.
- In **programming**, you use parent/child processes for tasks like daemons, subprocesses, or job scheduling.

---

## Want to Check This Yourself?

- On **Linux/macOS**:  
  Run `ps -ef` or `pstree` to see relationships.

- On **Windows**:  
  Use **Task Manager** or `Get-Process` in PowerShell.


---
# Task Manager

The **Task Manager** is a built-in system monitoring tool in Windows that provides real-time information about the computer's performance and running processes. It allows users to view and manage:

- **Running applications and background processes**
- **CPU, memory, disk, and network usage**
- **Startup programs**
- **Services and user sessions**

Task Manager is often used to troubleshoot system slowdowns, terminate unresponsive programs, monitor resource usage, and analyze process behavior. It plays a crucial role in both system administration and incident response.

## Windows Task Manager: Details Tab Overview

The **Details** tab in Task Manager provides in-depth, technical insights about all processes running on the system. It’s a vital tool for system administrators, developers, and cybersecurity analysts who need to monitor or investigate system behavior in real time.

---


## Example Entry from the Details Tab

| Image Name     | PID  | User Name | CPU | Memory (Private Working Set) | Description       | Image Path Name                                           |
|----------------|------|-----------|-----|-------------------------------|--------------------|-----------------------------------------------------------|
| explorer.exe   | 4567 | Aisha     | 02  | 85,432 K                      | Windows Explorer   | C:\Windows\explorer.exe                                   |
| chrome.exe     | 6789 | Aisha     | 15  | 250,112 K                     | Google Chrome      | C:\Program Files\Google\Chrome\Application\chrome.exe     |
| cmd.exe        | 3421 | Aisha     | 00  | 3,240 K                       | Windows Command    | C:\Windows\System32\cmd.exe                               |
| notepad.exe    | 9981 | Aisha     | 00  | 5,812 K                       | Notepad            | C:\Windows\System32\notepad.exe                           |


---

## Column Descriptions with Examples

- **Name**  
  - `notepad.exe`  
  - The filename of the process’s executable.

- **PID (Process ID)**  
  - `9981`  
  - Unique identifier for the process, useful for command-line tools like `taskkill` or `procmon`.

- **Status**  
  - `Running`  
  - Current execution state of the process. Could be `Running`, `Suspended`, etc.

- **User name**  
  - `Aisha`  
  - The Windows account under which the process is running.

- **CPU**  
  - `0%`  
  - CPU utilization by this process.

- **Memory (Private Working Set)**  
  - `5,812 K `  
  - The amount of physical RAM the process is using exclusively.

- **Description**  
  - `Notepad`  
  - Friendly name or description of the application.

- **Command Line**  
  - `C:\Windows\System32\notepad.exe C:\Users\Aisha\doc.txt`  
  - Full path and arguments used to start the process. Extremely helpful in identifying suspicious or malicious processes.

---

## Additional Optional Columns

These columns can be enabled by right-clicking any column header:

- **Threads**: Number of threads the process is using (e.g., `8`)
- **Handles**: Number of open handles (files, registry keys, etc.)
- **Session ID**: ID for the user session (e.g., `1`)
- **Architecture**: Whether the process is `x86` or `x64`
- **Image Path Name**: This column helps you understand exactly where the process's binary is located on the file system, which is especially useful for identifying:
     - Whether the process is from a legitimate source (e.g., `C:\Windows\System32\svchost.exe`)
     - If a suspicious or malicious version of a common process is running from an unusual path (e.g., `C:\Users\Public\svchost.exe`)
     - Troubleshooting and managing which programs are active on the system

---

## Why It's Important

- Helps identify suspicious processes or malware.
- Useful for killing unresponsive or rogue applications.
- Enables deep inspection via PID and Command Line tracing.

---

> **Tip:** Always enable the **Command Line** column for a better view of what a process is really doing — especially in malware analysis.

# System

## What is the **System Process**?

- **Name in Task Manager**: `System`
- **PID**: Usually `4`
- **User Name**: `SYSTEM`
- **Description**: Kernel-level process
- **Image Path**: Not shown directly because it's managed by the kernel (not a typical executable)

The **System process** is a critical part of the Windows operating system. It acts as the kernel's representative in Task Manager and manages **low-level tasks** such as hardware drivers, memory management, and system threads. It's not to be confused with **System Idle Process**, which just measures unused CPU.

What is user mode? Kernel-mode? Visit the following [link](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode) to understand each of these.

## **Unusual Behavior** for the System Process

The **System** process in Windows should behave in a very specific manner. Any deviations from this can indicate potential issues or even malicious activity. Below are common **unusual behaviors** to watch for:

- What is unusual behaviour for this process?
- A parent process (aside from System Idle Process (0))
- Multiple instances of System. (Should only be one instance) 
- A different PID. (Remember that the PID will always be PID 4)
- Not running in Session 0

---
# System > smss.exe

The **smss.exe** process stands for **Session Manager Subsystem**. It's an essential system process in Windows, responsible for creating and managing the **user sessions**. 


### **What Does smss.exe Do?**

1. **Session Creation**: It initializes system sessions during boot-up, including loading the Windows environment and the necessary drivers.
2. **Launching Other Important Processes**: After the kernel and Session 0 start, **smss.exe** is responsible for launching important processes like the **winlogon.exe** and **csrss.exe** (Client/Server Runtime Subsystem).

### **Unusual Behavior for smss.exe**

- A different parent process other than System (4)
- The image path is different from C:\Windows\System32
- More than one running process. (children self-terminate and exit after each new session)
- The running User is not the SYSTEM user
- Unexpected registry entries for Subsystem

---
# csrss.exe

### **System > csrss.exe** 

The **csrss.exe** (Client/Server Runtime Subsystem) is a critical system process in Windows. It is responsible for managing graphical elements and console windows, and it also handles some low-level system functions, such as process and thread creation.


### **What Does csrss.exe Do?**

1. **Process and Thread Management**: It is responsible for creating and managing user-mode processes and threads.
2. **Console Window Management**: **csrss.exe** manages console windows (command prompt) and ensures the proper display and interaction with the user.
3. **Graphical User Interface (GUI)**: It plays a role in handling window management and user interface tasks.


### **Unusual Behavior for csrss.exe**

**csrss.exe** should run in **Session 0** as part of the system processes. If you observe any of the following, it may indicate potential **malware activity** or **system compromise**:

- An actual parent process. (smss.exe calls this process and self-terminates)
- Image file path other than C:\Windows\System32
- Subtle misspellings to hide rogue processes masquerading as csrss.exe in plain sight
- The user is not the SYSTEM user.

---
# wininit.exe

**wininit.exe** (Windows Initialization) is a critical system process in the Windows operating system. It operates in **Session 0**, which is reserved for trusted system services. It is launched by `smss.exe` early in the boot process and is responsible for initializing key system services necessary for Windows to function.


### What Does wininit.exe Do?

- **Launched by smss.exe**:`smss.exe` starts `wininit.exe` as part of its initialization of **Session 0**.
  
- **Starts Essential Services**:
  - **services.exe** – the Service Control Manager (SCM) responsible for managing Windows services.
  - **lsass.exe** – Local Security Authority Subsystem Service that enforces security policies and handles user logins.
  - **lsm.exe** – Local Session Manager responsible for managing user sessions.

- **Prepares Windows Environment**: It sets up the environment so the system can reach a usable state for both services and user interaction.


### Correct Startup Sequence

1. **System (PID 4)** starts → `smss.exe`
2. `smss.exe` launches → `wininit.exe` and `csrss.exe` in Session 0
3. `wininit.exe` launches:
   - `services.exe`
   - `lsass.exe`
   - `lsm.exe`

This chain of startup ensures that all necessary system services are initialized properly before the user session begins.


### **Unusual Behavior for wininit.exe**

- An actual parent process. (smss.exe calls this process and self-terminates)
- Image file path other than C:\Windows\System32
- Subtle misspellings to hide rogue processes in plain sight
- Multiple running instances
- Not running as SYSTEM

---
# wininit.exe > services.exe

### **System > services.exe**

The **services.exe** process (Service Control Manager) is a vital part of the Windows operating system, responsible for managing the services and processes that run in the background. It starts and stops services, which are programs that run in the background and handle tasks such as network management, hardware monitoring, and system updates.


### **What Does services.exe Do?**

1. **Manage System Services**: **services.exe** controls and manages the execution of services in Windows. It starts essential services during boot and ensures they remain running throughout the system’s operation.
2. **Service Control Manager (SCM)**: It acts as the **Service Control Manager**, providing an interface between the operating system and service applications to start, stop, or pause services.
3. **Process Creation**: It is responsible for launching other system processes, such as **svchost.exe**, which host system services in their own processes.



### **Unusual Behavior for services.exe**
- A parent process other than wininit.exe
- Image file path other than C:\Windows\System32
- Subtle misspellings to hide rogue processes in plain sight
- Multiple running instances
- Not running as SYSTEM

---
# wininit.exe > services.exe > svchost.exe

The **svchost.exe** (Service Host) process is a system process in Windows that acts as a generic host process for services that run from dynamic-link libraries (DLLs). It is a crucial part of the operating system and is responsible for running and managing various services.


### **What Does svchost.exe Do?**

1. **Host Multiple Services**: **svchost.exe** allows Windows to run multiple services in one process. These services are typically written as DLL files, and **svchost.exe** provides the environment for them to run.
2. **Service Grouping**: Different instances of **svchost.exe** can run multiple services grouped together by functionality. For example, **svchost.exe** can run all networking-related services in one instance and other system-related services in another.
3. **Manage Background Operations**: The services hosted by **svchost.exe** handle various background tasks such as Windows Update, network connectivity, and other system operations.

---

### **Common Services Run by svchost.exe**
- **Windows Update** (`wuauserv`)
- **Windows Firewall** (`MpsSvc`)
- **DNS Client** (`dnscache`)
- **Plug and Play** (`PlugPlay`)

These are just a few examples, and each instance of **svchost.exe** can host different services depending on the system’s configuration and the number of services installed.

### What is unusual ?

- A parent process other than services.exe
- Image file path other than C:\Windows\System32
- Subtle misspellings to hide rogue processes in plain sight
- The absence of the -k parameter

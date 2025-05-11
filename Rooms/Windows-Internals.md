# TryHackMe: Windows Internals Room Summary

Room URL: https://tryhackme.com/room/windowsinternals

# Introduction

# Windows Internals Overview

## Summary

Operating systems like Windows have complex underlying technologies and architectures that aren't always visible at first glance. This learning module focuses on exploring the internal components of the Windows operating system.

## Learning Objectives

- **Understand and interact with Windows processes** and their supporting technologies.
- **Learn about core file formats** used by Windows and how they function.
- **Explore Windows internals**, including how the Windows kernel operates.

## Importance for Red Teaming

Since Windows machines dominate corporate environments, red teamers must understand Windows internals. Knowledge of these components helps in:

- Evasion techniques
- Exploitation strategies
- Development of offensive tools

## Prerequisites

- Basic understanding of **Windows usage and functionality**
- Familiarity with **C++** and **PowerShell** is helpful but not required

---
# Processes

## Overview

A **process** represents the execution of a program and serves as a fundamental building block of the Windows operating system. Each application can run one or more processes, and these processes consist of various components that manage resources and execution.

## Process Structure (High-Level Components)

| Component                 | Purpose                                                                 |
|---------------------------|-------------------------------------------------------------------------|
| Private Virtual Address Space | Memory addresses allocated to the process                           |
| Executable Program        | Contains code and data in memory                                       |
| Open Handles              | Access to system resources (files, registry, etc.)                     |
| Security Context          | Access token with user, group, and privilege info                      |
| Process ID (PID)          | Unique identifier for the process                                      |
| Threads                   | Executable units within the process                                    |


## Process Structure (Low-Level Memory View)

| Component         | Purpose                                   |
|-------------------|-------------------------------------------|
| Code              | Instructions to be executed               |
| Global Variables  | Stored process variables                  |
| Process Heap      | Memory used for dynamic data allocation   |
| Process Resources | Additional used resources (files, etc.)   |
| Environment Block | Structure containing process information  |

![image](https://github.com/user-attachments/assets/5d1d547b-e61b-4757-8d68-80475e5d0cc2)

## Common Windows Processes

Examples of system-related processes:
- **MsMpEng** – Microsoft Defender
- **wininit** – Keyboard and mouse initialization
- **lsass** – Credential storage

## Attacker Techniques (MITRE ATT&CK References)

Attackers can abuse processes using:
- **Process Injection [T1055](https://attack.mitre.org/techniques/T1055/)**
- **Process Hollowing [T1055.012](https://attack.mitre.org/techniques/T1055/012/)**
- **Process Masquerading [T1055.013](https://attack.mitre.org/techniques/T1055/013/)**

## Observing Processes

Tools like **Windows Task Manager**, **[Process Hacker 2](https://github.com/processhacker/processhacker)**, **[Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)**, and **[Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)** allow users to inspect and analyze process behavior.

### Task Manager - Key Process Details

| Component   | Purpose                                   | Example       |
|-------------|-------------------------------------------|---------------|
| Name        | Process name (from application)           | conhost.exe   |
| PID         | Unique identifier                         | 7408          |
| Status      | Current execution state                   | Running       |
| User Name   | User account that launched the process     | SYSTEM        |

These details are useful for both general users and attackers for identifying, analyzing, or manipulating process behavior.

## Conclusion

Processes are core to how Windows operates internally. Understanding their structure and behavior is essential for both system monitoring and exploitation activities. The following sections will dive deeper into process manipulation and usage.

---
# Threads

## Overview

A **thread** is the basic unit of execution within a process. It is scheduled based on various **device factors** such as:

- CPU and memory specifications
- Process/thread priority
- Logical system constraints

### Simplified Definition:
> A thread controls the execution of a process.

Because threads manage execution, they are often targeted for **abuse in code execution**, either independently or as part of other API-based techniques.

## Thread Behavior and Resource Sharing

Threads:
- **Share** the parent process’s resources (e.g., code, global variables)
- **Possess** unique data relevant to their specific execution

## Key Components of a Thread

| Component            | Purpose                                                                 |
|----------------------|-------------------------------------------------------------------------|
| **Stack**            | Stores all thread-specific data (e.g., procedure calls, exceptions)     |
| **Thread Local Storage** | Provides pointers for data unique to each thread                    |
| **Stack Argument**   | Unique value assigned to the thread                                     |
| **Context Structure**| Contains CPU register values, maintained by the kernel                  |

## Conclusion

While threads may appear simple, they are **crucial to process execution** and often serve as a core component in advanced techniques for both legitimate use and exploitation.

---
# Virtual Memory

## Overview

**Virtual memory** is a foundational element in how Windows internal components interact. It enables processes to treat memory as if it were physical, while preventing collisions between applications.

## Key Concepts

- Each **process** is assigned a **[private virtual address space](https://docs.microsoft.com/en-us/windows/win32/memory/virtual-address-space)**, preventing direct access to physical memory.
- A **memory manager** translates virtual addresses to physical addresses, reducing the risk of accidental damage.

![image](https://github.com/user-attachments/assets/60da0d1f-43aa-46d6-a629-a52daa7269ed)

## Memory Paging

- When a process exceeds available physical memory, the memory manager **pages** parts of memory to disk.
- This system enables more efficient and flexible memory usage.

## Virtual Address Space Layout

![image](https://github.com/user-attachments/assets/9e9e51ae-1e31-47be-962a-a619d7623d4f)

### 32-bit Systems (x86)

- **Maximum Virtual Address Space**: 4 GB
- **Allocation**:
  - **Lower Half (0x00000000 - 0x7FFFFFFF)**: Process memory
  - **Upper Half (0x80000000 - 0xFFFFFFFF)**: OS memory
- **Custom Configuration**:
  - `increaseUserVA`: Adjusts process memory allocation
  - **AWE [Address Windowing Extensions](https://docs.microsoft.com/en-us/windows/win32/memory/address-windowing-extensions)**: Enables larger allocations

### 64-bit Systems

- **Maximum Virtual Address Space**: 256 TB
- Follows the same conceptual layout as 32-bit systems
- Larger space resolves most limitations faced on 32-bit systems

## Importance

Understanding virtual memory is critical even though it's an abstract concept. It plays a key role in memory management and can be **leveraged in security research and exploitation** involving Windows internals.

---
# Dynamic Link Libraries

# Understanding DLLs in Windows

## What is a DLL?

According to Microsoft:
> "A DLL (Dynamic-Link Library) is a library that contains code and data that can be used by more than one program at the same time."

### Key Benefits of DLLs

- **Modularization of code**
- **Code reuse**
- **Efficient memory usage**
- **Reduced disk space**
- Faster load/run times for both the OS and applications

## DLLs as Dependencies

When an application uses a DLL, it becomes **dependent** on it. This makes DLLs a common **attack target** for threat actors.

### Common Attack Techniques

- **DLL Hijacking** – T1574.001
- **DLL Side-Loading** – T1574.002
- **DLL Injection** – T1055.001

## Example: Creating a DLL in C++

### DLL Source File (`sampleDLL.cpp`)

```cpp
#include "stdafx.h"
#define EXPORTING_DLL
#include "sampleDLL.h"

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    return TRUE;
}

void HelloWorld()
{
    MessageBox(NULL, TEXT("Hello World"), TEXT("In a DLL"), MB_OK);
}
```
### DLL Header File (`sampleDLL.h`)
```cpp
#ifndef INDLL_H
#define INDLL_H

#ifdef EXPORTING_DLL
    extern __declspec(dllexport) void HelloWorld();
#else
    extern __declspec(dllimport) void HelloWorld();
#endif

#endif
```
### Loading DLLs in Applications
1. Load-Time Dynamic Linking
    - Requires `.h` (header) and `.lib` (import library) files
    - DLL functions are called directly

```cpp
#include "stdafx.h"
#include "sampleDLL.h"

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HelloWorld();
    return 0;
}
```
2. Run-Time Dynamic Linking
    - DLL is loaded during execution using `LoadLibrary` or `LoadLibraryEx`
    - `GetProcAddress` is used to retrieve the function address

```cpp
typedef VOID (*DLLPROC)(LPTSTR);
HINSTANCE hinstDLL;
DLLPROC HelloWorld;
BOOL fFreeDLL;

hinstDLL = LoadLibrary("sampleDLL.dll");
if (hinstDLL != NULL)
{
    HelloWorld = (DLLPROC)GetProcAddress(hinstDLL, "HelloWorld");
    if (HelloWorld != NULL)
        HelloWorld();
    fFreeDLL = FreeLibrary(hinstDLL);
}
```
---
# Portable Executable Format

## Overview

The Portable Executable (PE) format is used in Windows operating systems to define the structure and layout of executable (.exe), object, and DLL files.

It includes components from both:
- **PE (Portable Executable) format**
- **COFF (Common Object File Format)**

These components together manage how executables are loaded and run by the OS.

---

## Main Components of the PE Format

![image](https://github.com/user-attachments/assets/ba872411-3392-416f-8ec1-779119f75d67)

### 1. **DOS Header**
- Contains the **MZ** signature (`0x4D 0x5A`) that identifies the file as an executable.
- Ensures backward compatibility with DOS.
  
### 2. **DOS Stub**
- A small program that prints:  
  `"This program cannot be run in DOS mode."`
- This stub runs if the program is executed in DOS.

### 3. **PE File Header**
- Starts with the **"PE\0\0"** signature.
- Defines:
  - File characteristics
  - Target machine architecture
  - Number of sections
  - Time/date stamps
  - Size of the optional header

### 4. **Image Optional Header**
- Despite the name, this is **mandatory** for executables.
- Includes:
  - Entry point address
  - Image base
  - Section alignment
  - Size of code/data
  - Subsystem and DLL characteristics

### 5. **Data Directories**
- Located in the Optional Header.
- Point to tables for:
  - Imports
  - Exports
  - Resources
  - Relocations
  - Debug information

---

## Import-Related Information

### .idata / .rdata Section
- **Purpose**: Stores **import information** for the application.
- **What it includes**:
  - List of DLLs that the executable depends on (e.g., `kernel32.dll`, `user32.dll`)
  - Functions used from those DLLs (e.g., `CreateFile`, `MessageBox`, etc.)
  - Address tables that map the DLL functions into memory

### Import Address Table (IAT)
- Loaded into memory at runtime.
- Resolved dynamically so the executable can use external DLL functions.
- **Crucial for:**
  - Dynamic linking
  - API hooking
  - Malware analysis and reverse engineering

---

## Section Table Overview

| Section   | Purpose                                      |
|-----------|----------------------------------------------|
| `.text`   | Contains executable code and entry point     |
| `.data`   | Contains initialized global variables        |
| `.rdata` or `.idata` | Contains **imports (Windows APIs, DLLs)** |
| `.reloc`  | Relocation information (if not loaded at preferred base) |
| `.rsrc`   | Application resources (icons, dialogs, etc.) |
| `.debug`  | Debugging symbols and information            |

---

## Summary

Understanding the PE format is critical for:
- Malware analysis
- Reverse engineering
- Exploit development
- Secure application design

The import directory and `.rdata`/`.idata` sections reveal how executables interact with external code, especially through DLLs and Windows APIs.



نسخ
تحرير

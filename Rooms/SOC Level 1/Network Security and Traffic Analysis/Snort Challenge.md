# TryHackMe: Snort Challenge

Room URL: https://tryhackme.com/room/snortchallenges1

**This room is all about how to write IDS Rules**

---
# Task2: Writing IDS Rules (HTTP)

**Write a rule to detect all TCP packets from or to port 80.**

```
alert tcp any 80 <> any any (msg:"TCP port 80 inbound traffic detected";sid:10000001;rev:1;)

```

- test the configuration with `snort -c local.rules -T`
- if success, run the local rule on the pcap file 
- `snort -c local.rules -A full -l . -r mx-3.pcap`
- to view a certain number of packet from a snort log use this command 
- `snort -r <snort.log> -n <number of packet you want to view>`

---
# Writing IDS Rules (FTP)

### Write a single rule to detect "all TCP port 21"  traffic in the given pcap.

`alert tcp any 21 <> any any (msg:"TCP port 21 inbound traffic detected";sid:10000001;rev:1;)`

- `snort -c local.rule -T`
- `sudo snort -A full -r ftp-png-gif.pcap -c local.rules -l `.
- to search for ftp service in snort log file use `strings` command which is used to search and print for any readable text.
- `sudo string <snort.log> | grep 220` 220 is FTP code for "ready for new users"

### Write a rule to detect failed FTP login attempts in the given pcap.

- comment the previous rule 
- `alert tcp any 21 <> any any (msg:"Failed FTP login attempt";content:"530 User";sid:10000001;rev:1;)`
- test it 
- then run it `snort -c local.rules -A full -l . -r ftp-png-gif.pcap `


### Write a rule to detect successful FTP logins in the given pcap.

- Deactivate/comment on the old rule.
- `alert tcp any 21 <> any any (msg:"successful FTP login attempt";content:"230 User";sid:10000001;rev:1;)`


### Write a rule to detect FTP login attempts with a valid username but no password entered yet.

- `alert tcp any 21 <> any any (msg:"331 Username okay, need password.";content:"331 Password";sid:10000001;rev:1;)`


### Write a rule to detect FTP login attempts with the "Administrator" username but no password entered yet.

- `alert tcp any 21 <> any any (msg:"331 Username Administrator, need password.";content:"331 Password";content:"Administrator";sid:10000001;rev:1;)`

---
# Writing IDS Rules (PNG)

### Write a rule to detect the PNG file in the given pcap.

- `alert ip any any <> any any  (msg: "PNG file Found";content:"PNG"; sid: 100001; rev:1;)`
- use `strings` command to read from the log
- `sudo strings <snort.log>`

### Write a rule to detect the GIF file in the given pcap.

- `alert ip any any <> any any  (msg: "GIF file Found";content:"GIF"; sid: 100001; rev:1;)`
- to fine readable strings `sudo strings <snort.log>`

---
# Writing IDS Rules (Torrent Metafile)


### Write a rule to detect the torrent metafile in the given pcap.

- `alert tcp any any <> any any  (msg: "Torrent file found";content:".torrent"; sid: 100001; rev:1;)`


---
# Troubleshooting Rule Syntax Errors


- test the rules configuration with this command `snort -c <local-x.rule> -T`
- Rule 1: 
   - `alert tcp any 3372 -> any any (msg:"Troubleshooting 1";    sid:1000001;rev:1;)`

- Rule 2: 
    - `alert icmp any any -> any any (msg:"Troubleshooting 2"; sid:1000001; rev:1;)`

- Rule 3: 
    - `alert icmp any any -> any any (msg:"ICMP Packet Found"; sid:1000001; rev:1;)`
    - `alert tcp any any -> any [80,443] (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)`

- Rule 4: 
   - `alert icmp any any -> any any (msg:"ICMP Packet Found"; sid:1000001; rev:1;)`
   - `alert tcp any [80,443] -> any any (msg:"HTTPX Packet Found"; sid:1000002; rev:1;)`

- Rule 5: 
    - `alert icmp any any <> any any (msg:"ICMP Packet Found"; sid:1000001;rev:1;)`
   - `alert icmp any any <> any any (msg:"ICMP Packet Found"; sid:1000002;rev:1;)`
   - `alert tcp any any -> any 80,443 (msg: "HTTPX Packet  Found"; sid:1000003; rev:1;)`

- Rule 6:
   - `alert tcp any any <> any 80 (msg:"GET Request Found";content:"|47 45 54|"; sid: 100001; rev:1;)`

- Rule 7:
  - `alert tcp any any <> any 80 (msg:"html detected";content:"|2E 68 74 6D 6C|"; sid: 100001; rev:1;)`


---
# Using External Rules (MS17-010)


### Use the given rule file (local.rules) to investigate the ms1710 exploitation.

- local.rule file: 
``` 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.




alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; sid: 2094284; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:2094285; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "NTLMSSP";sid: 2094286; rev: 2;) 
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "WindowsPowerShell";sid: 20244223; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "ADMIN$";sid:20244224; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$";sid: 20244225; rev:3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 20244226; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 209462812; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "samr"; sid: 209462813; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "browser"; sid: 209462814; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established;content: "epmapper";sid: 209462815; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "eventlog"; sid: 209462816; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "/root/smbshare"; sid: 20242290; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "\\PIPE"; sid: 20242291; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "smbshare"; sid: 20242292; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "srvsvc"; sid: 20242293; rev: 2;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB3|00 00 00 00|"; depth:9; offset:4; byte_extract:2,26,TotalDataCount,relative,little; byte_test:2,>,TotalDataCount,20,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,blog.talosintelligence.com/2017/05/wannacry.html; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:41978; rev:5;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|A0 00 00 00 00|"; depth:9; offset:4; content:"|01 00 00 00 00|"; within:5; distance:59; byte_test:4,>,0x8150,-33,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:42944; rev:2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; reference: ExploitDatabase (ID’s - 42030, 42031, 42315); priority: 10; sid: 2094284; rev: 2;)

```
- result: ![Screenshot 2025-04-29 103713](https://github.com/user-attachments/assets/6e28034a-bafd-4def-8c3a-2ccfb68d5cda) ![Screenshot 2025-04-29 103727](https://github.com/user-attachments/assets/724c0f16-b547-41bb-a143-0610a340fd14)

- alert file: ![Screenshot 2025-04-29 103817](https://github.com/user-attachments/assets/3c09b999-c4ab-408f-9883-f0374288dc12)

- extracted strings from the snort log: ![Screenshot 2025-04-29 104239](https://github.com/user-attachments/assets/22c50a8a-e9da-49b9-8113-74ab3a923cc2)


### Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword.

- `alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content:"IPC$"; sid:2094285444; rev: 1;)`
- extracted strings from snort log: ![Screenshot 2025-04-29 104817](https://github.com/user-attachments/assets/a481f0a5-7308-49ba-ac1b-f4889914df69)



---
# Using External Rules (Log4j)


### Use the given rule file (local.rules) to investigate the log4j exploitation.

- local.rule file: 
```

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.


alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:ldap://"; fast_pattern:only; flowbits:set, fox.apachelog4j.rce; priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003726; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; pcre:"/\$\{jndi\:(rmi|ldaps|dns)\:/"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003728; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; content:!"ldap://"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, twitter.com/stereotype32/status/1469313856229228544; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003730; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228)"; flow:established, to_server; content:"%7bjndi:"; nocase; fast_pattern; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003731; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header"; flow:established, to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003732; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI"; flow:established,to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003733; rev:1;) 

# Better and stricter rules, also detects evasion techniques
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header (strict)"; flow:established,to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Hi"; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003734; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI (strict)"; flow:established, to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Ui"; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003735; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in Client Body (strict)"; flow:to_server; content:"${"; http_client_body; fast_pattern; content:"}"; http_client_body; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Pi"; flowbits:set, fox.apachelog4j.rce.strict; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-12; metadata:ids suricata; priority:3; sid:21003744; rev:1;)

```

- result: ![Screenshot 2025-04-29 105954](https://github.com/user-attachments/assets/133c61f2-d003-4029-b74f-c8b6656542de)

- alert file: ![Screenshot 2025-04-29 110909](https://github.com/user-attachments/assets/e9c735ed-9b30-4012-8d6c-d5c4463194fe)

- extracted strings from snort log: ![Screenshot 2025-04-29 111231](https://github.com/user-attachments/assets/29c21813-566b-454b-98c7-038e42a56f9b)



### Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes.

- `alert tcp any any -> any any (msg:"detected packet payload len between 770 and 855";flow:established, to_server; dsize:770<>855;sid:21003726; rev:1;)`
- extracted strings from snort log: ![Screenshot 2025-04-29 121835](https://github.com/user-attachments/assets/8945214c-dc3b-4b83-b7de-bd85e7775e36)
- to decode a base64 command
   - grep "Base64" from the snort log using `strings` command
   - Redirect the output to a text file
   - You have to take only the base64-encoded part, store it in a different file, and then decode it.
   - If you noticed, there are three encoded base64 commands, put them into one file separated by a new line. then decoded them
   - I put them into separate files, then used this command to decode it `based64 --decode <encoded base64 file>`
   
 - ![Screenshot 2025-04-29 123325](https://github.com/user-attachments/assets/d96c1c3b-8985-4570-a4e6-63b50d1dc726)

 - ![Screenshot 2025-04-29 123917](https://github.com/user-attachments/assets/1f636b14-e546-4378-88f8-507b066d449d)



---
# summary

| **Option**         | **Description**                                                                 | **Example**                                            |
|--------------------|----------------------------------------------------------------------------------|--------------------------------------------------------|
| `msg`              | Message shown when the rule triggers.                                           | `msg:"Possible Log4j RCE";`                           |
| `flow`             | Direction and state of TCP connection.                                          | `flow:established, to_server;`                        |
| `content`          | Searches for specific string in the packet payload.                            | `content:"${jndi:";`                                  |
| `nocase`           | Makes `content` match case-insensitive.                                        | `content:"%7bjndi:"; nocase;`                         |
| `fast_pattern`     | Optimizes rule matching with pattern matcher.                                  | `fast_pattern:only;` or just `fast_pattern;`          |
| `http_uri`         | Match `content` in the HTTP URI portion.                                       | `content:"${"; http_uri;`                             |
| `http_header`      | Match `content` in HTTP headers.                                                | `content:"${"; http_header;`                          |
| `http_client_body` | Match `content` in HTTP body from client (POST data).                          | `content:"${"; http_client_body;`                     |
| `distance`         | Sets byte distance from previous match to next `content`.                      | `distance:0;`                                         |
| `within`           | Max number of bytes after previous `content` to search for next.               | `within:10;`                                          |
| `depth`            | Limits how deep into the packet to search for a `content`.                     | `depth:50;`                                           |
| `offset`           | Number of bytes from the start to begin searching.                             | `offset:20;`                                          |
| `flowbits`         | Sets or checks custom state flags across multiple rules.                       | `flowbits:set, apachelog4j.rce;`                      |
| `pcre`             | Perl-compatible regex match in payload.                                        | `pcre:"/\\$\\{jndi\\:(rmi|ldaps|dns)\\:/";`           |
| `threshold`        | Limits how often alerts are generated.                                         | `threshold:type limit, track by_dst, count 1, seconds 3600;` |
| `reference`        | External reference URL for more context.                                       | `reference:url,http://...;`                           |
| `metadata`         | Tags for rule classification, like CVE or tool (used by Suricata).             | `metadata:CVE 2021-44228;`                            |
| `priority`         | Priority level of alert (1 = high, 3 = low).                                   | `priority:3;`                                         |
| `sid`              | Snort rule ID — must be unique.                                                | `sid:21003731;`                                       |
| `rev`              | Revision number for rule maintenance.                                          | `rev:1;`                                              |
| `dsize`            | Tests payload size. Can be used as: `<`, `>`, `!=`, `=`, or a single value.    | `dsize:>100;` or `dsize:100<>200;` *(Suricata only)*  |
|


---
# reference

- *https://docs.snort.org/welcome*
- *https://tryhackme.com/room/snort*
- *https://www.solarwinds.com/serv-u/tutorials/225-226-227-230-ftp-response-codes*
- *https://www.rapidtables.com/convert/number/hex-to-ascii.html*
- *https://www.tenable.com/plugins/nessus/97737*
  

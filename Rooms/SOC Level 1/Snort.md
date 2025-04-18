# Tryhackme: Snort 

This is a summary of Snort tool in TryHackMe room 

Room URL: https://tryhackme.com/room/snort

# Snort - Overview and Modes

## Snort - Brief Overview

Snort is an open-source Network Intrusion Detection and Prevention System (NIDS/NIPS) developed by Cisco. It is widely used for real-time traffic analysis, packet logging, and detecting malicious activities on a network. Snort inspects network packets and matches them against user-defined rules to identify and take action on threats.

---

## Snort Modes and Common Parameters

### Mode 1: Sniffer Mode

Purpose: Monitors and displays packets on the console (like `tcpdump`).

Common Parameters:
- `-v`: Displays packet headers.
- `-d`: Displays application layer data (payload).
- `-e`: Displays MAC (Ethernet) headers.

Example: `snort -vde`

Explanation: Snort will sniff packets and show headers, payloads, and MAC addresses.

---

### Mode 2: Packet Logger Mode

Purpose: Logs network packets to a file for later analysis.

Common Parameters:
- `-l <directory>`: Specifies the logging directory.
- `-K <format>`: Logging format (`ascii`, pcap, `none`).

Example:`snort -dev -l /home/aisha/snort_logs -K ascii`

Explanation: Logs all sniffed packets in ASCII format in the specified directory.

---

### Mode 3: IDS/IPS Mode

Purpose: Uses a rule-based engine to analyze traffic and detect intrusions.

Common Parameters:
- `-c <file>`: Path to the Snort configuration file.
- `-i <interface>`: Network interface to monitor.
- `-A <alert mode>`: Alert output mode (`full`, fast, `console`).

Example:`snort -c /etc/snort/snort.conf -i eth0 -A console`

Explanation: Runs Snort in IDS mode, monitoring traffic on eth0 and showing alerts on the terminal.

---

### Mode 4: PCAP Investigation Mode

Purpose: Reads and analyzes traffic from a .pcap file.

Common Parameters:
- `-r <file>`: Path to the .pcap file to read.
- `-c <file>`: Configuration file with rules for analysis.

Example:`snort -r attack_traffic.pcap -c /etc/snort/snort.conf -A console`

Explanation: Snort analyzes the contents of attack_traffic.pcap using its rules and shows alerts in the console.

---

## Snort Rule Structure

![image](https://github.com/user-attachments/assets/02d185fc-3b46-4e6b-add4-21dbb7d26c8b)

A Snort rule consists of two parts:
1. Rule Header
2. Rule Options

### General Syntax:action protocol src_ip src_port -> dest_ip dest_port (options)

### Example Rule:alert tcp any any -> 192.168.1.10 80 (msg:"HTTP access detected"; sid:1000001; rev:1;)

### Breakdown:

Rule Header:
- `alert`: Action (others: log, pass, drop, etc.)
- `tcp`: Protocol
- `any any`: Source IP and port
- `->`: Direction (can also be <-, `<>`)
- `192.168.1.10 80`: Destination IP and port

Rule Options (inside parentheses):
- `msg`: Message displayed when rule triggers.
- `sid`: Snort ID (unique identifier for the rule).
- `rev`: Revision number of the rule.

### Common Rule Options:
- content: Specifies a payload string to match.
- nocase: Makes content match case-insensitive.
- classtype: Classifies the type of attack.
- priority: Alert priority (1 = high, 3 = low).
- flow: Specifies flow direction (e.g., from_client, `to_server`).

---
## Snort Rule Options - Categories Summary

Snort rule options are grouped into three main categories based on what part of the packet or flow they inspect:

### 1. General Rule Options
These are fundamental options used in almost all Snort rules. They define general behavior, metadata, and rule identifiers.

Common General Options:
- msg: Message shown when the rule triggers.
- sid: Unique Snort ID for the rule.
- rev: Revision number.
- classtype: Categorizes the type of alert (e.g., attempted-admin, trojan-activity).
- priority: Assigns severity (1 = high, 3 = low).
- metadata: Adds descriptive info (e.g., author, affected OS).

> Use case: Organizing rules and giving context to alerts.

---

### 2. Payload Rule Options
These options inspect the actual payload (data) within packets. They're useful for detecting signatures, patterns, or malicious content in data sent over the network.

Common Payload Options:
- content: Searches for specific strings in the payload.
- nocase: Makes content search case-insensitive.
- offset, depth: Define where to start/stop content matching.
- pcre: Allows regex-based matching.
- http_uri, http_header, http_cookie: Match specific HTTP elements.

> Use case: Detecting malware signatures, SQL injections, or file types.

---

### 3. Non-Payload Rule Options
These focus on non-payload attributes, such as packet headers, protocol behavior, or flow direction. They're key for creating stateful or flow-aware rules.

Common Non-Payload Options:
- flow: Specifies traffic direction and state (e.g., from_client, `to_server`).
- dsize: Matches on packet size.
- flags: TCP flags (e.g., SYN, ACK).
- ttl, tos, id: IP header attributes.
- fragoffset: Checks IP fragmentation offset.
- sameip: Ensures source and destination IPs are the same.

> Use case: Detecting scanning activity, malformed packets, or session behavior.

---

# Task-9 Snort Rule Structure

Answer the Questions Below:

---
**Q1. Use "task9.pcap". Write a rule to filter IP ID "35369" and run it against the given pcap file. What is the request name of the detected packet? You may use this command: "snort -c local.rules -A full -l . -r task9.pcap"**

- Write the rule in local.rule 
- First I tried to only set one rule for tcp packet but that didn't work so I wrote two more rules for UDP and ICMP protocols
- ![q1 rule](https://github.com/user-attachments/assets/cb889757-e96c-4b8d-9173-2bba6dcb85b8)
- you have to test the configuration rules before applying it to the pcap file `sudo snort -c local.rule -T `.
- Once the configuration test succeeds, run your rules on the task9.pcap file `sudo snort -c local.rules -A full -l . -r task9.pcap`
- Once Snort is done analyzing the pcap file, it will generate an alert file print this file to see the answer `cat alert`
-![q1 ans ](https://github.com/user-attachments/assets/477a1711-6ba8-4718-89c3-b0b52dbf764e)

Ans : ***TIMESTAMP REQUEST*** 

---
**Q2. Clear the previous alert file and comment out the old rules. Create a rule to filter packets with Syn flag and run it against the given pcap file. What is the number of detected packets?**

- ![image](https://github.com/user-attachments/assets/41aa7418-8ae6-40dd-8038-6515b7fd964a)
- Test your configuration 
- Run Snort against task9.pcap `sudo snort -c local.rules -A full -l . -r task9.pcap`
- ![q2  ans](https://github.com/user-attachments/assets/c33f578f-d5c1-4026-8a79-bdc0460a88e2)
- ![q2  alert](https://github.com/user-attachments/assets/311ded17-4e68-450a-8e2e-965fbdacccab)

Ans : ***1*** 


---
**Q3. Clear the previous alert file and comment out the old rules. Write a rule to filter packets with Push-Ack flags and run it against the given pcap file. What is the number of detected packets?**

- ![q3 rule](https://github.com/user-attachments/assets/d26c684f-3d28-431b-beb5-c77cb5a8b308)
- Test your configuration and run it against the pcap file `sudo snort -c local.rules -A full -l . -r task9.pcap`
- ![q3  ans](https://github.com/user-attachments/assets/28266edb-497d-40d7-973a-362d821f4eb6)

Ans : ***216*** 


---
**Q4. Clear the previous alert file and comment out the old rules. Create a rule to filter UDP packets with the same source and destination IP and run it against the given pcap file. What is the number of packets that show the same source and destination address?**

- ![q4  rule](https://github.com/user-attachments/assets/c7db7d03-1cd7-4ae2-a466-bf64beb56505)
- Test your configuration and run it with `sudo snort -c local.rules -A full -l . -r task9.pcap`
- ![q4 ans](https://github.com/user-attachments/assets/1b298682-0b96-4b95-8da9-1f6b7d5c0bea)
- This is the generated alert file, as you can see, both the src and dst ip are the same
- ![q4 alert](https://github.com/user-attachments/assets/3dba9a8f-cef8-47bb-9877-2e190e692feb)

Ans : ***7*** 

---
Reverence:

*https://www.snort.org/*

*https://en.wikipedia.org/wiki/Berkeley_Packet_Filter*

*https://biot.com/capstats/bpf.html*

*https://www.tcpdump.org/manpages/tcpdump.1.html*

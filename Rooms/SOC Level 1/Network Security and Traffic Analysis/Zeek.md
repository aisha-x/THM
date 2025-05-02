# TryHackMe: Zeek Room Summary

Room URL: https://tryhackme.com/room/zeekbro

# Network Security Monitoring and Zeek

## Network Security Monitoring (NSM)
Network Security Monitoring involves the collection, analysis, and escalation of indications and warnings to detect and respond to intrusions. It relies on full packet capture, protocol analysis, and event logging to give security analysts insights into network activities.

## Zeek Overview
Zeek (formerly Bro) is a powerful network analysis framework focused on security monitoring. It inspects network traffic, generates detailed logs, and allows for custom scripting to detect and respond to suspicious behavior in real time.

---

# Zeek Logs

Zeek generates a variety of log files for different protocol activities, such as:
- *conn.log*: Connection summaries.
- *http.log*: HTTP request/response information.
- *dns.log*: DNS queries and responses.
- *ssl.log*: SSL/TLS handshake data.
These logs are stored in plain text (TSV format) and are essential for threat detection and forensic analysis.

## Answer the questions below

### Q1. Investigate the sample.pcap file. Investigate the dhcp.log file. What is the available hostname?

- `zeek -C -r sample.pcap`
- ![image](https://github.com/user-attachments/assets/36b210dc-5948-4b27-80e2-14668fd4f54e)
- Review the overall connections from `conn.log`
   - `cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p service| head`
   - ![image](https://github.com/user-attachments/assets/ff6f33be-e46d-4156-b3f6-e99db3d17820)
- open `dhcp.log` to examine the fields and determine how to filter the data
   - ![image](https://github.com/user-attachments/assets/a6d9e1fa-9eac-4e1c-b7eb-e961d0a317fe)
- `cat dhcp.log | zeek-cut client_addr server_addr host_name  domain msg_types`
- ![image](https://github.com/user-attachments/assets/c8aa3159-8a0e-4403-8d70-94ec65337277)

Ans: ***Microknoppix***

### Q2. Investigate the dns.log file. What is the number of unique DNS queries?

- ![image](https://github.com/user-attachments/assets/35e13810-9320-4028-81d1-bf78220d4188)
- `cat dns.log | zeek-cut query | uniq | wc -l`
- ![image](https://github.com/user-attachments/assets/4e71de3d-f36c-4af5-9a21-bf5347ae1d7c)

Ans: ***2***

### Q3. Investigate the conn.log file. What is the longest connection duration?

- `cat conn.log | zeek-cut duration | sort -nr | nl | head`
- ![image](https://github.com/user-attachments/assets/f8b68c94-8f17-4b3a-93f8-a7152d930780)

Ans: ***332.319364***


---

# CLI Kung-Fu Recall: Processing Zeek Logs

Using the command line to analyze Zeek logs includes:
- cat, less, head, tail for viewing logs.
- cut, awk, grep, sort, uniq for filtering and summarizing data.
- zeek-cut for parsing specific fields from Zeek logs.

Example:
bash
zeek-cut id.orig_h id.resp_h < conn.log | sort | uniq -c


---

# Zeek Signatures

Zeek supports a signature framework that allows pattern matching on network traffic, similar to Snort or Suricata. Signatures are defined in .sig files and can match payload content, byte patterns, and headers. They trigger events that can be logged or trigger actions.

## Answer the questions below

### Q1. Investigate the `http.pcap` file. Create the  HTTP signature shown in the task and investigate the pcap. What is the source IP of the first event?

- Create an HTTP signature that will detect HTTP cleartext passwords
- ![image](https://github.com/user-attachments/assets/133be8aa-8aa5-4a01-9294-61362dd34d26)
- Apply the signature on the pcap file -> `zeek -C -r http.pcap -s http-password.sig`
- ![image](https://github.com/user-attachments/assets/d4a6c56b-5361-4717-af2b-d3a07fab4194)
    - Network logs -> conn.log, http.log
    - file log -> files.log
    - Zeek diagnostic logs -> packet_filter.log
- examine the files of the `http.log` using this command `cat http.log | sed -n 7p`
- ![image](https://github.com/user-attachments/assets/adab4884-8ed7-4b14-aa87-571cc64dd2fd)
- `cat http.log | zeek-cut id.orig_h id.resp_h method`
- ![image](https://github.com/user-attachments/assets/cc0883ff-39c3-4930-b6ce-82ab9b6f4958)

Ans: ***10.10.57.178***

### Q2. What is the source port of the second event?

- `cat http.log | zeek-cut id.orig_h id.orig_p id.resp_h | uniq`
- ![image](https://github.com/user-attachments/assets/7ebfc795-8a33-42e4-a531-4bd65d3331d2)

Ans: ***38712***

### Q3. Investigate the conn.log. What is the total number of the sent and received packets from source port 38706?

- `cat conn.log | zeek-cut id.orig_p orig_pkts resp_pkts | grep "38706"`
- ![image](https://github.com/user-attachments/assets/295e5e82-66d8-4624-8386-27a6ff04e351)

Ans: ***20***

### Q4. Create the global rule shown in the task and investigate the ftp.pcap file. Investigate the notice.log. What is the number of unique events? 

- Create three signatures for ftp protocol: FTP brute force attempt, ftp admin attempt, and ftp login attempt.
- ![image](https://github.com/user-attachments/assets/dbd84bca-f477-402f-9000-b7c0b603f50f)
- `zeek -C -r ftp.pcap -s ftp-bruteforce.sig`
- ![Screenshot 2025-05-02 133631](https://github.com/user-attachments/assets/b82cec29-7adb-44c1-baf5-ef2dbf10719a)
    - Network logs -> conn.log
    - Detections -> notice.log, signatures.log
    - Zeek diagnostic logs -> packet_filter.log
    - Miscellaneous -> weird.log
- `cat notice.log | zeek-cut uid | sort | uniq | wc -l`
- ![image](https://github.com/user-attachments/assets/2d84b966-b519-4776-84ca-1840ca406185)

Ans: ***1413***


### What is the number of ftp-brute signature matches?

- `cat notice.log | zeek-cut msg | grep "Brute-" | wc`
- ![image](https://github.com/user-attachments/assets/41537178-6d25-4770-a667-91d2f8e8782d)

Ans: ***1410***

 
---

# Zeek Scripts | Fundamentals

Zeeks scripting language is event-driven and allows users to define behaviors when specific events (like a new connection or HTTP request) occur. Basic elements include:
- event handlers
- Variables and types
- Conditional logic
- Built-in functions

**Zeek has base scripts installed by default, and these are not intended to be modified. These scripts are located in `/opt/zeek/share/zeek/base`.**
     - ![image](https://github.com/user-attachments/assets/c8dc86f6-6e55-4510-90ae-f75e93552460)

**User-generated or modified scripts should be located in a specific path. These scripts are located in `/opt/zeek/share/zeek/site`.**
    - ![image](https://github.com/user-attachments/assets/447693c9-224b-43ef-b3f2-45a1dec7450b)

**Policy scripts are located in a specific path.These scripts are located in `/opt/zeek/share/zeek/policy`.**
    - ![image](https://github.com/user-attachments/assets/8f4b804d-a9e7-430a-8ac9-e3ae0973dd5b)

**Like Snort, to automatically load/use a script in live sniffing mode, you must identify the script in the Zeek configuration file. You can also use a script for a single run, just like the signatures. The configuration file is located in `/opt/zeek/share/zeek/site/local.zeek`.**
    - ![image](https://github.com/user-attachments/assets/06a659a0-be52-4d63-92ff-b92e78627ff5)


## Answer the questions below

### Q1. Investigate the smallFlows.pcap file. Investigate the dhcp.log file. What is the domain value of the "vinlap01" host?

- ![image](https://github.com/user-attachments/assets/228c12cc-d033-4b82-b766-7b16f82c8a37)
- `zeek -C -r smallFlows.pcap dhcp-hostname.zeek`
    - ![image](https://github.com/user-attachments/assets/518497ab-faef-4387-82da-f71e2b207ba9)

- `cat dhcp.log | zeek-cut host_name domain | grep "vinlap01"`
   - ![image](https://github.com/user-attachments/assets/736f006f-65ad-40db-aff4-7f27a8a0f1c9)

Ans: ***astaro_vineyard***

### Q2. Investigate the bigFlows.pcap file. Investigate the dhcp.log file. What is the number of identified unique hostnames?

- ![image](https://github.com/user-attachments/assets/4d48ea00-07ce-4bd4-b971-5447b9a30826)
- `zeek -C -r bigFlows.pcap dhcp-hostname.zeek`
   - ![image](https://github.com/user-attachments/assets/d810b6e3-b98b-43a5-9acb-eb903ab04e07)
   - ![image](https://github.com/user-attachments/assets/67d79b66-9609-453c-acdd-1a6c988a74ed)
    - **Network logs** -> conn.log, http.log, dns.log, sip.log, ssh.log, ssl.log, syslog.log, smb_files.log, smb_mapping.log, snmp.log, ntp.log, kerberos.log, ntlm.log, dce_rpc.log
    - **file log** -> files.log, ocsp.log, x509.log
    - **Zeek diagnostic logs** -> packet_filter.log, reporter.log
    - **Miscellaneous** -> dpd.log, weird.log


- `cat dhcp.log | zeek-cut host_name | sort | uniq | wc`
- ![image](https://github.com/user-attachments/assets/fd925db3-1607-45b0-bb65-345fd2b5a185)
- The empty value was counted, so it is 17 without it

Ans: ***17***

### Q3. Investigate the dhcp.log file. What is the identified domain value?

- `cat dhcp.log | zeek-cut domain | sort -nr | uniq `
- ![image](https://github.com/user-attachments/assets/20a6ed61-ee24-4d1f-bc7b-6c3790f3b728)

Ans: ***jaalam.net***

---

# Zeek Scripts | Scripts and Signatures

Scripts can complement or extend signatures to provide context-aware detection. For instance, a script might check if an internal host is communicating with a known malicious IP, then log an alert. You can use scripts to:
- Suppress false positives
- Correlate multiple events
- Trigger custom alerts

---

# Zeek Scripts | Frameworks

Zeek includes built-in frameworks such as:
- *Notice Framework*: For generating security notices.
- *Intelligence Framework*: For integrating threat intel feeds.
- *Input Framework*: For reading structured data from files.
These frameworks simplify the creation of complex, structured detection logic.

---

# Zeek Scripts | Packages

Zeek supports a package manager (zkg) to install and manage scripts from the community. Packages extend Zeek's capabilities without needing to write new code from scratch. Examples include:
- Detecting Tor traffic
- Analyzing industrial protocols
- Enhancing log enrichment

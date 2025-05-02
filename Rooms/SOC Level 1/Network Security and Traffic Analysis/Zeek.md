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

---

# Zeek Scripts | Fundamentals

Zeekâs scripting language is event-driven and allows users to define behaviors when specific events (like a new connection or HTTP request) occur. Basic elements include:
- event handlers
- Variables and types
- Conditional logic
- Built-in functions

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

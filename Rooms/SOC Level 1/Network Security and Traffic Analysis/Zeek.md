# TryHackMe: Zeek Room Summary

Room URL: https://tryhackme.com/room/zeekbro

---
# TASK-2: Network Security Monitoring and Zeek

---

## 1. Network Monitoring vs. Network Security Monitoring

### **Network Monitoring (NM)**
- Focuses on **IT infrastructure**:
  - Uptime
  - Device health
  - Performance
  - Traffic management
- Used by **network administrators**
- Purpose:
  - Troubleshooting
  - Performance optimization
- Not primarily concerned with in-depth security analysis
- Not typically within SOC responsibilities

### **Network Security Monitoring (NSM)**
- Focuses on **security anomalies**:
  - Rogue hosts
  - Encrypted or suspicious traffic
  - Unusual port/service use
- Used by **SOC analysts**, **security engineers**, **threat hunters**
- Uses **rules, signatures, anomaly detection**
- Essential part of **SOC operations** (Tier 1-2-3 workflows)

---

## 2. Introduction to Zeek

- **Zeek** (formerly **Bro**) is a **passive network monitoring tool**.
- Developed by **Lawrence Berkeley Labs**, with a commercial version from **Corelight**.
- It’s both **open-source** and **enterprise-ready**.
- Focused on **network traffic analysis** for:
  - Forensics
  - Data analysis
  - Threat hunting

> Zeek provides over **50+ log types** in **7 categories** for deep visibility.

---

## 3. Zeek vs Snort

| Feature        | **Zeek**                                                                 | **Snort**                                               |
|----------------|-------------------------------------------------------------------------|----------------------------------------------------------|
| Type           | NSM & IDS Framework                                                      | IDS/IPS System                                           |
| Focus          | Traffic analysis, threat hunting, correlation                            | Signature-based threat detection                         |
| Detection      | Event-based, customizable scripting                                      | Packet-based, signature pattern matching                 |
| Pros           | In-depth visibility, supports scripting, correlates events               | Easy to deploy, strong community/Cisco support           |
| Cons           | Complex setup, mostly manual analysis                                    | Limited to known attacks (signatures)                    |
| Use Case       | Threat hunting, incident correlation, traffic inspection                 | Real-time intrusion detection and prevention             |

---

## 4. Zeek Architecture

Zeek operates on two main layers:

- **Event Engine**:
  - Processes raw packets
  - Extracts:
    - Source/destination IPs
    - Protocols
    - Sessions
    - Files

- **Policy Script Interpreter**:
  - Correlates and analyzes events using **Zeek scripting**
  - Defines detection logic and alerting behavior

---

## 5. Zeek Frameworks

Zeek supports various frameworks to extend its functionality:

- **Common Frameworks**:
  - Logging
  - Notice
  - Intelligence
  - GeoLocation
  - File Analysis
  - Signature
  - Packet Analysis
  - NetControl
  - TLS Decryption
  - Cluster and Broker Communication

> These frameworks help adapt Zeek to various use cases (e.g., detection, enrichment, clustering).

---

## 6. Zeek Output and Operation

### **Log Generation**
- Logs saved to:
  - Working directory (PCAP mode)
  - `/opt/zeek/logs/` (Service mode)
- Logs are human-readable and cover:
  - DNS, HTTP, connection data, SSL/TLS, DHCP, and more

### **Operating Modes**

#### **Service Mode**
- Used for live traffic monitoring
- Managed via `zeekctl`

#### **PCAP Mode**
- Offline processing of capture files:
  ```bash
  zeek -C -r sample.pcap
  ls -l
  ```

---

## 7. Zeek Commands and Usage

### **ZeekControl Commands**
```bash
zeekctl status   # Check status
zeekctl start    # Start Zeek service
zeekctl stop     # Stop Zeek service
```

### **Main Zeek CLI Parameters**
| Parameter | Description                            |
|-----------|----------------------------------------|
| `-r`      | Process a PCAP file                    |
| `-C`      | Ignore checksum errors                 |
| `-v`      | Show version                           |
| `zeekctl` | Zeek service management module         |

> Additional tools like `cat`, `cut`, `grep`, `sort`, `uniq`, and `zeek-cut` assist in log analysis.

---
# TASK- 3: Zeek Logs

---
Zeek generates log files according to the traffic data. You will have logs for every connection on the wire, including the application-level protocols and fields. Zeek can identify 50+ logs and categorize them into seven categories. Zeek logs are well-structured, tab-separated ASCII files, making them easy to read and process—but they still require effort. Familiarity with networking and protocols is crucial to correlate logs during investigations and find specific evidence.

Each log output consists of multiple fields, each representing different parts of the traffic data. Correlation is done through a unique value called "UID", a unique identifier assigned to each session.

### Zeek Logs Overview

| Category             | Description                              | Log Files |
|---------------------|------------------------------------------|-----------|
| **Network**         | Network protocol logs.                   | `conn.log`, `dce_rpc.log`, `dhcp.log`, `dnp3.log`, `dns.log`, `ftp.log`, `http.log`, `irc.log`, `kerberos.log`, `modbus.log`, `modbus_register_change.log`, `mysql.log`, `ntlm.log`, `ntp.log`, `radius.log`, `rdp.log`, `rfb.log`, `sip.log`, `smb_cmd.log`, `smb_files.log`, `smb_mapping.log`, `smtp.log`, `snmp.log`, `socks.log`, `ssh.log`, `ssl.log`, `syslog.log`, `tunnel.log` |
| **Files**           | File analysis result logs.               | `files.log`, `ocsp.log`, `pe.log`, `x509.log` |
| **NetControl**      | Network control and flow logs.           | `netcontrol.log`, `netcontrol_drop.log`, `netcontrol_shunt.log`, `netcontrol_catch_release.log`, `openflow.log` |
| **Detection**       | Detection and possible indicator logs.   | `intel.log`, `notice.log`, `notice_alarm.log`, `signatures.log`, `traceroute.log` |
| **Network Observations** | Network flow logs.                    | `known_certs.log`, `known_hosts.log`, `known_modbus.log`, `known_services.log`, `software.log` |
| **Miscellaneous**   | Covers external alerts, inputs, failures.| `barnyard2.log`, `dpd.log`, `unified2.log`, `unknown_protocols.log`, `weird.log`, `weird_stats.log` |
| **Zeek Diagnostic** | System messages, actions, statistics.    | `broker.log`, `capture_loss.log`, `cluster.log`, `config.log`, `loaded_scripts.log`, `packet_filter.log`, `print.log`, `prof.log`, `reporter.log`, `stats.log`, `stderr.log`, `stdout.log` |

### Log Update Frequency Examples

| Update Frequency | Log Name           | Description                                  |
|------------------|--------------------|----------------------------------------------|
| Daily            | `known_hosts.log`  | List of hosts that completed TCP handshakes. |
| Daily            | `known_services.log` | List of services used by hosts.             |
| Daily            | `known_certs.log`  | List of SSL certificates.                    |
| Daily            | `software.log`     | List of software used on the network.        |
| Per Session      | `notice.log`       | Anomalies detected by Zeek.                  |
| Per Session      | `intel.log`        | Traffic contains malicious patterns/indicators. |
| Per Session      | `signatures.log`   | List of triggered signatures.                |

> **Note:** Working with Zeek requires strong networking knowledge and an investigative mindset. Don’t worry—you can develop both by practicing and working through exercises like those on TryHackMe.

### Brief Log Usage Primer

| Overall Info        | Protocol Based | Detection        | Observation         |
|---------------------|----------------|------------------|---------------------|
| `conn.log`          | `http.log`     | `notice.log`     | `known_host.log`    |
| `files.log`         | `dns.log`      | `signatures.log` | `known_services.log`|
| `intel.log`         | `ftp.log`      | `pe.log`         | `software.log`      |
| `loaded_scripts.log`| `ssh.log`      | `traceroute.log` | `weird.log`         |

This categorization helps streamline investigations and makes it easier to locate specific anomalies. However, investigations vary by case, so you should adjust your focus accordingly.

#### Investigation Steps Using Logs

1. **Overall Info:** Review general connection, file sharing, loaded scripts, and intel logs.
2. **Protocol Based:** Focus on a specific protocol after identifying suspicious indicators.
3. **Detection:** Use signature-based or custom script outputs for further indicators.
4. **Observation:** Review services, software, and anomalies for a final assessment.

### Zeek Log Analysis Tools

Zeek logs are tab-separated ASCII files, making them suitable for command-line processing. Key tools include:

- **cat, cut, grep, sort, uniq** – For reading and filtering logs.
- **zeek-cut** – A powerful auxiliary tool to extract specific fields from log files.

> Each log file starts with a `#fields` line that lists available columns—these are what you pass to `zeek-cut`.

### Example: Using `zeek-cut` to Parse `conn.log`

```bash
root@ubuntu$ cat conn.log
...
#fields	ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service ...

root@ubuntu$ cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p
CTMFXm1AcIsSnq2Ric	udp	192.168.121.2	51153	192.168.120.22	53
CLsSsA3HLB2N6uJwW	udp	192.168.121.10	50080	192.168.120.10	514
```

This shows how `zeek-cut` simplifies field extraction. Practice reading log formats and try extracting your own insights!



---

# TASK-4 CLI Kung-Fu Recall: Processing Zeek Logs

While GUIs are helpful for visual tasks, CLI tools provide more power and flexibility for deep data processing. Knowing command-line tools is essential for analysts to filter, search, and extract data effectively.

### Command Categories and Examples

#### Basics
```bash
# View history
history

# Run the 10th command from history
!10

# Re-run the previous command
!!
```

#### Read File
```bash
# Display file
cat sample.txt

# First 10 lines
head sample.txt

# Last 10 lines
tail sample.txt
```

#### Find & Filter
```bash
# Cut 1st field (tab-separated)
cut -f 1 test.txt

# Cut 1st column (character-wise)
cut -c1 test.txt

# Filter keyword
grep 'keyword' test.txt

# Sort alphabetically
sort test.txt

# Sort numerically
sort -n test.txt

# Remove duplicate lines
uniq test.txt

# Count lines
wc -l test.txt

# Show line numbers
nl test.txt
```

#### Advanced
```bash
# Print line 11
sed -n '11p' test.txt

# Print lines 10–15
sed -n '10,15p' test.txt

# Print lines < 11
awk 'NR < 11 {print $0}' test.txt

# Print line 11
awk 'NR == 11 {print $0}' test.txt
```

#### Zeek-Specific
```bash
# Extract fields from Zeek log
cat signatures.log | zeek-cut uid src_addr dst_addr
```

#### Use Cases
```bash
# Remove duplicates
sort file | uniq

# Count duplicates
sort file | uniq -c

# Numeric reverse sort
sort -nr file

# Reverse strings
rev file

# Field cut
cut -f 1 file

# Delimiter cut (dot-separated)
cut -d '.' -f 1-2 file

# Invert grep
grep -v 'test' file

# Invert multiple patterns
grep -v -e 'test1' -e 'test2' file

# View file info
file test.txt

# Search everywhere and view neatly
grep -rin Testvalue1 * | column -t | less -S
```

---
# TASK-5: Zeek Signatures

---

**Zeek Signatures Overview**

Zeek signatures enable low-level pattern matching and are useful for identifying specific types of traffic and activities on the network. They are structured differently from Snort rules and primarily serve as a supplementary detection mechanism within Zeek's scripting environment.

### Zeek Signature Structure

Each signature in Zeek consists of three key parts:

1. **Signature ID**: A unique name for the signature.
2. **Conditions**:
   - **Header Filters**:
     - `src-ip`: Source IP
     - `dst-ip`: Destination IP
     - `src-port`: Source port
     - `dst-port`: Destination port
     - `ip-proto`: Protocol (e.g., TCP, UDP, ICMP)
   - **Content Filters**:
     - `payload`: Raw packet data
     - `http-request`, `http-request-header`, `http-request-body`
     - `http-reply-header`, `http-reply-body`
     - `ftp`: FTP command inputs
   - **Context**:
     - `same-ip`: Check if source and destination IPs are the same
3. **Action**:
   - `event`: Message generated when the signature matches
   - Default: Creates `signatures.log` and optionally `notice.log`

**Note**: Supports string, numeric, and regex comparisons using operators like `==`, `!=`, `<`, `>`, etc.

---

### Running Zeek with Signatures

```bash
ubuntu@ubuntu$ zeek -C -r sample.pcap -s sample.sig
```
- `-C`: Ignore checksum errors
- `-r`: Read pcap file
- `-s`: Use the specified signature file

---

### Example 1: Detect Cleartext Passwords

**Signature (http-password.sig)**
```zeek
signature http-password {
     ip-proto == tcp
     dst-port == 80
     payload /.*password.*/
     event "Cleartext Password Found!"
}
```

**Analysis Commands**
```bash
ubuntu@ubuntu$ zeek -C -r http.pcap -s http-password.sig
ubuntu@ubuntu$ cat notice.log | zeek-cut id.orig_h id.resp_h msg
ubuntu@ubuntu$ cat signatures.log | zeek-cut src_addr dest_addr sig_id event_msg
ubuntu@ubuntu$ cat signatures.log | zeek-cut sub_msg
```

---

### Example 2: Detect FTP Admin Logins

**Signature (ftp-admin.sig)**
```zeek
signature ftp-admin {
     ip-proto == tcp
     ftp /.*USER.*dmin.*/
     event "FTP Admin Login Attempt!"
}
```

**Analysis**
```bash
ubuntu@ubuntu$ zeek -C -r ftp.pcap -s ftp-admin.sig
ubuntu@ubuntu$ cat signatures.log | zeek-cut src_addr dst_addr event_msg sub_msg | sort -r | uniq
```

---

### Global Signatures for FTP Brute-Force

**Combined Signatures (ftp-brute.sig)**
```zeek
signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*/
    event "FTP Username Input Found!"
}

signature ftp-brute {
    ip-proto == tcp
    payload /.*530.*Login.*incorrect.*/
    event "FTP Brute-force Attempt!"
}
```

**Analysis**
```bash
ubuntu@ubuntu$ zeek -C -r ftp.pcap -s ftp-brute.sig
ubuntu@ubuntu$ cat notice.log | zeek-cut uid id.orig_h id.resp_h msg sub | sort -r | nl | uniq | sed -n '1001,1004p'
```

---

### Important Notes
- Zeek signatures are effective for specific detection tasks but should be used thoughtfully.
- Case-based rules may generate excessive logs and obscure significant anomalies.
- Optimize rules to focus on meaningful patterns (e.g., FTP error codes).

---

### Snort Rules in Zeek?
Historically, Zeek supported Snort rules via a script (`snort2bro`), but this is no longer maintained or supported in modern Zeek versions. The recommended approach is to use native Zeek scripting and signature formats for network detection and analysis.




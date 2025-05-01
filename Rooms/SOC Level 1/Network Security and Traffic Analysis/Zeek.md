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

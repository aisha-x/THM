# Zeek Exercises

Room URL: https://tryhackme.com/room/zeekbroexercises

---
# TASK-2 Anomalous DNS

An alert triggered: **"Anomalous DNS Activity"**.

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a **true positive**. 

## Answer the questions below

### Q1. Investigate the dns-tunneling.pcap file. Investigate the dns.log file. What is the number of DNS records linked to the IPv6 address?

- `zeek -Cr dns-tunneling.pcap local`
- `cat dns.log | zeek-cut qtype_name | sort |uniq`
- ![image](https://github.com/user-attachments/assets/5dda5d27-7c02-47bb-b7ce-6aa7dba68ed9)
- `"qtype_name": "AAAA" `→ indicates the query was for an IPv6 address.
- `cat dns.log | zeek-cut qtype_name | grep "AAAA"| wc -l`
- ![image](https://github.com/user-attachments/assets/40c3df3b-d5db-4f49-b20b-8d9c0da8abaa)

Ans: ***320***

### Q2. Investigate the conn.log file. What is the longest connection duration?

- `cat conn.log | zeek-cut duration | sort -nr | head`
- ![image](https://github.com/user-attachments/assets/71d30890-92ee-42a7-8156-bbb50cfe28a7)

Ans: ***9.420791***


### Q3. Investigate the dns.log file. Filter all unique DNS queries. What is the number of unique domain queries?

- `cat dns.log | zeek-cut qtype_name | sort | uniq`
- ![image](https://github.com/user-attachments/assets/4ef32209-8c78-4c07-bee7-ed94533b81cb)

Ans: ***6***

### Q4. There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let's find out which hosts are involved in this activity. Investigate the conn.log file. What is the IP address of the source host?

- `cat conn.log | zeek-cut id.orig_h id.resp_h service | grep "dns" `
- ![image](https://github.com/user-attachments/assets/fdb5df36-14a9-48ae-84c5-ae0399763621)
- `cat conn.log | zeek-cut id.orig_h id.resp_h service | awk  '/10.20.57.3/ && /10.10.2.21/' | grep "dns" | wc   `
- ![image](https://github.com/user-attachments/assets/2c09d968-e6c4-4773-ae58-06bb9cb0f1db)
- There are 2851 DNS connections between the two IPs, so it 

Ans: ***10.20.57.3***

## is it True Positive?
Yes — based on the evidence, this strongly appears to be a true positive.
pic

**Why This Is Likely a True Positive?**

1. Patterned, Random Subdomains
   - Hostnames like `d5c8016cb1e77e46b46acb16c24df1aea3.cisco-update.com` are typical of encoded payloads in DNS tunneling.
2. Consistent Base Domain
   - The repeated use of cisco-update.com mimics a legitimate vendor (Cisco), which is a common tactic for evasion.
   - But it's not a legitimate Cisco domain — Cisco uses *.cisco.com.
3. High-Frequency Queries
   - Dozens of queries per second are not normal DNS client behavior.
   - Regular clients would typically query only once per domain and cache the result.
4. Internal-to-Internal DNS Traffic
The DNS server (10.10.2.21) is inside the network, which is suspicious if it's being used to resolve external-looking fake domains.



---
# TASK-3 Phishing

An alert triggered: **"Phishing Attempt"**.

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 


## Answer the questions below

### Q1. Investigate the logs. What is the suspicious source address? Enter your answer in defanged format.

- `zeek -Cr phishing.pcap file-extract-demo.zeek hash-demo.zeek `
- ![image](https://github.com/user-attachments/assets/9ae11e45-816c-4805-b75e-0930d2456dd2)
- `cat http.log | zeek-cut id.orig_h id.resp_h method host uri`
- ![image](https://github.com/user-attachments/assets/0a3673e6-b88d-4026-a425-2b1684194f1f)
- Why this IP 10.6.27.102 suspicious? Because it is requesting an executable file from a suspicious domain that may be associated with malware or phishing 

Ans: ***10[.]6[.]27[.]102***

### Q2. Investigate the http.log file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.

- We already know the domain that is associated with the downloaded file from question 1
- Use CyberChef to defang the domain address
- ![image](https://github.com/user-attachments/assets/f87737bf-095a-41e5-bc86-af401643c319)

Ans: ***smart-fax[.]com***

### Q3. Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?

- View extracted files and hash the malicious document using `md5sum` to generate md5 hash and search for this file in `VirusTotal`
- ![image](https://github.com/user-attachments/assets/fb6451ac-ac5a-4215-afc9-c68ca74958c4)
- ![image](https://github.com/user-attachments/assets/78f06258-c5d9-46e3-b9aa-6cebacddb824)
- ![image](https://github.com/user-attachments/assets/7c869ca3-78cf-4f01-bcd8-6c7122adf1f1)
- The malicious document is a Microsoft Word file containing `VBA` (Visual Basic for Applications) macros. The embedded component `ThisDocument.cls` suggests that it includes a macro-enabled script, which is commonly used to execute malicious code when the document is opened. These types of files are typically used to download or execute malware on the victim's system.

Ans: ***VBA***

### Q3. Investigate the extracted malicious .exe file. What is the given file name in Virustotal?

- gernerate `md5` hash to search for this file in VirusTotal website
- ![image](https://github.com/user-attachments/assets/e662318c-7a9b-4338-833e-2142b3714861)
- ![image](https://github.com/user-attachments/assets/5a78bfd6-bf03-473a-a2b7-a14a7169f471)
- in the Details Tab, under the names section
- ![image](https://github.com/user-attachments/assets/b1041175-4e29-4505-a3f9-5d05e910ca08)

Ans: ***PleaseWaitWindow.exe***

### Q4. Investigate the malicious .exe file in VirusTotal. What is the contacted domain name? Enter your answer in defanged format.

- Continue from question 2, Behaviour > Network Communication > DNS Resolutions
- ![image](https://github.com/user-attachments/assets/885d89ff-81af-4a93-b2de-f91f099317b3)
- ![image](https://github.com/user-attachments/assets/862977c8-ebfb-4ca9-afd1-f03f061539d1)

Ans: ***hopto[.]org***

### Q5. Investigate the http.log file. What is the request name of the downloaded malicious .exe file?

- `cat http.log | zeek-cut method host uri`
- ![image](https://github.com/user-attachments/assets/8e00fe28-4472-43ec-9b11-f67e16cfadb2)

Ans: ***knr.exe***


## is it true positive?

Yes it is a true positive. why?
1. From the `http.log`, there was a suspicious .exe file request from an unknown domain
2. Using the `file-extract-demo.zeek` script, to automatically extract suspicious documents, executables, or payloads for investigation.
3. The extracted files returned three files, two of them were suspicious
4. As a result of investigating both the malicious document and the malicious `.exe` files using **VirusTotal**, we confirmed that these files are indeed malicious.
   


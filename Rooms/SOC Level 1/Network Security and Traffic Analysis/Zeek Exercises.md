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
- there are 2851 number of DNS connections between the two IPs

Ans: ***10.20.57.3***




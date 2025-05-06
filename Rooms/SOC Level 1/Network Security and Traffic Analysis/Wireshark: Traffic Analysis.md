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


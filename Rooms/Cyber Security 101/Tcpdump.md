# TryHackMe: Tcpdump

Room URL: https://tryhackme.com/room/tcpdump

---
# Basic Packet Capture

| Command Option        | Description                                                        |
|-----------------------|--------------------------------------------------------------------|
| `tcpdump -i INTERFACE`| Captures packets on a specific network interface                   |
| `tcpdump -w FILE`     | Writes captured packets to a file                                  |
| `tcpdump -r FILE`     | Reads captured packets from a file                                 |
| `tcpdump -c COUNT`    | Captures a specific number of packets                              |
| `tcpdump -n`          | Don’t resolve IP addresses                                          |
| `tcpdump -nn`         | Don’t resolve IP addresses and don’t resolve protocol numbers       |
| `tcpdump -v`          | Verbose display (increase verbosity with `-vv` or `-vvv`)          |

---
# Filtering Expressions

| Command Option                              | Description                                                                 |
|---------------------------------------------|-----------------------------------------------------------------------------|
| `tcpdump host IP` or `tcpdump host HOSTNAME`| Filters packets by IP address or hostname                                  |
| `tcpdump src host IP`                       | Filters packets by a specific source host                                  |
| `tcpdump dst host IP`                       | Filters packets by a specific destination host                             |
| `tcpdump port PORT_NUMBER`                  | Filters packets by port number (both source and destination)               |
| `tcpdump src port PORT_NUMBER`              | Filters packets by the specified source port number                        |
| `tcpdump dst port PORT_NUMBER`              | Filters packets by the specified destination port number                   |
| `tcpdump PROTOCOL`                          | Filters packets by protocol (e.g., `ip`, `ip6`, `icmp`)                    |


**Answer the Questions Below:**

**Q1. How many packets in traffic.pcap use the ICMP protocol?**
-  `tcpdump -r traffic.pcap icmp -n | wc`
-  ![image](https://github.com/user-attachments/assets/a2856abf-4e66-415f-9a02-8ec7000e3b23)

Ans: ***26***

**Q2. What is the IP address of the host that asked for the MAC address of 192.168.124.137?**
- ` tcpdump -r traffic.pcap arp -n dst host 192.168.124.137`
- ![image](https://github.com/user-attachments/assets/6737500c-19f6-4f1e-b324-8690e4361cfb)

Ans: ***192.168.124.148***

**Q3.What hostname (subdomain) appears in the first DNS query?**

- `tcpdump -r traffic.pcap port 53 -c 2`
- ![image](https://github.com/user-attachments/assets/b0ccd20a-facc-47bd-8255-5b9749b951c9)

Ans: ***mirrors.rockylinux.org***

---
# Advanced Filtering

## Length-Based Filtering

| Command                         | Description                                               |
|----------------------------------|-----------------------------------------------------------|
| `tcpdump greater LENGTH`        | Capture packets with length ≥ specified length            |
| `tcpdump less LENGTH`           | Capture packets with length ≤ specified length            |

---

## Binary Operations (Bitwise Operators)

| Operator | Name | Function                                 |
|----------|------|------------------------------------------|
| `&`      | AND  | Returns 1 only if both bits are 1        |
| `|`      | OR   | Returns 1 if at least one bit is 1       |
| `!`      | NOT  | Inverts the bit (1 → 0, 0 → 1)           |

---

## Header Byte Access Syntax

```bash
proto[offset:size]
```

- **proto**: Protocol (e.g., `ip`, `tcp`, `ether`)
- **offset**: Byte position (starting at 0)
- **size** (optional): Byte length to read (1, 2, or 4 bytes)

### Examples
- `ether[0] & 1 != 0`: Match Ethernet multicast addresses.
- `ip[0] & 0xf != 5`: Match IP packets with options.


## TCP Flag Filtering

| Command Example                                      | Description                                                    |
|-----------------------------------------------------|----------------------------------------------------------------|
| `tcpdump "tcp[tcpflags] == tcp-syn"`                | Capture packets with **only** SYN flag set                     |
| `tcpdump "tcp[tcpflags] & tcp-syn != 0"`            | Capture packets where **SYN** is set (can include others too) |
| `tcpdump "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0"`  | Capture packets with **SYN or ACK** flags set                 |


**Answer the Questions Below:**

**Q1. How many packets have only the TCP Reset (RST) flag set?**
- `tcpdump -r traffic.pcap tcp[tcpflags]==tcp-rst | wc`
- ![image](https://github.com/user-attachments/assets/c1736fbc-a12e-4ab3-ad71-c38cc68092b6)

Ans: ***57***

**Q2. What is the IP address of the host that sent packets larger than 15000 bytes?**

- ` tcpdump -r traffic.pcap -n 'len > 15000' -c 1`
- ![image](https://github.com/user-attachments/assets/b33a7b3f-e9d6-49e1-892f-cea9f573c95f)


Ans: ***185.117.80.53***

---
# Displaying Packets


| Command        | Explanation                                        |
|----------------|----------------------------------------------------|
| `tcpdump -q`   | Quick and quiet: brief packet information          |
| `tcpdump -e`   | Include MAC addresses                              |
| `tcpdump -A`   | Print packets as ASCII encoding                    |
| `tcpdump -xx`  | Display packets in hexadecimal format              |
| `tcpdump -X`   | Show packets in both hexadecimal and ASCII formats |


**Answer the Questions Below:**

**Q1. What is the MAC address of the host that sent an ARP request?**

- ` tcpdump -r traffic.pcap arp -e -c 4 -n`
- ![image](https://github.com/user-attachments/assets/825bcbb9-4551-4c00-b7f0-a4322b38770a)

Ans: ***52:54:00:7c:d3:5b***

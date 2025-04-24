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


Answer the Questions Below:

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

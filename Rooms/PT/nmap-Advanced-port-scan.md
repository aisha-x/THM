# TryHackMe: Nmap Advanced Port Scans

Room URL: https://tryhackme.com/room/nmap03


[Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)

## TCP Null Scan, FIN Scan, Xmas, and **Maimon Scan**

**usage:** when scanning a target behind a stateless (non-stateful) firewall that drops TCP packets with SYN flag .  However, a stateful firewall will practically block all such crafted packets and render this kind of scan useless.

**Null Scan: S**end TCP packets with no flag set. 

- open or filtered → No response
- Closed →  response with an `RST` packet

```html
sudo nmap -sN <target>
```

FIN Scan: Send TCP packet with FIN flag.

- Open or filtered → No response
- Closed →  response with an `RST` packet
- Some firewalls will 'silently' drop the traffic without sending an RST
    
    

```html
sudo nmap -sF <target>
```

**Xmas Scan:** Send TCP packet with FIN, PSH, and URG flags.

- Open or filtered → No response
- Closed →  response with an `RST` packet

```html
sudo nmap -sX <target>
```

**TCP Maimon Scan**: Aiming to identify open ports by observing the target's response. Specifically, it sets the **FIN** and **ACK** flags in a TCP packet. **RFC 793** dictates that a target should respond with a RST packet, regardless of the port's state. However, some systems, particularly older BSD-based systems, would drop the packet entirely if the port was open, thus revealing its open status. While not as effective on modern systems due to their tendency to always respond with an RST, the Maimon scan can still be a useful tool for understanding TCP behavior and potentially bypassing rudimentary firewalls

```html
sudo nmap -sM <target>
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-02 20:08 BST
Nmap scan report for ip-10-10-228-61.eu-west-1.compute.internal (10.10.228.61)
Host is up (0.0062s latency).
All 1000 scanned ports on ip-10-10-228-61.eu-west-1.compute.internal (10.10.228.61) are closed
MAC Address: 02:C4:FE:9A:A2:1D (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds

```

## TCP ACK, Window, and Custom Scan

**ACK Scan**: Send TCP packet with ACK.

- open or closed → TCP response with open or closed, regardless of the post state(if there is no firewall). This is because the ACK flag is set only in response to a received TCP packet to acknowledge the receipt of some data
- unfiltered → means the port is open and is not ****blocked by the firewall.

This type of scan is used to determine if a firewall is present behind the target. By analyzing the responses to ACK packets, you can identify which ports were not blocked by the firewall.

Example-1: Scanning a target with no firewall installed

```bash
pentester@TryHackMe$ sudo nmap -sA 10.10.75.35

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:37 BST
Nmap scan report for 10.10.75.35
Host is up (0.0013s latency).
All 1000 scanned ports on 10.10.75.35 are unfiltered
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.68 second
```

Example-2: Scanning a target with a firewall installed

```bash
root@ip-10-10-245-127:~# sudo nmap -sA 10.10.75.35
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-03 13:42 BST
Nmap scan report for ip-10-10-75-35.eu-west-1.compute.internal (10.10.75.35)
Host is up (0.0013s latency).
Not shown: 996 filtered ports
PORT    STATE      SERVICE
22/tcp  unfiltered ssh
25/tcp  unfiltered smtp
80/tcp  unfiltered http
443/tcp unfiltered https
MAC Address: 02:8F:2D:67:91:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.36 seconds
```

This result indicates that the firewall is blocking all other ports except for these four ports.

**Windows Scan:** Send TCP packet with ACK. It examines the TCP Window field of the RST packets returned

- open or closed → TCP response with open or closed regardless of the port state (if there is no firewall)
- Closed  → means the port is open and is not being blocked by the firewall

Example-1: Scanning a target with no firewall installed

```bash
Pentester@TryHackMe$ sudo nmap -sW 10.10.75.35

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:38 BST
Nmap scan report for 10.10.75.35
Host is up (0.0011s latency).
All 1000 scanned ports on ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27) are closed
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds
```

Example-2:  Scanning a target with a firewall installed

```bash
root@ip-10-10-245-127:~# sudo nmap -sW 10.10.75.35
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-03 14:03 BST
Nmap scan report for ip-10-10-75-35.eu-west-1.compute.internal (10.10.75.35)
Host is up (0.00074s latency).
Not shown: 996 filtered ports
PORT    STATE  SERVICE
22/tcp  closed ssh
25/tcp  closed smtp
80/tcp  closed http
443/tcp closed https
MAC Address: 02:8F:2D:67:91:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.26 seconds

```

- It is essential to note that the ACK scan and the window scan were very efficient at helping us map out the firewall rules. However, it is vital to remember that just because a firewall is not blocking a specific port, it does not necessarily mean that a service is listening on that port. For example, there is a possibility that the firewall rules need to be updated to reflect recent service changes. Hence, ACK and window scans are exposing the firewall rules, not the services.

**Custom Scan:** experiment with a new TCP flag combination other than the built-in TCP scan types, you can use it with  `--scanflags` . For instance, if you want to set SYN, RST, and FIN simultaneously →  `--scanflags RSTSYNFIN`

```bash
root@ip-10-10-245-127:~# sudo nmap --scanflags RSTSYNFIN 10.10.75.35
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-03 14:15 BST
Nmap scan report for ip-10-10-75-35.eu-west-1.compute.internal (10.10.75.35)
Host is up (0.00010s latency).
All 1000 scanned ports on ip-10-10-75-35.eu-west-1.compute.internal (10.10.75.35) are filtered
MAC Address: 02:8F:2D:67:91:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 21.29 seconds

```

## Spoofing and Decoys

**Spoofed**: Scan a target system using a spoofed IP address or a spoofed MAC address.  

`nmap -S SPOOFED_IP <target-ip>` 

```bash
# Spoofed IP
nmap -S SPOOFED_IP <target-ip> 

# Spoofed mac address, only work if the target in the same LAN
nmap --spoof-mac SPOOFED_MAC <target-ip>
```

Scanning with a spoofed IP address is three steps:

1. Attacker sends a packet with a spoofed source IP address to the target machine.
2. Target machine replies to the spoofed IP address as the destination.
3. Attacker captures the replies to figure out open ports.

Terminal-1

```bash
oot@ip-10-10-245-127:~# nmap -e ens5 -Pn -S 10.10.0.2 10.10.75.35 -p22,443,80
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-03 15:28 BST
NSOCK ERROR [0.1160s] mksock_bind_addr(): Bind to 10.10.0.2:0 failed (IOD #1): Cannot assign requested address (99)
Nmap scan report for 10.10.75.35
Host is up (0.000095s latency).

PORT    STATE    SERVICE
22/tcp  filtered ssh
80/tcp  filtered http
443/tcp filtered https
MAC Address: 02:8F:2D:67:91:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 14.40 seconds

```

Terminal-2: Capturing the requests 

```bash
root@ip-10-10-245-127:~# sudo tcpdump -i ens5 host 10.10.0.2 -n -C 14
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens5, link-type EN10MB (Ethernet), capture size 262144 bytes
15:28:47.732584 IP 10.10.0.2.56998 > 10.10.75.35.80: Flags [S], seq 1031003937, win 1024, options [mss 1460], length 0
15:28:47.732685 IP 10.10.0.2.56998 > 10.10.75.35.443: Flags [S], seq 1031003937, win 1024, options [mss 1460], length 0
15:28:47.732706 IP 10.10.0.2.56998 > 10.10.75.35.22: Flags [S], seq 1031003937, win 1024, options [mss 1460], length 0
15:28:48.833930 IP 10.10.0.2.56999 > 10.10.75.35.22: Flags [S], seq 1030938400, win 1024, options [mss 1460], length 0
15:28:48.833980 IP 10.10.0.2.56999 > 10.10.75.35.443: Flags [S], seq 1030938400, win 1024, options [mss 1460], length 0
15:28:48.833993 IP 10.10.0.2.56999 > 10.10.75.35.80: Flags [S], seq 1030938400, win 1024, options [mss 1460], length 0

```

Decoys: Scan the target with multiple IP addresses, along with the attacker's IP. `ME` is the attacker IP and `RND` is to assign IP addresses randomly 

```bash
nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME 10.10.75.35
```

Example: `10.10.245.127` Is the attacker's IP

```bash
Nmap done: 1 IP address (1 host up) scanned in 5.25 seconds
root@ip-10-10-245-127:~# nmap -D 10.10.0.1,10.10.0.2,RND,RND,10.10.245.127 10.10.75.35
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-03 14:44 BST
Nmap scan report for ip-10-10-75-35.eu-west-1.compute.internal (10.10.75.35)
Host is up (0.00054s latency).
Not shown: 996 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
80/tcp  open   http
443/tcp closed https
MAC Address: 02:8F:2D:67:91:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.27 seconds
root@ip-10-10-245-127:~# 
```

## Fragmented Packets

When you use **`-f`**, Nmap splits its packets into smaller chunks (usually **8 bytes per fragment** for TCP headers). The **`-ff`** option splits them even further (**16 bytes per fragment**).

This technique can:

- **Bypass simple firewalls** that don't reassemble packets.
- **Avoid signature detection** (some IDS rules look for full packets).
- **Test network stack behavior** (some systems mishandle fragments

```bash
root@ip-10-10-130-7:~# nmap -sS -p80,8080,22 10.10.41.114 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-04 13:10 BST
Nmap scan report for ip-10-10-41-114.eu-west-1.compute.internal (10.10.41.114)
Host is up (0.00014s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
8080/tcp closed http-proxy
MAC Address: 02:46:A9:39:97:DB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.20 seconds

```

```bash
root@ip-10-10-130-7:~# tcpdump -i ens5 host 10.10.41.114 -n
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens5, link-type EN10MB (Ethernet), capture size 262144 bytes
13:10:49.531322 ARP, Request who-has 10.10.41.114 tell 10.10.130.7, length 28
13:10:49.531388 ARP, Reply 10.10.41.114 is-at 02:46:a9:39:97:db, length 28
13:10:49.595377 IP 10.10.130.7.57784 > 10.10.41.114.22: Flags [S], seq 480432743, win 1024, options [mss 1460], length 0
13:10:49.595453 IP 10.10.130.7.57784 > 10.10.41.114.8080: Flags [S], seq 480432743, win 1024, options [mss 1460], length 0
13:10:49.595491 IP 10.10.130.7.57784 > 10.10.41.114.80: Flags [S], seq 480432743, win 1024, options [mss 1460], length 0
13:10:49.595676 IP 10.10.41.114.22 > 10.10.130.7.57784: Flags [S.], seq 121427655, ack 480432744, win 62727, options [mss 8961], length 0
13:10:49.595676 IP 10.10.41.114.8080 > 10.10.130.7.57784: Flags [R.], seq 0, ack 480432744, win 0, length 0
13:10:49.595676 IP 10.10.41.114.80 > 10.10.130.7.57784: Flags [S.], seq 3676031566, ack 480432744, win 62727, options [mss 8961], length 0
13:10:49.595728 IP 10.10.130.7.57784 > 10.10.41.114.22: Flags [R], seq 480432744, win 0, length 0
13:10:49.595740 IP 10.10.130.7.57784 > 10.10.41.114.80: Flags [R], seq 480432744, win 0, length 0

```

Exmple-1: **Basic Fragmentation (`-f`)**

```bash
root@ip-10-10-130-7:~# nmap -sS -p80,8080,22 -f  10.10.41.114 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-04 13:06 BST
Nmap scan report for ip-10-10-41-114.eu-west-1.compute.internal (10.10.41.114)
Host is up (0.00010s latency).

PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
8080/tcp filtered http-proxy
MAC Address: 02:46:A9:39:97:DB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds

```

capturing

```bash
root@ip-10-10-130-7:~# tcpdump -i ens5 host 10.10.41.114 -n
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens5, link-type EN10MB (Ethernet), capture size 262144 bytes
13:06:27.490801 ARP, Request who-has 10.10.41.114 tell 10.10.130.7, length 28
13:06:27.490890 ARP, Reply 10.10.41.114 is-at 02:46:a9:39:97:db, length 28
13:06:27.555571 IP 10.10.130.7.50201 > 10.10.41.114.80: [|tcp]
13:06:27.555684 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:27.555690 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:27.555747 IP 10.10.130.7.50201 > 10.10.41.114.22: [|tcp]
13:06:27.555752 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:27.555756 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:27.555816 IP 10.10.130.7.50201 > 10.10.41.114.8080: [|tcp]
13:06:27.555821 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:27.555825 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:28.656191 IP 10.10.130.7.50202 > 10.10.41.114.8080: [|tcp]
13:06:28.656213 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:28.656218 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:28.656252 IP 10.10.130.7.50202 > 10.10.41.114.22: [|tcp]
13:06:28.656257 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:28.656261 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:28.656288 IP 10.10.130.7.50202 > 10.10.41.114.80: [|tcp]
13:06:28.656292 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:06:28.656296 IP 10.10.130.7 > 10.10.41.114: ip-proto-6

```

Example-2: **More Aggressive Fragmentation (`-ff`)**

```bash
oot@ip-10-10-130-7:~# nmap -sS -p80,8080,22 -ff  10.10.41.114 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2025-08-04 13:08 BST
Nmap scan report for ip-10-10-41-114.eu-west-1.compute.internal (10.10.41.114)
Host is up (0.00019s latency).

PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
8080/tcp filtered http-proxy
MAC Address: 02:46:A9:39:97:DB (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.39 seconds

```

```bash
root@ip-10-10-130-7:~# tcpdump -i ens5 host 10.10.41.114 -n
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens5, link-type EN10MB (Ethernet), capture size 262144 bytes
13:08:15.642941 ARP, Request who-has 10.10.41.114 tell 10.10.130.7, length 28
13:08:15.643120 ARP, Reply 10.10.41.114 is-at 02:46:a9:39:97:db, length 28
13:08:15.706897 IP 10.10.130.7.40298 > 10.10.41.114.80: [|tcp]
13:08:15.706932 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:08:15.707143 IP 10.10.130.7.40298 > 10.10.41.114.8080: [|tcp]
13:08:15.707148 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:08:15.707172 IP 10.10.130.7.40298 > 10.10.41.114.22: [|tcp]
13:08:15.707177 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:08:16.808112 IP 10.10.130.7.40299 > 10.10.41.114.22: [|tcp]
13:08:16.808142 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:08:16.808166 IP 10.10.130.7.40299 > 10.10.41.114.8080: [|tcp]
13:08:16.808199 IP 10.10.130.7 > 10.10.41.114: ip-proto-6
13:08:16.808218 IP 10.10.130.7.40299 > 10.10.41.114.80: [|tcp]
13:08:16.808221 IP 10.10.130.7 > 10.10.41.114: ip-proto-6

```

## Idle/Zombie Scan

**Prerequisites**

- The **zombie host** must:
    - Be **idle** (minimal network activity).
    - Use **incremental IP IDs** (not random).
    - Have **at least one open/unfiltered port** (to monitor IP ID changes).

**Step-by-Step Process**

1. **Attacker probes the zombie’s IP ID (Initial Baseline)**
    - Attacker sends a **SYN/ACK** (or SYN) to the zombie’s open port (e.g., port **`3389`**).
    - Zombie responds with **RST**, revealing its current **IP ID = X**.
        
        *(This establishes a baseline for comparison.)*
        
2. **Attacker spoofs a SYN to the target, pretending to be the zombie**
    - Attacker sends a **SYN to the target** with a **spoofed source IP = zombie’s IP**.
    - **Target’s response depends on the port state**:
        - **If target port is OPEN**:
            
            → Target sends **SYN/ACK to the zombie**.
            
            → Zombie (confused) responds with **RST**, incrementing its IP ID to **X+1**.
            
        - **If target port is CLOSED**:
            
            → Target sends **RST to the zombie**.
            
            → Zombie **ignores it** (no response), so IP ID **stays at X**.
            
3. **Attacker re-probes the zombie to check IP ID change**
    - Attacker sends another **SYN/ACK** to the zombie.
    - Zombie responds with **RST** and a new IP ID:
        - **If IP ID = X+1**:
            
            → Target port is **closed** (only the attacker’s probe incremented it).
            
        - **If IP ID = X+2**:
            
            → Target port is **open** (target’s SYN/ACK + attacker’s probe incremented it twice).
            

Example: use the option `--packet-trace` to examine the IP ID

```bash
nmap -sI zombie_ip:open_port target_ip -Pn -p80

```

Check → [How to Perform an Idle Scan](https://iritt.medium.com/mastering-network-scanning-a-practical-guide-to-nmap-and-masscan-43491ca0dfac#:~:text=How%20to%20Perform%20an%20Idle%20Scan) 

## Summary

| **Port Scan Type** | **Example Command** |
| --- | --- |
| TCP Null Scan | `sudo nmap -sN 10.10.41.114` |
| TCP FIN Scan | `sudo nmap -sF 10.10.41.114` |
| TCP Xmas Scan | `sudo nmap -sX 10.10.41.114` |
| TCP Maimon Scan | `sudo nmap -sM 10.10.41.114` |
| TCP ACK Scan | `sudo nmap -sA 10.10.41.114` |
| TCP Window Scan | `sudo nmap -sW 10.10.41.114` |
| Custom TCP Scan | `sudo nmap --scanflags URGACKPSHRSTSYNFIN 10.10.41.114` |
| Spoofed Source IP | `sudo nmap -S SPOOFED_IP 10.10.41.114` |
| Spoofed MAC Address | `--spoof-mac SPOOFED_MAC` |
| Decoy Scan | `nmap -D DECOY_IP,ME 10.10.41.114` |
| Idle (Zombie) Scan | `sudo nmap -sI ZOMBIE_IP 10.10.41.114` |
| Fragment IP data into 8 bytes | `-f` |
| Fragment IP data into 16 bytes | `-ff` |

| **Option** | **Purpose** |
| --- | --- |
| `--source-port PORT_NUM` | specify source port number |
| `--data-length NUM` | append random data to reach given length |

These scan types rely on setting TCP flags in unexpected ways to prompt ports for a reply. Null, FIN, and Xmas scan provoke a response from closed ports, while Maimon, ACK, and Window scans provoke a response from open and closed ports.

| **Option** | **Purpose** |
| --- | --- |
| `--reason` | explains how Nmap made its conclusion |
| `-v` | verbose |
| `-vv` | very verbose |
| `-d` | debugging |
| `-dd` | more details for debugging |

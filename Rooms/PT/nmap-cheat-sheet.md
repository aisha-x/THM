### [**Nmap Live Host Discovery**](https://tryhackme.com/room/nmap01)

| **Scan Type** | **Example Command** |
| --- | --- |
| ARP Scan | `sudo nmap -PR -sn MACHINE_IP/24` |
| ICMP Echo Scan | `sudo nmap -PE -sn MACHINE_IP/24` |
| ICMP Timestamp Scan | `sudo nmap -PP -sn MACHINE_IP/24` |
| ICMP Address Mask Scan | `sudo nmap -PM -sn MACHINE_IP/24` |
| TCP SYN Ping Scan | `sudo nmap -PS22,80,443 -sn MACHINE_IP/30` |
| TCP ACK Ping Scan | `sudo nmap -PA22,80,443 -sn MACHINE_IP/30` |
| UDP Ping Scan | `sudo nmap -PU53,161,162 -sn MACHINE_IP/30` |

Remember to add `-sn` if you are only interested in host discovery without port-scanning. Omitting `-sn` will let Nmap default to port-scanning the live hosts.

| **Option** | **Purpose** |
| --- | --- |
| `-n` | no DNS lookup |
| `-R` | reverse-DNS lookup for all hosts |
| `-sn` | host discovery only |

### [Nmap Basic Port Scan](https://tryhackme.com/room/nmap02)

| **Port Scan Type** | **Example Command** |
| --- | --- |
| TCP Connect Scan | `nmap -sT MACHINE_IP` |
| TCP SYN Scan | `sudo nmap -sS MACHINE_IP` |
| UDP Scan | `sudo nmap -sU MACHINE_IP` |

These scan types should get you started discovering running TCP and UDP services on a target host.

| **Option** | **Purpose** |
| --- | --- |
| `-p-` | all ports |
| `-p1-1023` | scan ports 1 to 1023 |
| `-F` | 100 most common ports |
| `-r` | scan ports in consecutive order |
| `-T<0-5>` | -T0 being the slowest and T5 the fastest |
| `--max-rate 50` | rate <= 50 packets/sec |
| `--min-rate 15` | rate >= 15 packets/sec |
| `--min-parallelism 100` | at least 100 probes in parallel |

### [Nmap Advanced port scan](https://tryhackme.com/room/nmap03)

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
| `--reason` | explains how Nmap made its conclusion |
| `-v` | verbose |
| `-vv` | very verbose |
| `-d` | debugging |
| `-dd` | more details for debugging |

### [**Nmap Post Port Scans**](https://tryhackme.com/room/nmap04)

| **Option** | **Meaning** |
| --- | --- |
| `-sV` | determine service/version info on open ports |
| `-sV --version-light` | try the most likely probes (2) |
| `-sV --version-all` | try all available probes (9) |
| `-O` | detect OS |
| `--traceroute` | run traceroute to target |
| `--script=SCRIPTS` | Nmap scripts to run |
| `-sC` or `--script=default` | run default scripts |
| `-A` | equivalent to `-sV -O -sC --traceroute` |
| `-oN` | save output in normal format |
| `-oG` | save output in grepable format |
| `-oX` | save output in XML format |
| `-oA` | save output in normal, XML and Grepable formats |

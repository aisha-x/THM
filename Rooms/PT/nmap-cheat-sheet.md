### Nmap port scan

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

### **Nmap Post Port Scans**

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

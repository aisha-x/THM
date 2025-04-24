# TryHackMe: Nmap The Basics

Room URL: https://tryhackme.com/room/nmap

# Summary

## 📄 Nmap Options Summary

| **Option**                                      | **Explanation**                                                                 |
|------------------------------------------------|---------------------------------------------------------------------------------|
| `-sL`                                           | List scan – list targets without scanning                                       |
| **Host Discovery**                              |                                                                                 |
| `-sn`                                           | Ping scan – host discovery only                                                 |
| **Port Scanning**                               |                                                                                 |
| `-sT`                                           | TCP connect scan – complete three-way handshake                                 |
| `-sS`                                           | TCP SYN – only first step of the three-way handshake                            |
| `-sU`                                           | UDP Scan                                                                        |
| `-F`                                            | Fast mode – scans the 100 most common ports                                     |
| `-p[range]`                                     | Specifies a range of port numbers – `-p-` scans all the ports                   |
| `-Pn`                                           | Treat all hosts as online – scan hosts that appear to be down                  |
| **Service Detection**                           |                                                                                 |
| `-O`                                            | OS detection                                                                    |
| `-sV`                                           | Service version detection                                                       |
| `-A`                                            | OS detection, version detection, and other additions                            |
| **Timing**                                      |                                                                                 |
| `-T<0-5>`                                       | Timing template – paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5) |
| `--min-parallelism <numprobes>`                | Minimum number of parallel probes                                               |
| `--max-parallelism <numprobes>`                | Maximum number of parallel probes                                               |
| `--min-rate <number>`                          | Minimum rate (packets/second)                                                   |
| `--max-rate <number>`                          | Maximum rate (packets/second)                                                   |
| `--host-timeout`                                | Maximum amount of time to wait for a target host                                |
| **Real-time Output**                            |                                                                                 |
| `-v`                                            | Verbosity level – for example, `-vv` and `-v4`                                  |
| `-d`                                            | Debugging level – for example `-d` and `-d9`                                    |
| **Report**                                      |                                                                                 |
| `-oN <filename>`                                | Normal output                                                                   |
| `-oX <filename>`                                | XML output                                                                      |
| `-oG <filename>`                                | Grep-able output                                                                |
| `-oA <basename>`                                | Output in all major formats (Normal, XML, and Grep-able)                        |

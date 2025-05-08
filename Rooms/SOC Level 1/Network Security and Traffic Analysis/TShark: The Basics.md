# tryhackme: TShark the Basics Summary

Room URL: https://tryhackme.com/room/tsharkthebasics


## Overview
**TShark** is the command-line version of **Wireshark**, a powerful network protocol analyzer. It allows users to capture and analyze packets in real-time or from saved capture files. TShark is especially useful for scripting, remote analysis, and automation tasks, where a GUI is not practical.

- Part of the **Wireshark suite**
- Cross-platform (Linux, Windows, macOS)
- Suitable for deep packet inspection and troubleshooting

---

## Common Parameters

| Parameter | Description |
|----------|-------------|
| `-i <interface>` | Specify the network interface to capture from (e.g., `-i eth0`) |
| `-w <file>` | Write captured packets to a file in pcap format |
| `-r <file>` | Read packets from a capture file |
| `-c <count>` | Capture only the specified number of packets |
| `-f <capture filter>` | Apply a **capture filter** using BPF syntax |
| `-Y <display filter>` | Apply a **display filter** to captured or read packets |
| `-T <format>` | Output format (e.g., `fields`, `json`, `pdml`) |
| `-e <field>` | Specify fields to extract when using `-T fields` |
| `-V` | Show packet details (verbose mode) |
| `-q` | Quiet mode (minimal output) |
| `--color` | Colorize output (for better readability) |

---

## Supplemental CLI Tools

| Tool | Description |
|------|-------------|
| **dumpcap** | Efficient packet capture engine used by Wireshark and TShark |
| **capinfos** | Display summary information about capture files |
| **editcap** | Edit and manipulate capture files (e.g., split, trim) |
| **mergecap** | Merge multiple capture files into one |
| **text2pcap** | Convert text files to pcap format for analysis |
| **captype** | Identify the file type of capture files |

---

## Packet Filtering Options

### Capture Filters (BPF Syntax)
- Applied **before** capturing packets
- More efficient (filters out unwanted packets at the capture level)

**Examples:**
```bash
-f "tcp port 80"
-f "host 192.168.1.1"
-f "udp"
```

### Display Filters
- Display filters use Wireshark's filter syntax.
- They are applied after the packets are captured or while reading a capture file.
- Very expressive: allows deep inspection of protocol-specific fields.

**Examples:**
```bash
-Y "ip.addr == 192.168.1.100"
-Y "tcp.flags.syn == 1 && tcp.flags.ack == 0"
-Y "http.request.method == \"GET\""
-Y "dns.qry.name contains \"example.com\""
```

## Example Use Cases
1. Capture traffic on eth0 for 60 packets and save to file:
```bash
tshark -i eth0 -c 60 -w session.pcap
```
2. Read a pcap file and display only DNS queries:
```bash
tshark -r capture.pcap -Y "dns.flags.response == 0"
```
3. Extract HTTP GET requests from a file:
```bash
tshark -r web_traffic.pcap -Y "http.request.method == \"GET\"" -T fields -e http.host -e http.request.uri
```

# References:
- TShark Manual - > *https://www.wireshark.org/docs/man-pages/tshark.html*
- Display Filters -> *https://wiki.wireshark.org/DisplayFilters*
- Capture Filters -> *https://wiki.wireshark.org/CaptureFilters*

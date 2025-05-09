# TryHackMe: TShark: CLI Wireshark Features Summary


Room URL: https://tryhackme.com/room/tsharkcliwiresharkfeatures

---
# Command-Line Wireshark Features I | Statistics I

| Feature                      | Description                                                                 | Example Command                                      |
|-----------------------------|-----------------------------------------------------------------------------|------------------------------------------------------|
| `tshark`                    | Terminal-based Wireshark, used for packet capturing and analysis           | `tshark -i eth0`                                     |
| Interface listing           | List all available interfaces                                               | `tshark -D`                                          |
| Basic capture to file       | Capture packets and save to .pcap file                                      | `tshark -i eth0 -w capture.pcap`                     |
| Protocol hierarchy stats    | Show protocol distribution                                                  | `tshark -r capture.pcap -q -z io,phs`                |
| Conversations stats         | Show conversation details (e.g., TCP, UDP)                                  | `tshark -r capture.pcap -q -z conv,tcp`              |
| Endpoints stats             | Show endpoints involved in traffic                                          | `tshark -r capture.pcap -q -z endpoints,ip`          |
| Packet counts/time stats    | Count packets per protocol/time interval                                    | `tshark -r capture.pcap -q -z io,stat,0.5`           |


---
# Command-Line Wireshark Features III | Streams, Objects and Credentials
| Feature                      | Description                                                                 | Example Command                                      |
|-----------------------------|-----------------------------------------------------------------------------|------------------------------------------------------|
| TCP stream extraction       | Follow and extract a specific TCP stream                                    | `tshark -r capture.pcap -q -z follow,tcp,ascii,1`    |
| HTTP objects export         | Extract HTTP-transferred files (use Wireshark GUI or `wireshark -r`)        | Not directly in `tshark`, use `wireshark -r`         |
| Credentials analysis        | Display credentials sent over protocols (e.g., FTP, HTTP)                   | Use filters like `ftp.request.command == "USER"`     |
| Follow UDP stream           | Analyze UDP communication                                                    | `tshark -r capture.pcap -q -z follow,udp,ascii,1`    |
| Extract text streams        | Output stream data in ASCII                                                  | `tshark -z follow,tcp,ascii,<stream_index>`          |


---
#  Advanced Filtering Options | Contains, Matches and Fields

| Filter Type                 | Syntax/Keyword         | Description                                                                 | Example                                           |
|----------------------------|------------------------|-----------------------------------------------------------------------------|---------------------------------------------------|
| Contains                   | `contains`             | Checks if a field contains a specified string                              | `http contains "login"`                           |
| Matches                    | `matches`              | Uses regex to match field content                                           | `ip.addr matches "^192\.168\.1\.\d+$"`            |
| Field-based filters        | `<protocol>.<field>`   | Filters based on specific field values                                      | `ip.src == 192.168.1.10`                          |
| And / Or                   | `and`, `or`             | Logical operations in filters                                               | `ip.src == 10.0.0.1 && tcp.port == 443`|
| Display specific fields    | `-T fields -e <field>` | Extract and print specific fields                                           | `tshark -r capture.pcap -T fields -e ip.src`       |
| Multiple fields output     | Combine `-e` options   | Output multiple specific fields from each packet                            | `tshark -r capture.pcap -T fields -e ip.src -e ip.dst` |


---
# Use Cases:

### Use Case 1: Extract All IPs Accessing a Specific URL Endpoint
**Objective:** Identify all source IPs that accessed a login page over HTTP, then count the number of requests per IP.

**Command:**
```bash
tshark -r traffic.pcap -Y 'http.request.uri contains "/login"' -T fields -e ip.src | sort | uniq -c | sort -nr
```
- `-Y 'http.request.uri contains "/login"'`: Applies display filter to match /login requests
- `-T fields -e ip.src`: Outputs only the source IP field


---

### Use Case 2: Extract Files Downloaded Over HTTP and Check for Suspicious File Types


**Objective:** Detect downloaded `.exe` or `.zip` files from HTTP traffic and list the URLs and file names.

**Command:**
```bash
tshark -r capture.pcap -Y 'http.content_type contains "application"' \
-T fields -e http.host -e http.request.uri -e http.file_data | \
grep -Ei "\.exe|\.zip"
```
- Filters HTTP requests with application content types
- Extracts the host, URI, and file data
- `grep -Ei "\.exe|\.zip"` filters for suspicious file types


---

### Use Case 3: Follow a TCP Stream Involving a Specific IP, Extract Credentials, and Save to File

**Objective:** Follow a TCP stream involving `192.168.1.100`, extract ASCII content (possibly credentials), and save it.

**Command:**
```bash
STREAM_INDEX=$(tshark -r session.pcap -Y "ip.addr == 192.168.1.100" -T fields -e tcp.stream | sort -u | head -n 1)
tshark -r session.pcap -q -z "follow,tcp,ascii,$STREAM_INDEX" > extracted_stream.txt
```
- Finds the TCP stream index associated with a specific IP
- Extracts the full ASCII stream and saves it to a file
- You can inspect `extracted_stream.txt` for plaintext credentials (e.g., from FTP, HTTP Basic Auth)


### Use Case 4: Identify suspicious domain and follow TCP stream

**Objective:** A victim login to a malicious website thinking it was a legitimate one.

> Note: this case from **TShark Challenge I: Teamwork**

1. Identify the domain
   - `tshark -r teamwork.pcap -T fields -e http.host -q |awk NF | sort | uniq -c`
   - ![image](https://github.com/user-attachments/assets/34ca7f61-2b4a-4d28-a984-fe13eb403bef)
   - the malicious domain -> `paypal`
2. Identify the IP address of the malicious domain
  - `tshark -r teamwork.pcap -T fields -e http.host -e ip.dst -q |awk NF | sort | uniq -c`
  - ![image](https://github.com/user-attachments/assets/2082103b-2ea4-4906-954d-138c0fe23774)
  - malicious domain ip address -> `184[.]154[.]127[.]226`
3. Search for POST method
  - `tshark -r teamwork.pcap -Y 'http contains "mail"' -T fields -e tcp.stream`
  - The above command will return the TCP stream of that packet containing mail text, which is -> `28`. You can also search for  `http.method=="POST"`
  - Follow this TCP stream and write the result into extracted-stream.txt file `tshark -r teamwork.pcap -z follow,tcp,ascii,28  -q > extracted-stream.txt`
  - ![image](https://github.com/user-attachments/assets/0b0c917b-0f89-4613-9f00-b30ebb05187a)

4. Return the email of the victim
  - ![image](https://github.com/user-attachments/assets/b1462c03-9c50-4b57-bdca-69f802137bbb)
  - email -> `johnny5alive[at]gmail[.]com`
  - passowrd -> `johnny5alive`



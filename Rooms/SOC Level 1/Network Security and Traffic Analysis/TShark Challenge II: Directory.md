# TryHackMe: TShark Challenge II: Directory Challenge

Room URL: https://tryhackme.com/room/tsharkchallengestwo

---
# Case: Directory Curiosity!

An alert has been triggered: "A user came across a poor file index, and their curiosity led to problems".

The case was assigned to you. Inspect the provided directory-curiosity.pcap located in ~/Desktop/exercise-files and retrieve the artefacts to confirm that this alert is a true positive.

Your tools: [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [VirusTotal](https://www.virustotal.com/gui/home/upload).

## Answer the questions below

- Investigate the DNS queries.
- Investigate the domains by using VirusTotal.
- According to VirusTotal, there is a domain marked as malicious/suspicious.


### Q1. What is the name of the malicious/suspicious domain?

- `tshark -r directory-curiosity.pcap -T fields -e http.host | awk NF | sort | uniq -c`

![Screenshot 2025-05-09 203730](https://github.com/user-attachments/assets/d8fc58d4-eabc-4863-9a2b-b9f32617bb8e)

- the domain `jx2` flagged as malicious in VirusTotal

Ans: ***jx2-bavuong[.]com***

---

### Q2. What is the total number of HTTP requests sent to the malicious domain?

- in the previous question, I used `uniq -c` to count how many http request were made on each uniq host, and for the suspicious host, it was 14 times  

Ans: ***14***

---

### Q3.What is the IP address associated with the malicious domain?

- `tshark -r directory-curiosity.pcap -Y 'http.host contains "jx2"' -T fields -e ip.dst -e http.host -q | head -n1`

 ![Screenshot 2025-05-09 204503](https://github.com/user-attachments/assets/b02ca9ae-ede9-47b3-ad04-f5fe0391f3fa)


Ans: ***141[.]164[.]41[.]174***


---
### Q4. What is the server info of the suspicious domain?


```bash
tshark -r directory-curiosity.pcap -Y 'http.host contains "jx2"' -T fields -e tcp.stream -e http.request.method -e http.host -e http.request.uri -q | awk NF
```

![Screenshot 2025-05-09 170229](https://github.com/user-attachments/assets/e3bfd951-f716-43bd-9cbf-33a0cf10f73c)

- The URI paths `/newbot/`, `/vlauto.exe`, and `/botlogger.php` strongly suggest:
   - Possible malware C2 communication
   - Executable file download (`vlauto.exe`)
   - Logging or data exfiltration (`botlogger.php`)

- Next step reconstruct the TCP stream for stream 9:
```bash
tshark -r directory-curiosity.pcap -z follow,tcp,ascii,9  -q`
```
 ![Screenshot 2025-05-09 170430](https://github.com/user-attachments/assets/cf209c51-4737-411e-8eeb-08f89f66d4ce)

- This will show exactly what was sent/received in that stream — useful for credential stealing, payload analysis, or commands.

Ans: ***Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9***


---
### Q5. Follow the "first TCP stream" in "ASCII". Investigate the output carefully. What is the number of listed files?

```bash
tshark -r directory-curiosity.pcap -z follow,tcp,ascii,0 -q | grep -E "\.(exe|php)"`
```
 ![Screenshot 2025-05-09 211614](https://github.com/user-attachments/assets/16fb2993-b9d6-4573-9ad6-1a2c548b4b0d)

- `vlauto.exe` → Possibly a malware payload (Windows executable)
- `vlauto.php`, `123.php` → PHP scripts, could be C2 panels, uploaders, or backdoors

Ans: ***3***


---
### Q6.What is the filename of the first file?

Ans: ***123[.]php***


### Q7.Export all HTTP traffic objects. What is the name of the downloaded executable file?

- make a directory `mkdir extracted-objects`
- then export HTTP objects (like `.exe`, `.jpg`, `.php`, etc.) to the extracted-objects directory.
```bash
tshark -r directory-curiosity.pcap --export-objects http,extracted-objects -q`
```
 ![Screenshot 2025-05-09 212316](https://github.com/user-attachments/assets/41833032-ebe0-4350-8a61-f5789d480275)


Ans: ***vlauto[.]exe***

### Q8.What is the SHA256 value of the malicious file?

```bash
`sha256sum extracted-objects/vlauto.exe`
```
Ans: ***b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de***


### Q9.Search the SHA256 value of the file on VirtusTotal. What is the "PEiD packer" value?
- PEiD is a well-known Windows tool used to detect packers, cryptors, and compilers that were used to build or protect an executable file.
  ![Screenshot 2025-05-09 212928](https://github.com/user-attachments/assets/8c7279f9-d149-4ea6-8436-4fc92da93204)

- This indicates the executable was built using the `.NET `Framework, most likely with: C# or VB.NET.

Ans: ***.NET executable***

### Q10.Search the SHA256 value of the file on VirtusTotal. What does the "Lastline Sandbox" flag this as?

![Screenshot 2025-05-09 213848](https://github.com/user-attachments/assets/b7247eee-b823-443f-b085-8edcb5beba6a)

Ans: ***MALWARE TROJAN***



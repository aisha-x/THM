# TryHackMe Yara Room

Room URL: https://tryhackme.com/room/yara

Due to the poor explanation of the Yara tool in this room, I used external resources.

# Contents:

1. Understanding YARA Rule  
2. The Structure of a YARA Rule  
3. Use Cases for YARA  
4. YARA Modules  
5. YARA Tools  
6. Loki Scanner  
7. Creating a Custom YARA Rule  
8. Using Valhalla for Threat Intelligence  

---

# 1- Understanding YARA Rules

**YARA**, humorously dubbed "Yet Another Ridiculous Acronym," is a framework for large-scale pattern matching, most often used in malware detection and classification. YARA rules enable analysts to describe malware families using text or binary patterns.

These rules can detect more than just malware — they are also capable of identifying various digital artifacts, including specific files and byte sequences within binary data. YARA rules are widely used by cybersecurity professionals, threat analysts, and malware researchers for digital forensics and real-time threat detection.

---

## Five Core Elements of a YARA Rule
Before crafting your own YARA rules, it's essential to understand their main components:

1. **Import**
2. **Metadata**
3. **Strings**
4. **Condition**
5. **Rule Name**

Each of these elements plays a specific role in how the rule is written and interpreted.

---

### 1. Import
The `import` statement allows a rule to utilize external modules, enhancing its capabilities. For example, the `pe` module lets YARA analyze Windows PE (Portable Executable) file structures.

**Example:**
```yara
import "pe"
```

Once imported, you can use module-specific functions and data types within the rule's condition section.

---

### 2. Metadata
The `metadata` section provides descriptive information about the rule, such as the author, source, date of creation, and intended purpose.

**Example:**
```yara
rule NetMonitor {
  meta:
    author = "FBI"
    source = "FBI"
    sharing = "TLP:CLEAR"
    status = "RELEASED"
    description = "YARA rule to detect NetMonitor.exe"
    category = "MALWARE"
    creation_date = "2023-05-05"
  strings:
    $rc4key = {11 4b 8c dd 65 74 22 c3}
    $op0 = {c6 [3] 00 00 05 c6 [3] 00 00 07 ...}
  condition:
    uint16(0) == 0x5A4D and filesize < 50000 and any of them
}
```

---

### 3. Strings
Strings are fundamental to identifying malicious patterns in files. They can be defined as:
- **Text strings**
- **Hexadecimal byte sequences**
- **Regular expressions**

**String Extraction Tool:**
Use `strings.exe` from the Sysinternals Suite to extract readable strings from binary files.

**Example:**
```bash
strings.exe "C:\Users\Desktop\Analysis\Examples\ABC"
```

**YARA Strings Example:**
```yara
rule ExampleRule {
  strings:
    $a = /RegCreateKeyA|CreatePipe|KERNEL32\.dll/
  condition:
    $a
}
```
In this example:

$a is a regular expression that searches for any of the terms "RegCreateKeyA", "CreatePipe", or "KERNEL32.dll".
The rule will be considered a match if the string pattern $a (as defined above) is found within the analyzed file or data. In simpler terms, if you run a file through YARA with this rule, YARA will flag the file as a match to "ExampleRule" if it contains any of the strings "RegCreateKeyA", "CreatePipe", or "KERNEL32.dll".

The importance of the strings section cannot be overstated. The precision and accuracy of these strings determine the rule's efficacy. Well-defined strings can drastically reduce false positives and false negatives, making the rule a potent tool in malware detection and threat hunting.

---

### 4. Condition
The `condition` section contains the logic that must be satisfied for the rule to trigger.

**Example Rule from CISA:**
```yara
rule HighEntropy {
  meta:
    description = "entropy rule"
  condition:
    math.entropy(0, filesize) >= 7.0
}
```

**Explanation:**
- `math.entropy(0, filesize)`: Calculates the entropy of the file.
- `>= 7.0`: A high entropy suggests encryption or compression, often used by malware.

---

### 5. Rule Name
The `rule` name identifies the rule. It should be meaningful and related to what the rule is detecting.

**Example:**
```yara
rule HighEntropy
{
    meta:
        description = "entropy rule"

    condition:
        math.entropy(0, filesize) >= 7.0
}
```

In this example, `HighEntropy` clearly indicates that the rule targets files with high entropy.

---

# 2- The Structure of a YARA Rule

YARA rules provide a way for researchers to identify patterns within files, making it a powerful tool for malware detection. YARA's proprietary rule-writing language is intuitive yet demands a deep understanding of the desired patterns.

Essential to every YARA command are two arguments:
- the rule file, and
- the target (file, directory, or process ID).

For instance, suppose we aim to apply the rule `threatDetect.yar` on a directory named `suspiciousFiles`. The appropriate command would be:

```bash
yara threatDetect.yar suspiciousFiles
```

Each rule must possess a unique name and a defining condition. 

For instance, in the rule below named `malwarePattern`, the condition checks if a certain string pattern, `maliciousCode`, is present:

```yara
rule malwarePattern {
    strings:
        $codePattern = "maliciousCode"

    condition:
        $codePattern
}
```

Here, `malwarePattern` is the unique name, and the presence of the string `maliciousCode` serves as its defining condition.

---

## What Is an Example of a YARA Rule?

In this instance, we will explore a YARA rule aimed at identifying malicious actions associated with the MOVEit Transfer Zero Day Vulnerability.

This rule has been shared by CISA in their CL0P Ransomware Gang Cybersecurity Advisory. 

> 🔗 [CISA Advisory Alert AA23-158A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a)

```yara
rule CISA_10450442_01 : LEMURLOOT webshell communicates_with_c2 remote_access
{
  meta:
      Author = "CISA Code & Media Analysis"
      Incident = "10450442"
      Date = "2023-06-07"
      Last_Modified = "20230609_1200"
      Actor = "n/a"
      Family = "LEMURLOOT"
      Capabilities = "communicates-with-c2"
      Malware_Type = "webshell"
      Tool_Type = "remote-access"
      Description = "Detects ASPX webshell samples"
      SHA256_1 = "3a977446ed70b02864ef8cfa3135d8b134c93ef868a4cc0aa5d3c2a74545725b"

  strings:
      $s1 = { 4d 4f 56 45 69 74 2e 44 4d 5a }  // "MOVEit.DMZ"
      $s2 = { 25 40 20 50 61 67 65 20 4c 61 6e 67 75 61 67 65 3d }  // ASPX page language declaration
      $s3 = { 4d 79 53 51 4c }  // "MySQL"
      $s4 = { 41 7a 75 72 65 }  // "Azure"
      $s5 = { 58 2d 73 69 4c 6f 63 6b 2d }  // "X-siLock-"

  condition:
      all of them
}
```

### Rule Breakdown

#### `meta:`
- **Author**: Creator or maintainer of the rule (e.g., "CISA Code & Media Analysis").
- **Incident**: Incident number associated with the threat.
- **Date** & **Last_Modified**: Track creation and modification times.
- **Actor**: Threat actor ("n/a" if unknown).
- **Family**: Malware family targeted ("LEMURLOOT").
- **Capabilities**: Describes what the malware can do (e.g., "communicates-with-c2").
- **Malware_Type**: Type of malware (e.g., "webshell").
- **Tool_Type**: Tool type (e.g., "remote-access").
- **Description**: Summary of what this rule detects.
- **SHA256_1**: A known hash of a malware sample.

#### `strings:`
The strings section contains byte sequences, text, or regular expressions to match against files:
- `$s1`: Looks for the byte pattern corresponding to "MOVEit.DMZ", likely part of the code or a library that the webshell interacts with.
The string "4d 4f 56 45 69 74 2e 44 4d 5a" is a sequence of hexadecimal values. Each pair of characters represents a byte, and each byte can be converted to its ASCII representation to decode the string.

Here's the decoding of our string:

| String Hexadecimals | ASCII Conversion |
|---------------------|------------------|
| 4d                  | M                |
| 4f                  | O                |
| 56                  | V                |
| 45                  | E                |
| 69                  | i                |
| 74                  | t                |
| 2e                  | .                |
| 44                  | D                |
| 4d                  | M                |
| 5a                  | Z                |

So, combining all the ASCII characters together gives you the string "MOVEit.DMZ".


- `$s2`: Looks for the byte pattern which translates to a typical declaration in ASPX files setting the language, possibly indicating an ASPX page.
- `$s3`: Searches for the byte pattern corresponding to "MySQL", hinting that the webshell interacts with MySQL databases.
- `$s4`: Searches for the byte pattern corresponding to "Azure", suggesting that the webshell may have functionalities related to Azure.
- `$s5`: Looks for the byte pattern "X-siLock-", which could be related to a specific HTTP header or parameter the webshell uses for authentication or command execution.

#### `condition:`
- `all of them`: The rule triggers only if **all five strings** are present in a scanned file.
In summary, this YARA rule will trigger if it detects a file (likely an ASPX file given the indicators) that contains all the mentioned strings, suggesting it's an instance of the LEMURLOOT webshell.


---

# 3- Use Cases for YARA
To help you better understand YARA rules, let’s take a look at some use cases:

#### YARA Rules for Malware Detection:
YARA rules can be created to detect specific malware or malware families, whether it’s variants of malware or specific strains of malware.

#### Signature-based YARA:
YARA rules can be created to detect malware-based hashes, specific strings, phrases, or code snippets, including registry keys and even malware based on byte sequences.

#### YARA Rules for File Types:
YARA rules can also apply to file types or extensions like .pdf or .exe. This allows you to find specific malware files that are already known.

#### YARA Rules and Threat Intelligence:
YARA rules can be integrated with threat intelligence tools to create rules based on the latest threat data. This helps in identifying new or emerging threats.

#### Ransomware Detection with YARA Rules:
According to Veeam’s 2024 Cybersecurity Trends Report, the number of ransomware victims surged by 50% year-over-year in 2023. Top data protection companies, such as Veeam, offer built-in signature-based backup malware detection scanners to maintain health and recoverability. Other features include backup file size analyzers, anomaly detection, and indicators of compromise (IOC) tool detection.

However, for specific rules that search for specific malware or patterns that can execute a ransomware attack, a YARA rule is the best option to find malicious software and alert administrators.

One example of a YARA rule that can prevent ransomware is CTBLocker ransomware, which can be found by looking for klospad.pdb. A YARA rule will scan for those files and alert you immediately if they are found within the backup or at the time of recovery.

---

# 4- YARA Modules 

YARA’s modular design allows you to extend its core functionality using built-in modules. These modules provide specialized functions and access to structured data for more complex rule creation and analysis. Below are some of the most widely used YARA modules:

---

## PE Module

### Purpose:
The PE module is used for analyzing Windows Portable Executable (PE) files such as `.exe` and `.dll`. It allows inspection of headers, sections, imports, exports, and other PE-specific attributes.

### Common Fields & Functions:
- `pe.is_pe`: Checks if a file is a valid PE file.
- `pe.number_of_sections`: Number of sections in the PE file.
- `pe.entry_point`: The address of the entry point.
- `pe.sections[i].name`: Name of the i-th section.
- `pe.sections[i].entropy`: Entropy value of the i-th section.

### Example:
```yara
import "pe"

rule suspicious_entropy {
  condition:
    pe.is_pe and pe.sections[1].entropy > 7.0
}
```

---

## ELF Module

### Purpose:
Used to inspect ELF (Executable and Linkable Format) files common in Unix/Linux environments.

### Common Fields:
- `elf.machine`: Architecture type (e.g., `elf.EM_X86_64`).
- `elf.section_names`: Access section names.

### Example:
```yara
import "elf"

rule detect_x64_elf {
  condition:
    elf.machine == elf.EM_X86_64
}
```

---

## Hash Module

### Purpose:
Provides hashing functions (MD5, SHA1, SHA256) for content comparison or fingerprinting.

### Functions:
- `hash.md5(offset, size)`
- `hash.sha1(offset, size)`
- `hash.sha256(offset, size)`

### Example:
```yara
import "hash"

rule md5_match_example {
  condition:
    hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"
}
```

---

## Magic Module

### Purpose:
Uses libmagic to detect file types and MIME types.

### Fields:
- `magic.mime_type`
- `magic.description`

### Example:
```yara
import "magic"

rule detect_pdf_file {
  condition:
    magic.mime_type == "application/pdf"
}
```

---

## Cuckoo Module

### Purpose:
Interacts with behavioral analysis results from the Cuckoo Sandbox.

### Fields:
- `cuckoo.network.http.url`
- `cuckoo.behavior.calls[*].api`

### Example:
```yara
import "cuckoo"

rule network_indicator {
  condition:
    cuckoo.network.http.url contains "suspicious"
}
```

---

## Math Module

### Purpose:
Provides mathematical functions like entropy calculations.

### Functions:
- `math.entropy(offset, size)`

### Example:
```yara
import "math"

rule high_entropy_file {
  condition:
    math.entropy(0, filesize) > 7.5
}
```

---

## Time Module

### Purpose:
Allows access to file timestamp data, useful for detecting anomalous or forged timestamps.

### Functions:
- `time.now()`: Current system time.
- `time.seconds_since(epoch)`: Seconds since a specified epoch.

---
# 5- Yara Tools

YARA tools are utilities used to work with YARA rules for detecting and classifying malware. These tools assist in scanning files, directories, or memory dumps based on user-defined YARA rules. There are plenty of [GitHub resources](https://github.com/InQuest/awesome-yara) and open-source tools (along with commercial products) that can be utilized to leverage Yara in hunt operations and/or incident response engagements.

### Yara Generate
Automates rule creation by generating rules from a collection of files. Useful for detecting common malware patterns across multiple files.
Example command:

`python yara_generate.py -d <directory> -o output.yar`

### Loki - Simple IOC and YARA Scanner
LOKI is a free open-source IOC (Indicator of Compromise) scanner created/written by Florian Roth.

Detection is based on four detection methods:
``` 
1. File Name IOC
   Regex match on full file path/name

2. Yara Rule Check
   Yara signature match on file data and process memory

3. Hash Check
   Compares known malicious hashes (MD5, SHA1, SHA256) with scanned files
   
4. C2 Back Connect Check
   Compares process connection endpoints with C2 IOCs (new since version v.10)
```
Example command to scan a file:

`python Loki.py -p <file_directory>`

Use Case: Ideal for detecting threats that do not leave traces on disk (fileless malware) or for scanning the runtime memory of a compromised system.

for more details, go to the page source: [Loki](https://github.com/Neo23x0/Loki/blob/master/README.md) 

### THOR (superhero named programs for a superhero blue teamer)
THOR Lite is Florian’s newest multi-platform IOC AND YARA scanner. There are precompiled versions for Windows, Linux, and macOS. A nice feature with THOR Lite is its scan throttling to limit exhausting CPU resources. For more information and/or to download the binary, start [here](https://www.nextron-systems.com/thor-lite/). You need to subscribe to their mailing list to obtain a copy of the binary. Note that THOR is geared towards corporate customers. THOR Lite is the free version.

### FENRIR (naming convention still mythical themed)
This is the 3rd tool created by Neo23x0 (Florian Roth). The updated version was created to address the issue from its predecessors, where requirements must be met for them to function. Fenrir is a bash script; it will run on any system capable of running bash (nowadays even Windows).

### YAYA (Yet Another Yara Automaton)
YAYA was created by the EFF (Electronic Frontier Foundation) and released in September 2020. Based on their website, “YAYA is a new open-source tool to help researchers manage multiple YARA rule repositories. YAYA starts by importing a set of high-quality YARA rules and then lets researchers add their own rules, disable specific rulesets, and run scans of files.”

Note: Currently, YAYA will only run on Linux systems.

---
# 6- Loki Scanner
As a security analyst, you may need to research various threat intelligence reports, blog postings, etc. and gather information on the latest tactics and techniques used in the wild, past or present. Typically in these readings, IOCs (hashes, IP addresses, domain names, etc.) will be shared so rules can be created to detect these threats in your environment, along with Yara rules. On the flip side, you might find yourself in a situation where you’ve encountered something unknown, that your security stack of tools can’t/didn’t detect. Using tools such as Loki, you will need to add your own rules based on your threat intelligence gathers or findings from an incident response engagement (forensics).

### Scanning Files for Malware
A directory containing two suspicious files (file1 and file2) is scanned using Loki.
The command used:

`python Loki.py -p suspicious_files`

The scan result shows that file1 is malicious and flagged as a web shell.

### Inspecting the Yara Rule Match

The detection output contains:
- Matched Rule Name
- Matched Strings
- Reason for Flagging the File
The flagged file is classified as a web shell, which could be used for unauthorized access.

# 7- Creating a Custom Yara Rule

- Using **Yara Generate**, a custom rule is created to detect the same malware in future scans.
- The rule is stored in a .yar file and tested against other files using:
`yara custom_rule.yar <directory>`

# 8- Using Valhalla for Threat Intelligence
Valhalla is a commercial service developed by Nextron Systems (the same folks behind THOR and Loki) that provides High-quality, curated YARA rules for threat detection.
Think of Valhalla as a threat intelligence feed made of constantly updated and highly effective YARA rules for detecting APTs, malware families, and suspicious files.

### 1- Searching for a Malware Hash
- A file’s SHA256 hash is checked in Valhalla to see if it has been flagged.
- If found, it may be linked to a known **APT** attack.

### 2- Inspecting VirusTotal Reports
The malware hash is submitted to VirusTotal.
The report shows:
- Antivirus detections of the file.
- File classification (Malicious, Suspicious, or Benign).
- Known variants of the malware.


## Resources

- [YARA Official Documentation](https://yara.readthedocs.io/en/stable/)
- [Cuckoo Sandbox](https://cuckoosandbox.org/)
- [VirusTotal YARA Module Reference](https://developers.virustotal.com/reference/yara-rules)
- [Tryhackme](https://tryhackme.com/room/yara)
- http://motasem-notes.net/yara-rules-explained-complete-tutorial-tryhackme-yara/




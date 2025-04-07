# TryHackMe Yara Room

Room URL: 

Due to the poor explanation of the Yara tool in this room, I used external resources.

# Understanding YARA Rules

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
In this rule, `$a` searches for specific function names or DLL references indicative of malicious behavior.

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

# The Structure of a YARA Rule

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
- `$s1`: Byte pattern for "MOVEit.DMZ" — possibly part of the code/library.
- `$s2`: ASPX language declaration indicator.
- `$s3`: Refers to "MySQL" interactions.
- `$s4`: Indicates potential "Azure" usage.
- `$s5`: A custom header or marker (e.g., for authentication or command execution).

#### `condition:`
- `all of them`: The rule triggers only if **all five strings** are present in a scanned file.






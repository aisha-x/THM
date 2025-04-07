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




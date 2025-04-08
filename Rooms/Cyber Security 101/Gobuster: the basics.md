# Gobuster: the Basics TryHackme Walkthrough

Room URL: https://tryhackme.com/r/room/gobusterthebasics

---
# Gobuster: Tool Overview & Use Cases

## 1. Gobuster: Introduction

Gobuster is a **command-line brute-force tool** written in Go. It is widely used by penetration testers for:

- Discovering hidden **directories/files** on web servers.
- Finding **subdomains** of a target domain.
- Enumerating **virtual hosts** on a server.

It supports multiple modes:
- `dir` – Directory/file brute-force
- `dns` – Subdomain enumeration
- `vhost` – Virtual host brute-force
- `s3` – S3 bucket enumeration (less commonly used)

> 🔗 **Official Repo**: [OJ/gobuster](https://github.com/OJ/gobuster)

---

## 2. Use Case: Directory and File Enumeration

### Mode: `dir`

Brute-forces directories and files on a web server using a wordlist.

### ✅ Common Flags:
| Flag         | Description                           |
|--------------|---------------------------------------|
| `-u`         | Target URL                            |
| `-w`         | Path to the wordlist                  |
| `-x`         | File extensions to try (comma-separated) |
| `-t`         | Number of concurrent threads (default: 10) |
| `-e`         | Perform expanded checks (e.g., for redirects) |
| `-o`         | Output results to a file              |

### Example:

```bash
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 20
```

### 🔍 Output Explanation:

```bash
===============================================================
Gobuster v3.5
===============================================================
/index.html           (Status: 200)
/admin.php            (Status: 403)
/backup               (Status: 301)
/robots.txt           (Status: 200)
===============================================================
```

**Question 1: Which flag do we have to add to our command to skip the TLS verification? Enter the long flag notation.**

Answer: ***— no-tls-validation***

**Question 2: Enumerate the directories of www.offensivetools.thm. Which directory catches your attention?.**

`gobuster -u "http://www.offensivetools.thm" -w /usr/share/wordlists/disbuster/directory-list-2.3-medium.txt -t 64 -r`

Answer: ***secret***

**Question 3: Continue enumerating the directory found in question 2. You will find an interesting file there with a .js extension. What is the flag found in this file?.**

`gobuster -u "http://www.offensivetools.thm/secret" -w /usr/share/wordlists/disbuster/directory-list-2.3-medium.txt -t 64 -x .js`

we found `flag.js` file, fetch the file using curl command `curl http://www.offensivetools.thm/secret/flag.js`

Answer: ***THM{ReconWasASuccess}***

---
## 3. Use Case: Subdomain Enumeration

### Mode: `dns`

Brute-forces subdomains using a given wordlist.

### Common Flags:
| Flag         | Description                        |
|--------------|------------------------------------|
| `-d`         | Target domain                      |
| `-w`         | Subdomain wordlist                 |
| `-t`         | Threads (default: 10)              |
| `--wildcard` | Check for DNS wildcard response    |

### Example:

```bash
gobuster dns -d example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
```
### 🔍 Output Explanation:

```
Found: dev.example.com
Found: mail.example.com
Found: staging.example.com
```

- These are valid subdomains that resolved.
- You can investigate each with `nslookup`, `dig`, or `httpx`.

**Question 1: Apart from the dns keyword and the -w flag, which shorthand flag is required for the command to work?**

Answer: ***-d***

**Question 2: Use the commands learned in this task, how many subdomains are configured for the offensivetools.thm domain?**

`gobuster dns -d offensivetools.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt `

Answer: ***4***

---

## 4. Use Case: Virtual Host (VHost) Enumeration

### Mode: `vhost`

Discovers virtual hosts on the same IP by modifying the `Host` HTTP header. A VHost is not a user, it’s a domain name or hostname that a web server uses to serve different websites on the same IP address.

Let’s say a single server has the IP address 192.168.1.10. That server might be hosting multiple websites:

- www.example.com
- admin.example.com
- test.example.com

These are virtual hosts — each one can show a completely different website, but they all go to the same server IP. The web server (like Apache or Nginx) uses the Host header in the HTTP request to decide which "website" to show.

### Common Flags:
| Flag         | Description                        |
|--------------|------------------------------------|
| `-u`         | Base URL (usually with IP)         |
| `-w`         | Wordlist of virtual hostnames      |
| `-t`         | Threads (default: 10)              |
| `-H`         | Custom HTTP headers (optional)     |
| `--append-domain` | Appends domain to wordlist entries |

### Example:

```bash
gobuster vhost -u http://10.10.10.10 -w /usr/share/wordlists/seclists/Discovery/DNS/vhost-wordlist.txt --append-domain -t 30
```

### Output Explanation:

```bash
Found: admin.example.com (Status: 200)
Found: internal.example.com (Status: 403)
```

- Virtual hosts were identified and resolved correctly.
- These may lead to separate hosted applications or admin panels.

**Question 1: Use the commands learned in this task to answer the following question: How many vhosts on the offensivetools.thm domain reply with a status code 200?**

`gobuster vhost -u "http://<target-machin>" --domain offensivetools.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 100 | grep "Status: 200"`

Answer: ***4***

---

## 🧪 Summary Table

| Mode     | Description                  | Key Command Example |
|----------|------------------------------|---------------------|
| `dir`    | Brute-force directories/files | `gobuster dir -u http://site -w wordlist` |
| `dns`    | Subdomain discovery           | `gobuster dns -d domain -w wordlist` |
| `vhost`  | Virtual host brute-force      | `gobuster vhost -u http://IP -w wordlist` |

---

## 📚 Resources

- [Gobuster GitHub Repo](https://github.com/OJ/gobuster)
- [TryHackMe - Gobuster Room](https://tryhackme.com)
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)
- [FreeCodeCamp Gobuster Tutorial](https://www.freecodecamp.org/news/gobuster-tutorial-find-hidden-directories-sub-domains-and-s3-buckets/)
- [Abricto Security Blog](https://abrictosecurity.com/gobuster-directory-enumerator-cheat-sheet/)



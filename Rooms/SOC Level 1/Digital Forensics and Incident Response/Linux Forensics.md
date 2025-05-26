# TryHackMe: Linux Forensics Room Summary


Room URL: https://tryhackme.com/room/linuxforensics


---
# Linux Forensics

Linux forensics involves examining Linux systems to identify, recover, and analyze digital evidence. It focuses on:

- File systems (ext3/ext4)
- System & user logs
- Process and network data
- Deleted files and hidden artifacts
- Disk and memory imaging

Tools like Autopsy, TSK, Volatility, and native Linux commands (`ps`, `netstat`, `journalctl`) are essential in this domain.


---
# TASK-3: OS and account information
In the case of Windows, *the Windows Registry* contains information about the Windows machine. For a Linux system, everything is stored in a *file*. Therefore, to identify forensic artifacts, we will need to know the locations of these files and how to read them.

## 1. OS and account information

- the OS release information strored in `/etc/os-release` file
```bash
cat /etc/os-release 
```
![Screenshot 2025-05-26 125936](https://github.com/user-attachments/assets/a77a3a72-334b-4fd1-a587-04e9336f439b)


## 2. User accounts
- The `/etc/passwd` file contains information about the user accounts that exist on a Linux system.
- The output contains 7 colon-separated fields, describing username, password information, user id (uid), group id (gid), description, home directory information, and the default shell that executes when the user logs in.

**Example**

```bash
cat /etc/passwd| column -t -s :
```
![image](https://github.com/user-attachments/assets/d103b44c-408e-49b1-b434-070df4ea2964)


## 3. Group Information
- The `/etc/group` file contains information about the different user groups present on the hos

**Example**

```bash
cat /etc/group | column -t -s :

```
![image](https://github.com/user-attachments/assets/d6b4f5d0-d5cf-448b-8773-97484e7b1bb4)


## 4. Sudoers List
- A Linux host allows only those users to elevate privileges to `sudo`, which are present in the Sudoers list
- This list is stored in the file `/etc/sudoers` and can be read using the `cat` utility
```bash
sudo cat /etc/sudoers
```
![Screenshot 2025-05-26 130349](https://github.com/user-attachments/assets/39f92352-0d94-4e42-a5be-405e0a460222)

## 5. Login information

- `/var/log/btmp` – This file contains information about failed login attemps. Use the `last` command to view the btmp file.
- `/var/log/wtmp` or `/var/log/utmp` – Contains login records. Using wtmp you can find out who is logged into the system. who command uses this file to display the information.

**Example**

```bash
ls /var/log/
```
![Screenshot 2025-05-26 130704](https://github.com/user-attachments/assets/a42ab2c9-7138-4dd3-9678-f3c1fcadbf59)

```bash
sudo last -f /var/log/wtmp
```
- [`last`](https://www.cyberciti.biz/faq/linux-unix-last-command-examples/) -> show a listing of last logged in users
- `-f` -> Tell last to use a specific file instead of /var/log/wtmp

![Screenshot 2025-05-26 131654](https://github.com/user-attachments/assets/969e1fa7-c8f7-4e91-9292-d082c8429e6e)


## 6. Authentication logs
- `/var/log/auth.log` – Contains system authorization information, including user logins and authentication machinsm that were used.
- Common types of events you'll find in auth.log: Login attempts, sudo usage, SSH access, su command usage, System authentication,Key authentication, ans Service authentication	

**Example**

```bash
cat /var/log/auth.log | grep "ubuntu"
```
![Screenshot 2025-05-26 132432](https://github.com/user-attachments/assets/c8a6383d-9cfa-42ba-b64b-3d3ae999f0cf)


look at the last four command, the `auth.log`, loged the sudo commands I typed in the Ubuntu user.


---
# TASK-4: System Configuration
Once we have identified the OS and account information, we can start looking into the system configuration of the host.


| Configuration Area         | File/Command                        | Description |
|----------------------------|-------------------------------------|-------------|
| **Hostname**               | `/etc/hostname`                    | Stores the system's hostname. |
| **Timezone**               | `/etc/timezone`                    | Contains the configured timezone of the system. |
| **Network Interfaces**     | `/etc/network/interfaces`          | Defines the system's network interface configuration (mainly used in Debian-based systems). |
| **Active Network Connections** | `netstat` or `ss`                   | Displays active network connections, listening ports, and related stats. |
| **Running Processes**      | `ps aux` or `top`                  | Lists current running processes and system resource usage. |
| **DNS Resolution**         | `/etc/hosts`, `/etc/resolv.conf`  | `/etc/hosts` maps IP addresses to hostnames. `/etc/resolv.conf` defines DNS servers. |
| **Mounted File Systems**   | `mount`, `/etc/fstab`              | Shows mounted drives and boot-time mount configuration. |
| **Systemd Services**       | `systemctl list-units --type=service` | Lists all system services and their status. |
| **OS Release Info**        | `/etc/os-release`                  | Contains the distribution-specific release information. |
| **Logged-In Users**        | `who`, `w`                         | Displays users currently logged into the system. |
| **Last Boot Time**         | `uptime`, `who -b`                 | Shows system uptime and last reboot time. |
| **User Accounts**          | `/etc/passwd`, `/etc/shadow`      | Contains user info and hashed passwords (shadow file is root-only). |
| **System Logs**            | `/var/log/syslog`, `/var/log/auth.log` | Stores general and authentication-related system logs. |


---
# TASK-5: Persistence mechanisms
Knowing the environment we are investigating, we can then move on to finding out what persistence mechanisms exist on the Linux host under investigation. Persistence mechanisms are ways a program can survive after a system reboot. This helps malware authors retain their access to a system even if the system is rebooted

## 1. Cron jobs
- Cron jobs are commands that run periodically after a set amount of time. A Linux host maintains a list of Cron jobs in a file located at `/etc/crontab`

```bash
ubuntu@Linux4n6:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

```

## 2. Service startup
- services can be set up in Linux that will start and run in the background after every system boot. A list of services can be found in the `/etc/init.d` directory.

![Screenshot 2025-05-26 142822](https://github.com/user-attachments/assets/3558486c-8941-4feb-a1dc-e282bb4731af)



## 3. `.bashrc` 

- The `.bashrc` file is a shell script that Bash runs whenever a new terminal session is started in **interactive mode** (like when opening a terminal window).

**Purpose**

The `.bashrc` file is used to configure **user-specific shell behavior**, such as:

| Feature                 | Example                                | Description                                        |
|------------------------|----------------------------------------|----------------------------------------------------|
|  Aliases             | `alias ll='ls -la'`                    | Shortcut for long or frequent commands             |
|  Environment Variables| `export PATH=$PATH:/custom/bin`       | Add custom paths or variables                      |
|  Prompt Customization| `PS1='\u@\h:\w\$ '`                    | Customize the appearance of the shell prompt       |
|  Shell Options       | `shopt -s histappend`                  | Configure shell behavior                           |
|  Startup Scripts      | `source ~/.custom_script.sh`          | Run scripts or commands when shell starts          |


**Location**
- The file is located in the user's home directory:

**Use Cases in Forensics**
If you're analyzing a compromised machine:
- Check `.bashrc` for malicious persistence mechanisms (e.g.,` nc -lvp 4444` or reverse shells).
- Attackers may add commands here to maintain access or steal information.


---
# TASK-6: Evidence of Execution

Knowing what programs have been executed on a host is one of the main purposes of performing forensic analysis. On a Linux host, we can find the evidence of execution from the following sources.

## 1. Sudo execution history
- All the commands that are run on a Linux host using sudo are stored in the auth log.
- location: `/var/log/auth.log`

## 2. Bash history
- Any commands other than the ones run using `sudo` are stored in the bash history
- Every user's bash history is stored separately in that user's home folder.
- It is important to examine the bash history from the root user as well

![Screenshot 2025-05-26 151452](https://github.com/user-attachments/assets/a3b6ab70-aec7-47b4-8d6d-018686fa874f)


## 3. Files accessed using vim
- The `Vim` text editor stores logs for opened files in `Vim` in the file named `.viminfo` in the home directory.
- This file contains command line history, search string history, Expression History, Input Line History, Debug Line History, etc

![Screenshot 2025-05-26 150332](https://github.com/user-attachments/assets/c0d70ca9-de59-4ca1-b2c8-b83715864082)


---
# TASK-7: Log files
One of the most important sources of information on the activity on a Linux host is the log files. These log files maintain a history of activity performed on the host and the amount of logging depends on the logging level defined on the system.Let's take a look at some of the important log sources. Logs are generally found in the `/var/log` directory.

## 1. Syslog
- he syslog is a standard logging system used to collect, store, and manage log messages from the kernel, system services, applications, and daemons.
- `syslog` refers both to:
   - A protocol for sending log messages (RFC 5424),
   - And to the system logging service on Unix/Linux.
- It centralizes messages from: The kernel, System components (e.g., `cron`, `sshd`, `sudo`), and Applications
- location: `/var/log/syslog`

![Screenshot 2025-05-26 153323](https://github.com/user-attachments/assets/c47b5c56-1cce-47bc-98a2-c9c027ddf297)

The above terminal shows the system time, system name, the process that sent the log [the process id], and the details of the log. We can see a couple of cron jobs being run here in the logs above, apart from some other activity. We can see an asterisk(*) after the syslog. This is to include rotated logs as well. With the passage of time, the Linux machine rotates older logs into files such as syslog.1, syslog.2 etc, so that the syslog file doesn't become too big. In order to search through all of the syslogs, we use the asterisk(*) wildcard.

## 2. Auth logs
- The auth logs contain information about users and authentication-related logs
- location: `/var/log/auth.log`

## 3. Third-party logs
- Similar to the syslog and authentication logs, the `/var/log/` directory contains logs for third-party applications such as webserver, database, or file share server logs.
- location: `/var/log/`

![Screenshot 2025-05-26 153740](https://github.com/user-attachments/assets/b7c74a7a-3973-4dbe-9c2b-df524799521a)



---
# Linux Forensics Cheatsheet

- *[Linux Forensics Cheatsheet](https://blog.michweb.de/wp-content/uploads/2024/03/Linux-Forensics-Cheatsheet.pdf)*

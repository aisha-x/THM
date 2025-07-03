# Task-16: Under Construction

the goal is to exploit a **boot-to-root** machine and gain initial access then privilege escalate. 

## Enumeration
Ports found: 80, 22

Hidden directories discovered:
- /assets
- /keys

Found an SSH private key under the `/keys` directory.

## Getting a Shell

Used the discovered private key to identify the username and establish an SSH session:

```bash
ssh -i id_rsa dev@<IP>
```

## Privilege Escalation

Referred to this blog for escalation techniques:

https://www.strongdm.com/blog/linux-privilege-escalation

Used Misconfigured Sudo Rights to check what commands the current user can run as root:
```bash
sudo -l
```

Discovered that the user has permission to run the Vim editor as root:
```bash
sudo vim
```

Escalated privileges to root by executing a shell from within Vim:

```vi
:!bash
```
Successfully obtained a root shell

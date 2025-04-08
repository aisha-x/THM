# Hydra TryHackme Walkthrough

Room URL: https://tryhackme.com/room/hydra

---
# Introduction

### What is Hydra?
Hydra is a brute force online password cracking program, a quick system login password “hacking” tool.

Hydra can run through a list and “brute force” some authentication services. Imagine trying to manually guess someone’s password on a particular service (SSH, Web Application Form, FTP or SNMP) - we can use Hydra to run through a password list and speed this process up for us, determining the correct password.

According to its [official repository](https://github.com/vanhauser-thc/thc-hydra), Hydra supports, i.e., has the ability to brute force the following protocols: “Asterisk, AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird, FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST, HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD, HTTPS-POST, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MEMCACHED, MONGODB, MS-SQL, MYSQL, NCP, NNTP, Oracle Listener, Oracle SID, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, Radmin, RDP, Rexec, Rlogin, Rsh, RTSP, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, TeamSpeak (TS2), Telnet, VMware-Auth, VNC and XMPP.”

For more information on the options of each protocol in Hydra, you can check the [Kali Hydra tool page](https://en.kali.tools/?p=220).

This shows the importance of using a strong password; if your password is common, doesn’t contain special characters and is not above eight characters, it will be prone to be guessed. A one-hundred-million-password list contains common passwords, so when an out-of-the-box application uses an easy password to log in, change it from the default! CCTV cameras and web frameworks often use admin:password as the default login credentials, which is obviously not strong enough.

### Installing Hydra

 installing Hydra on an Ubuntu or Fedora system: `apt install hydra` or `dnf install hydra`

 Furthermore, you can download it from its official [THC-Hydra repository](https://github.com/vanhauser-thc/thc-hydra).
---
 # Using Hydra

### Hydra Commands
The options we pass into Hydra depend on which service (protocol) we’re attacking.

### FTP

`hydra -l user -P passlist.txt ftp://MACHINE_IP`

### SSH

`hydra -l <username> -P <full path to pass> MACHINE_IP -t 4 ssh`

- `-l`: specifies the (SSH) username for login
- `-P`: indicates a list of passwords
- `-t`:	sets the number of threads to spawn

For example, `hydra -l root -P passwords.txt MACHINE_IP -t 4 ssh` will run with the following arguments:

- Hydra will use `root` as the username for `ssh`
- It will try the passwords in the `passwords.txt` file
- There will be four threads running in parallel as indicated by `-t 4`


### Post Web Form
We can use Hydra to brute force web forms too. You must know which type of request it is making; GET or POST methods are commonly used. You can use your browser’s network tab (in developer tools) to see the request types or view the source code.

`sudo hydra <username> <wordlist> MACHINE_IP http-post-form "<path>:<login_credentials>:<invalid_response>"`

| Option           | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `-l`             | The username for (web form) login                                           |
| `-P`             | The password list to use                                                    |
| `http-post-form` | Indicates the form uses HTTP POST method                                    |
| `<path>`         | The login page URL (e.g., `login.php`)                                      |
| `<login_credentials>` | The username and password field values (e.g., `username=^USER^&password=^PASS^`) |
| `<invalid_response>`  | Part of the server response when login fails                           |
| `-V`             | Verbose output for every login attempt                                      |

Below is a more concrete example Hydra command to brute force a POST login form:

`hydra -l <username> -P <wordlist> MACHINE_IP http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V`

- The login page is only `/`, i.e., the main IP address.
- The `username` is the form field where the username is entered
- The specified username(s) will replace `^USER^`
- The `password` is the form field where the password is entered
- The provided passwords will be replacing `^PASS^`
- Finally, `F=incorrect` is a string that appears in the server reply when the login fails

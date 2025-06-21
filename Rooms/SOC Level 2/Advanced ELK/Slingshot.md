# TryHackMe: Slingshot Challenge

Room URL: https://tryhackme.com/room/slingshot


---
# Investigation Report

## Initial Findings

- IP address `10.0.2.15` generated the most traffic and was involved in suspicious activity.
- This IP is the primary focus of the investigation.

---

## Reconnaissance

- The attacker used **Nmap** to scan for open ports and services.
- **Gobuster** was used to enumerate directories.

### Discovered Resources:
- 9 directories were found.
- One of the directories was `/backups/`.
- A login page was discovered, which returned a `401 Unauthorized` status (indicating that valid credentials were needed).

---

## Brute-force and Access

- The attacker attempted brute-forcing the login page using **Hydra**.
- A successful login attempt was observed.
- The credentials were obtained from a Base64-encoded `Authorization` header:
  - Decoded to: `admin:thx1138`.

- After logging in, the attacker changed the user-agent to: `Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0` 


---

## Web Shell Activity

- The attacker uploaded a **PHP web shell**.
- This web shell allowed command execution via the browser.
- Commands were executed via the URL using the `cmd` parameter.
- The last command issued was: `which nc` to check for Netcat (likely in preparation for a reverse shell).

---

## Lateral Movement & Data Access

- Path traversal attempts were observed.
- The attacker accessed: `/etc/phpmyadmin/config-db.php`

which contained database credentials.

- Using these credentials, the attacker accessed the **phpMyAdmin** interface.
- The attacker exported the `customer_credit_cards` database:
- A POST request to `export.php` with `db=customer_credit_cards` was used.

- Later, the attacker **inserted data** into the database (possibly to plant or manipulate records).

---

## Timeline

| Timestamp                  | Activity                                                                 |
|----------------------------|--------------------------------------------------------------------------|
| `Jul 26, 2023 @ 14:27:08`  | Reconnaissance using **Nmap** from IP `10.0.2.15`                        |
| `Jul 26, 2023 @ 14:27:43`  | Directory enumeration using **Gobuster**                                 |
| `Jul 26, 2023 @ 14:27:45`  | Discovered `/backups/` directory                                        |
| `Jul 26, 2023 @ 14:29:04`  | Attempted brute-force using **Hydra**                                   |
| `Jul 26, 2023 @ 14:29:04`  | Successfully logged in using `admin:thx1138`                            |
| `Jul 26, 2023 @ 14:29:35`  | Uploaded a **PHP web shell** to the server                              |
| `Jul 26, 2023 @ 14:31:27`  | Accessed database configuration at `/etc/phpmyadmin/config-db.php`      |
| `Jul 26, 2023 @ 14:33:54`  | Exported sensitive database `customer_credit_cards`                     |
| `Jul 26, 2023 @ 14:34:46`  | Inserted data into the database                                          |

---

##  Vulnerabilities Exploited

| Vulnerability Type           | Description                                                               |
|------------------------------|---------------------------------------------------------------------------|
| **Directory Enumeration**    | Used Gobuster to discover hidden directories                              |
| **Exposed Admin Interface**  | Login page was publicly accessible and brute-forced                        |
| **Weak Credentials**         | Successful login with weak credentials: `admin:thx1138`                   |
| **Web Shell Upload**         | File upload allowed execution of arbitrary PHP code                        |
| **Path Traversal**           | Gained access to config files via traversal                                |
| **Database Exposure**        | Exported database via unprotected phpMyAdmin interface                     |
| **Lack of Segmentation**     | Web server had direct access to the internal database                      |

---


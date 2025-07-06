# tryhackme: Threat Hunting Pivoting Cheat sheet

Room URL: https://tryhackme.com/room/threathuntingpivoting

---

| Tactic              | Hunting Methodology |
|---------------------|---------------------|
| **Discovery**       | Look for executions of built-in tools used for enumerating user and host information. |
|                     | Spot unusual internal network scanning activities. |
|                     | Hunt for unusual processes initiating LDAP queries. |
|                     | Utilise the parent-child relationships of processes to connect associated events. |
| **Privilege Escalation** | Look for unusual SYSTEM account processes spawned by a low-privileged user. |
|                     | Hunt for potential service permission abuses via service binary modification. |
|                     | Utilise the parent-child relationship of processes, including the context of the user who spawned it. |
| **Credential Access** | Hunt for known indicators that are associated with LSASS credential dumping. |
|                     | Monitor events related to domain controller data replication. |
|                     | Seek patterns of numerous failed login attempts to Windows hosts, followed by successful authentication. |
|                     | Observe unusual process creation activities of potentially compromised accounts. |
| **Lateral Movement** | Hunt for unusual process creations made by WmiPrvSE.exe. |
|                     | Look for suspicious successful authentication patterns that may indicate a potential Pass-the-Hash activity. |
|                     | Observe unusual process creation activities after detecting a successful lateral movement attempt. |
|                     | Correlate the source of the lateral movement attempt and investigate how the source was compromised. |

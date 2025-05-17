
# TryHackMe: Osquery: The Basics Room Summary

Room URL: https://tryhackme.com/room/osqueryf8

# What is osqueryi?
osqueryi provides a standalone, interactive shell that transforms your operating system into a relational database. This enables you to write and execute SQL queries to retrieve detailed information about various system components, such as running processes, user accounts, installed software, network connections, and more. It's particularly useful for tasks like system monitoring, incident response, and security analytics.

[osquery](https://osquery.io/)

---
# Creating SQL queries

> Note: Please refer to the Osquery [documentation](https://osquery.readthedocs.io/en/stable/introduction/sql/) for more information regarding SQL and creating queries specific to Osquery. 

## Answer the questions below

### Q1. Using Osquery, how many programs are installed on this host?

```powershell
osquery> select count(*) from programs;
count(*)
----------
19
```
Ans: ***19***

### Q2. Using Osquery, what is the description for the user James?

```powershell
osquery> select username, description from users
    ...> where username='James';
username    description
----------  ---------------
James       Creative Artist
```

Ans: ***Creative Artist***

### Q3. When we run the following search query, what is the full SID of the user with RID '1009'? Query: `select path, key, name from registry where key = 'HKEY_USERS';`

```powershell
osquery> SELECT r.path, r.key, r.name ,u.username
    ...> FROM registry r
    ...> JOIN users u
    ...> ON r.path LIKE '%' || u.uuid || '%'
    ...> WHERE r.key='HKEY_USERS';
path                                                     key         name                                          username
-------------------------------------------------------  ----------  --------------------------------------------  ----------
HKEY_USERS\S-1-5-21-1966530601-3185510712-10604624-1009  HKEY_USERS  S-1-5-21-1966530601-3185510712-10604624-1009  James
HKEY_USERS\S-1-5-21-1966530601-3185510712-10604624-1009  HKEY_USERS  S-1-5-21-1966530601-3185510712-10604624-1009  James
HKEY_USERS\S-1-5-18                                      HKEY_USERS  S-1-5-18                                      SYSTEM
HKEY_USERS\S-1-5-19                                      HKEY_USERS  S-1-5-19                                      LOCAL SERV
HKEY_USERS\S-1-5-20                                      HKEY_USERS  S-1-5-20                                      NETWORK SE
osquery>

```

Ans: ***S-1-5-21-1966530601-3185510712-10604624-1009***

### Q4.When we run the following search query, what is the Internet Explorer browser extension installed on this machine? Query: `select * from ie_extensions;`

```powershell
osquery> select name,path from ie_extensions;
name                       path
-------------------------  -------------------------------
Microsoft Url Search Hook  C:\Windows\System32\ieframe.dll
```

Ans: ***C:\Windows\System32\ieframe.dll***

### Q5. After running the following query, what is the full name of the program returned? Query: `select name,install_location from programs where name LIKE '%wireshark%';`

```powershell
osquery> select name,install_location from programs where name LIKE '%wireshark%';
name                    install_location
----------------------  --------------------------
Wireshark 3.6.8 64-bit  C:\Program Files\Wireshark

```
Ans: ***Wireshark 3.6.8 64-bit***

---
# Challenge and Conclusion

## Answer the questions below

### Q1. Which table stores the evidence of process execution in Windows OS?

Ans:  ***userassist***

### Q2. One of the users seems to have executed a program to remove traces from the disk; what is the name of that program?



```powershell
osquery> select sid, path from userassist;
+----------------------------------------------+-------------------------------------------------------------------------------------+
| sid                                          | path                                                                                |
+----------------------------------------------+-------------------------------------------------------------------------------------+
| S-1-5-21-1966530601-3185510712-10604624-1009 | C:\Users\James\Documents\DiskWipe.exe                                               |
```

Ans:  ***DiskWipe.exe***

### Q3. Create a search query to identify the VPN installed on this host. What is name of the software?

```powershell
osquery> select path from userassist
    ...> WHERE path LIKE '%VPN%';
+------------------------------------------------------------------------------------+
| path                                                                               |
+------------------------------------------------------------------------------------+
| C:\Users\James\Downloads\tools\ProtonVPN_win_v2.0.6.exe                            |
| {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Proton Technologies\ProtonVPN\ProtonVPN.exe |
+------------------------------------------------------------------------------------+
```
Ans:  ***ProtonVPN.exe***

### Q4. How many services are running on this host?

```powershell
osquery> select count(*) FROM services;
+----------+
| count(*) |
+----------+
| 214      |
+----------+
```
Ans:  ***214***

### Q5. A table autoexec contains the list of executables that are automatically executed on the target machine. There seems to be a batch file that runs automatically. What is the name of that batch file (with the extension .bat)?

```powershell
osquery> select name,path FROM autoexec
    ...> WHERE name LIKE '%.bat%';
+----------------+---------------------------------------------------------------------------------------------+
| name           | path                                                                                        |
+----------------+---------------------------------------------------------------------------------------------+
| batstartup.bat | C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat                 |
| batstartup.bat | C:\Users\James\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat |
+----------------+---------------------------------------------------------------------------------------------+
```
Ans:  ***batstartup.bat***

### Q6. What is the full path of the batch file found in the above question? (Last in the List)

Ans:  ***C:\Users\James\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat***

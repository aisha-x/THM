# TryHackMe: OWASP Walkthrough

Room URL: https://tryhackme.com/room/owasptop102021

---

# 1. Broken Access Control (IDOR Challenge)

**Q1. Look at other users' notes. What is the flag?**

- Change the `id` parameter till we get the flag
- `http://10.10.203.85/note.php?note_id=5`
- ![image](https://github.com/user-attachments/assets/825411d8-d060-4a86-9e45-18cb465b8f5c)
- in `id=5` it says try id number lower than 1 
- `http://10.10.203.85/note.php?note_id=0`
- ![image](https://github.com/user-attachments/assets/2fb6f7b5-f56c-4b86-88d3-fdf9e323f4f2)

Ans: ***flag{fivefourthree}***

---
# 2.Cryptographic Failures (Challenge)

**Q1. What is the name of the mentioned directory?**

- look into the source page of the login page
- ![image](https://github.com/user-attachments/assets/ed01d151-880c-4a36-af08-248a1160dd76)


Ans: ***/assets***

---
**Q2.Navigate to the directory you found in question one. What file stands out as being likely to contain sensitive data?**

- go to the mentioned directory
-![image](https://github.com/user-attachments/assets/c1553b5a-9f25-4f72-b8fd-9041a8b65093)
- click on the webapp.db 
- ![image](https://github.com/user-attachments/assets/f4874008-f8a3-4ab4-bce3-26c9a1a85ae3)

Ans: ***webapp.db***

**Q3.Use the supporting material to access the sensitive data. What is the password hash of the admin user?**

- Download the database using this command `wget http://10.10.226.253:81/assets/webapp.db `
- ![image](https://github.com/user-attachments/assets/9b918958-f546-4860-a8a4-4cd0b9d3bd87)
- Then access the database using this command `sqlite3 webapp.db`
- show tables use, `.tables`
- To see table info use, `PRAGMA table_info(<table_name>);`
- To dump all info stored in that table, use this command. `SELECT * FROM <table_name>;`
- ![image](https://github.com/user-attachments/assets/54cef7d1-fcd9-4351-a484-241764dc2639)


`4413096d9c933359b898b6202288a650|admin|6eea9b7ef19179a06954edd0f6c05ceb|1`

- userID: `4413096d9c933359b898b6202288a650`
- username: `admin`
- password: `6eea9b7ef19179a06954edd0f6c05ceb`
- admin: `1`

Ans: ***6eea9b7ef19179a06954edd0f6c05ceb***

---
**Q4. **
- Use https://crackstation.net/ website to crack the admin hash
- ![image](https://github.com/user-attachments/assets/696399ef-376d-44ae-b91d-141bf35faa06)

Ans: ***qwertyuiop***

---
**Q5.**
- Use the credentials found to login and get the flag
- ![image](https://github.com/user-attachments/assets/990867a1-3060-4b06-9521-69417b8f4209)

Ans: ***THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}***




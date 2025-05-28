# TryHackMe: Disk Analysis & Autopsy Challenge

Room URL: https://tryhackme.com/room/autopsy2ze0

---
# Windows 10 Disk Image



## Answer the questions below



### Q1. What is the MD5 hash of the E01 image?

- Click on the data source node, then view the file Metadata 

![Screenshot 2025-05-27 120924](https://github.com/user-attachments/assets/84f765a5-27ba-48e4-907d-a35a107c1ae8)


Ans: ***3f08c518adb3b5c1359849657a9b2079***

---

### Q2.What is the computer account name?

- Click on the operating System Information from the result node

![Screenshot 2025-05-27 121801](https://github.com/user-attachments/assets/7b334894-9685-438e-9690-4f0d76651614)


Ans: ***DESKTOP-0R59DJ3***

---

### Q3. List all the user accounts. (alphabetical order)

- from the operating system user Accounts, sort the username and copy users whose RID is 1000 and above -> typical custom user account

![Screenshot 2025-05-27 122451](https://github.com/user-attachments/assets/0e202447-549b-42fc-873c-ae348caf2605)


Ans: ***H4S4N,joshwa,keshav,sandhya,shreya,sivapriya,srini,suba***

---

### Q4. Who was the last user to log into the computer?

- from the operating system user Accounts, sort the data accessed from the last accessed account

![Screenshot 2025-05-27 123235](https://github.com/user-attachments/assets/565d9d62-9282-4db0-9b19-e99b0bc8b0ba)


Ans: ***sivapriya***

---

### Q5. What was the IP address of the computer?

- Expand Data Source node 
- /img_HASAN2.E01/vol_vol3/Program Files (x86)/Look@LAN/irunin.ini

![Screenshot 2025-05-27 131724](https://github.com/user-attachments/assets/4ae6301a-373f-495c-866b-bed5eeac848f)

Ans: ***192.168.130.216***

---

### Q6. What was the MAC address of the computer? (XX-XX-XX-XX-XX-XX)

- same location as the previous question

![Screenshot 2025-05-27 132619](https://github.com/user-attachments/assets/baba2446-b14b-4426-8efa-41a50113387c)

Ans: ***08-00-27-2c-c4-b9***

---

### Q7. What is the name of the network card on this computer?

- use keyboard Search option to search for network cards
- `[Nn]etwork.?[Cc]ards?` -> a regular expression search
    - Matches "N" or "n".
    - Matches the literal characters "etwork" -> Network or network
    - . -> any single charachter, ? -> zero or one occurrence.
    - [Cc]ards? -> C or c,  match for card or cards
![Screenshot 2025-05-27 134343](https://github.com/user-attachments/assets/cc0b14c8-c173-4fc0-b0bc-afd89b56d32c)

- the file `MpRtp.dll` returned a reqistry key for network card
- then go to the operation system information and click on the SOFTWARE registy and select Application option
- from there, go to the network card registry -> SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards

![Screenshot 2025-05-27 141809](https://github.com/user-attachments/assets/dde6f055-eef5-4890-9934-765f2a16f12b)



Ans: ***Intel(R) PRO/1000 MT Desktop Adapter***

---

### Q8. What is the name of the network monitoring tool?


- From the Installed Programs node, there is a tool called Look@LAN

![Screenshot 2025-05-27 142133](https://github.com/user-attachments/assets/058212d0-5eb9-4260-9115-23340a7cf806)

- Look@Lan is an advanced network monitor that allows you to monitor your net in few clicks. 
- for more information about this too -> [Source ](https://www.majorgeeks.com/files/details/looklan.html)

Ans: ***Look@LAN***

---

### Q9. A user bookmarked a Google Maps location. What are the coordinates of the location?

- from the web Bookmarks node, select the source titled "Google Maps"

![Screenshot 2025-05-27 142544](https://github.com/user-attachments/assets/f10a68ea-6114-41e3-83ed-65be42047050)


Ans: ***12°52'23.0"N 80°13'25.0"E***

---

### Q10. A user has his full name printed on his desktop wallpaper. What is the user's full name?

- Select the Images/Videos option, expand the users folder, and view each user's image

![Screenshot 2025-05-27 144605](https://github.com/user-attachments/assets/710cdb53-f3ef-4d85-896e-7036fb8cccde)

![Screenshot 2025-05-27 144512](https://github.com/user-attachments/assets/9f591aa0-2ea5-4341-a487-47c70c0f8709)

Ans: ***Anto Joshwa***

---

### Q11. A user had a file on her desktop. It had a flag but she changed the flag using PowerShell. What was the first flag?

- this file `ConsoleHost_history.txt` stores powershell command history -> for more information visti [hack stuff website](https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html#history-file-information)
- use keyborad search option to search for this file 

![Screenshot 2025-05-28 115043](https://github.com/user-attachments/assets/c32f8eb2-fb1a-44b5-8469-4f203a03f059)

Ans: ***flag{HarleyQuinnForQueen}***

---

### Q12. The same user found an exploit to escalate privileges on the computer. What was the message to the device owner?

- This user is Shreya, from the data source node, go to vol_vol3/Users/shreya/Desktop/exploit.ps1

![Screenshot 2025-05-28 115652](https://github.com/user-attachments/assets/3101238f-452b-431e-ac6c-0fd3cc249c7e)


Ans: ***flag{I-hacked-you}***

---

### Q13. 2 hack tools focused on passwords were found in the system. What are the names of these tools? (alphabetical order)

- go to this location -> /vol_vol3/ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/

![Screenshot 2025-05-28 121839](https://github.com/user-attachments/assets/9c6f6578-ed9a-47b4-aa94-5f7fb4d63050)

![Screenshot 2025-05-28 121942](https://github.com/user-attachments/assets/6324f67f-14ac-4e26-8210-78b5ca3394b2)

Ans: ***Lazagne,Mimikatz***

---

### Q14. There is a YARA file on the computer. Inspect the file. What is the name of the author?

- use keyword search option to search for .yar extention of the yara file

![Screenshot 2025-05-28 123846](https://github.com/user-attachments/assets/ef396cef-a739-463e-8fb9-73149e7af515)

- the result returned the location of the kiwi_passwords.yar -> C:\Users\H4S4N\Desktop\mimikatz_trunk\kiwi_passwords.yar
- but the file wasnt in the desktop folder it was in the downloads folder

![Screenshot 2025-05-28 125210](https://github.com/user-attachments/assets/4affdca7-3d88-4c33-b6a1-f303d62dbd67)


Ans: ***Benjamin DELPY (gentilkiwi)***

---

### Q15. One of the users wanted to exploit a domain controller with an MS-NRPC based exploit. What is the filename of the archive that you found? (include the spaces in your answer) 

- [MS-NRPC exploit](https://www.crowdstrike.com/en-us/blog/cve-2020-1472-zerologon-security-advisory/)
- Use the keyword search option to search for the exploit name "Zerologon "

![Screenshot 2025-05-28 130029](https://github.com/user-attachments/assets/1cca3425-4f67-497e-8f8f-9fa1e25c2b1a)


Ans: ***2.2.0 20200918 Zerologon encrypted.zip***

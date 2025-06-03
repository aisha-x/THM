# TryHackMe: Unattended Challenge



Room URL: https://tryhackme.com/room/unattended


---
# Introduction

Welcome to the team, kid. I have something for you to get your feet wet.
Our client has a newly hired employee who saw a suspicious-looking janitor exiting his office as he was about to return from lunch.
I want you to investigate if there was user activity while the user was away between 12:05 PM to 12:45 PM on the 19th of November 2022. If there are, figure out what files were accessed and exfiltrated externally.

You'll be accessing a live system, but use the disk image already exported to the C:\Users\THM-RFedora\Desktop\kape-results\C directory for your investigation. The link to the tools that you'll need is in C:\Users\THM-RFedora\Desktop\tools 

Finally, I want to remind you that you signed an NDA, so avoid viewing any files classified as top secret. I don't want us to get into trouble.

[Windows Forensics Cheat sheet](https://assets.tryhackme.com/cheatsheets/Windows%20Forensics%20Cheatsheet.pdf)


---
# 1. Snooping Around
Initial investigations reveal that someone accessed the user's computer during the previously specified timeframe.

Whoever this someone is, it is evident they already know what to search for. Hmm. Curious.

### Q1. What file type was searched for using the search bar in Windows Explorer?

- If we inspect the Windows cheat sheet, there is a registry path that saves `Windows Explorer Address/Search Bars`
- **location:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\TypedPaths` 
- use the **Registry Explorer** tool and from File select **load haive**
- Load the N hive from this location -> `C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\NTUSER.DAT`
- The` NTUSER.DAT` file is a Windows registry file that contains a user's profile-specific configuration and settings
- From the Registry Explorer, I first visited this location -> `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\TypedPaths`, but the last write timestamp does not match with the investigation 
- so I visited the other location located -> `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\WordWheelQuery`

![Screenshot 2025-06-02 220150](https://github.com/user-attachments/assets/46b9bfcc-3068-4698-bd59-64667742d7e1)

- As you can see, the last write timestamp does match the suspicious user activity. Now, right-click on the data value of the first result and click on the **Data Interpreter**

![Screenshot 2025-06-02 221205](https://github.com/user-attachments/assets/60eab9fa-4a98-449f-baeb-a4d42cb8ee69)

- under the **String**, Unicode: `.pdf` — this is interpreted from binary data that includes .pdf string, so the file that was searched is a PDF file

Ans: ***.pdf***

### Q2. What top-secret keyword was searched for using the search bar in Windows Explorer?

- Same location as the previous question, select the second value, and view the Data Interpreter

![Screenshot 2025-06-02 221949](https://github.com/user-attachments/assets/ac88e017-5be1-4c7f-ae5a-f432ea0f3e97)

Ans: ***continental***


---
# 2. Can't Simply Open it
Not surprisingly, they quickly found what they are looking for in a matter of minutes.

Ha! They seem to have hit a snag! They needed something first before they could continue.

Note:  When using the Autopsy Tool, you can speed up the load times by only selecting "Recent Activity" when configuring the Ingest settings.

**Autopsy Configuration:**
- Open a new case, set a case name, and pick the location you want to save the case to.

![Screenshot 2025-06-02 222542](https://github.com/user-attachments/assets/0f53c1eb-df90-43d3-a164-5c9cfeba9ba2)

- on the Add Data Source Options: 
   1. **Select Host** ->  leave it as default
   2. **Select Data Source Type** -> Logical Files
   3. **Select Data Source** -> `C:\Users\THM-RFedora\Desktop\kape-results\C`
   4. **Configure Ingest** -> Recent Activity
   5. **Finish**


### Q1. What is the name of the downloaded file to the Downloads folder?

- Search for the activity that happened **between 12:05 PM to 12:45 PM on the 19th of November 2022.**
- From the Web Downloads section, at 12:09:19, there was a binary file downloaded

![Screenshot 2025-06-02 224217](https://github.com/user-attachments/assets/1623f128-eb03-489c-91a3-296fbbb5af7a)


Ans: ***7z2201-x64.exe***

### Q2. When was the file from the previous question downloaded? (YYYY-MM-DD HH:MM:SS UTC)

Ans: ***2022-11-19 12:09:19 UTC***

### Q3. Thanks to the previously downloaded file, a PNG file was opened. When was this file opened? (YYYY-MM-DD HH:MM:SS)

- Go back again to Registry Explorer, and search for the registry hive that saves the recently opened files
- Location:  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
- Expand the RecentDocs folder, and select the .png file that was opened at *2022-11-19 12:10:21*
![Screenshot 2025-06-02 225629](https://github.com/user-attachments/assets/0eb7e4e3-73db-4949-8898-839becdbf420)

![Screenshot 2025-06-02 225431](https://github.com/user-attachments/assets/b142f58a-56df-4d40-b6f0-8e78a3e5ee56)


Ans: ***2022-11-19 12:10:21***


---
# Sending it outside
Uh oh. They've hit the jackpot and are now preparing to exfiltrate data outside the network.

There is no way to do it via USB. So what's their other option?

### Q1. A text file was created in the Desktop folder. How many times was this file opened?

- from the **Registry Explorer** in this location ->  `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

![Screenshot 2025-06-02 230037](https://github.com/user-attachments/assets/4072cb72-5ab5-4eec-9af9-25a6a78952de)

- there are three files opened between 12:01:24 and 12:12:35, and the text file opend twice


Ans: ***2***

### Q2. When was the text file from the previous question last modified? (MM/DD/YYYY HH:MM)


- using **JLECmd.exe tool**
```bash
JLECmd.exe -d "C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora" --csv C:\Users\THM-RFedora\Desktop\Task-3   
```
- Then open the Automatic Destination in the Task-3 folder using **EZViewer**

![Screenshot 2025-06-02 234146](https://github.com/user-attachments/assets/324befd7-9330-4ad6-8396-85539e6a86a7)

- on the Path Column, I found this `.txt` file in the desktop folder -> `C:\Users\THM-RFedora\Desktop\launchcode.txt`

Ans: ***11/19/2022 12:12***

### Q3.The contents of the file were exfiltrated to pastebin.com. What is the generated URL of the exfiltrated data?

- From the Web Search section, sort the Data Accessed.

![Screenshot 2025-06-02 235713](https://github.com/user-attachments/assets/44f1ad69-7624-431d-8bb0-e357de24a5ce)

Ans: ***https://pastebin.com/1FQASAav***

### Q4.What is the string that was copied to the pastebin URL?

- track this url (https://pastebin.com/1FQASAav) and copy the string 

![Screenshot 2025-06-03 000054](https://github.com/user-attachments/assets/bfaabaf3-2118-45d7-96ed-a8edccce4890)

- if you don't want to track the URL, use this option. 
- right-click on the raw you want to export and select **Export Selected Raw to CSV**

![Screenshot 2025-06-03 000350](https://github.com/user-attachments/assets/d53e3576-e051-45af-9dbf-e71ac179773e)

![Screenshot 2025-06-03 000725](https://github.com/user-attachments/assets/39ad0171-537f-430f-8b4c-e00ff5558a50)


Ans: ***ne7AIRhi3PdESy9RnOrN***


# Conclusion

At this point, we already have a good idea of what happened. The malicious threat actor was able to successfully find and exfiltrate data. While we could not determine who this person is, it is clear that they knew what they wanted and how to get it.

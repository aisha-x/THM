# TryHackMe: Retracted Challenge

Room URL: https://tryhackme.com/room/retracted


# Intro

"So I downloaded and ran an installer for an antivirus program I needed. After a while, I noticed I could no longer open any of my files. And then I saw that my wallpaper was different and contained a terrifying message telling me to pay if I wanted to get my files back. I panicked and got out of the room to call you. But when I came back, everything was back to normal."

"Except for one message telling me to check my Bitcoin wallet. But I don't even know what a Bitcoin is!"

"Can you help me check if my computer is now fine?"

---
# the Massage

"So, as soon as you finish logging in to the computer, you'll see a file on the desktop addressed to me."

"I have no idea why that message is there and what it means. Maybe you do?"

## Answer the questions below

### Q1. What is the full path of the text file containing the "message"?

![Screenshot 2025-05-17 162953](https://github.com/user-attachments/assets/8b52aea1-14c9-4df3-8eba-b1938a5ce8b9)


Ans: ***C:\Users\Sophie\Desktop\SOPHIE.txt***

### Q2. What program was used to create the text file?

Ans: ***notepad.exe***


### Q3.What is the time of execution of the process that created the text file? Timezone UTC (Format YYYY-MM-DD hh:mm:ss)

 

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*/System/EventID=1 and */EventData/Data[@Name='Image']='C:\Windows\System32\notepad.exe'" |
>> ForEach-Object {
>> $xml = [xml]$_.ToXml()
>> $cmdline = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"}
>> if ($cmdline.'#text' -like "*SOPHIE.txt*"){
>> [PSCustomObject]@{
>> image = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"}).'#text'
>> commandline = $cmdline.'#text'
>> timecreated = $_.TimeCreated
>> }
>> }
>> }

image                           commandline                                                          timecreated
-----                           -----------                                                          -----------
C:\Windows\System32\notepad.exe "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Sophie\Desktop\SOPHIE.txt 5/17/2025 5:47:24 PM
C:\Windows\System32\notepad.exe "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Sophie\Desktop\SOPHIE.txt 1/8/2024 2:25:30 PM


```

Ans: ***2024-01-08 14:25:30***


---
# Something Wrong

"I swear something went wrong with my computer when I ran the installer. Suddenly, my files could not be opened, and the wallpaper changed, telling me to pay."

"Wait, are you telling me that the file I downloaded is a virus? But I downloaded it from Google!"

## Answer the questions below


### Q1. What is the filename of this "installer"? (Including the file extension)

- **Sysmon Event 11** -> File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection. [source](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j)
- and since the file was downloaded from the internet, the file will be in the `download` folder

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*/System/EventID=11" | Where-Object {
$_.Message -like "*\Sophie\download*" } | Format-List m*


Message         : File created:
                  RuleName: -
                  UtcTime: 2024-01-08 14:15:01.682
                  ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                  ProcessId: 5992
                  Image: C:\Users\Sophie\download\antivirus.exe
                  TargetFilename: C:\Users\Sophie\Desktop\VolunteerContacts.xlsx.dmp
                  CreationUtcTime: 2024-01-05 02:57:01.210

Message         : File created:
                  RuleName: -
                  UtcTime: 2024-01-08 14:15:00.916
                  ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                  ProcessId: 5992
                  Image: C:\Users\Sophie\download\antivirus.exe
                  TargetFilename: C:\Users\Sophie\Desktop\FundraisingPlan_2024 - Copy (2).docx.dmp
                  CreationUtcTime: 2024-01-05 02:55:47.686
                  User: SHIELDED-FUTURE\Sophie
MachineName     : SHIELDED-FUTURES-012
```
Ans: ***antivirus.exe***

### Q2. What is the download location of this installer?

Ans: ***C:\Users\Sophie\download***

### Q3. The installer encrypts files and then adds a file extension to the end of the file name. What is this file extension?

- `TargetFilename: C:\Users\Sophie\Desktop\FundraisingPlan_2024 - Copy (2).docx.dmp` the extension `dmp` was seen multiple times in the output of the first question

Ans: ***.dmp***


### Q4. The installer reached out to an IP. What is this IP?

- since we know the installer, filter network connections going from this installer `antivirus.exe`.
```powershell
 Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*/System/EventID=3 and */EventData/Data[@Name='Image']='C:\Users\Sophie\download\antivirus.exe'" | Format-List me*


Message : Network connection detected:
          RuleName: Usermode
          UtcTime: 2024-01-08 14:15:00.821
          ProcessId: 5992
          Image: C:\Users\Sophie\download\antivirus.exe
          User: SHIELDED-FUTURE\Sophie
          Protocol: tcp
          Initiated: true
          SourceIsIpv6: false
          SourceIp: 10.10.235.67
          DestinationIsIpv6: false
          DestinationIp: 10.10.8.111
          DestinationHostname: ip-10-10-8-111.eu-west-1.compute.internal
          DestinationPort: 80
          DestinationPortName: http
```
Ans: ***10.10.8.111***


---
# Back to Normal
"So what happened to the virus? It does seem to be gone since all my files are back."

## Answer the questions below


### Q1.The threat actor logged in via RDP right after the “installer” was downloaded. What is the source IP?

- when i searched in the sysmon logs for network connections event, i find there was a rule named "RDP"
- based on that rule, adject the filter to only view events that happend in the day the installer was downloaded
```powershell
 Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*/System/EventID=3 and */EventData/Data[@Name='RuleName']='RDP'" | Where-Object {$_.message -like "*2024-01-08*"} | Format-List me*


Message : Network connection detected:
          RuleName: RDP
          UtcTime: 2024-01-08 14:19:44.364
          ProcessGuid: {c5d2b969-01e7-659c-1500-000000002701}
          ProcessId: 1108
          Image: C:\Windows\System32\svchost.exe
          User: NT AUTHORITY\NETWORK SERVICE
          Protocol: tcp
          Initiated: false
          SourceIsIpv6: false
          SourceIp: 10.11.27.46
          SourceHostname: ip-10-11-27-46.eu-west-1.compute.internal
          SourcePort: 62336
          SourcePortName: -
          DestinationIsIpv6: false
          DestinationIp: 10.10.235.67
          DestinationHostname: SHIELDED-FUTURES-012.eu-west-1.compute.internal
          DestinationPort: 3389

```
Ans: ***10.11.27.46***

### Q2. This other person downloaded a file and ran it. When was this file run? Timezone UTC (Format YYYY-MM-DD hh:mm:ss)

- search in the download folder and in the same day the installer downloaded
```powershell
 Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*/System/EventID=1" -Oldest| Where-Object {$_.message -like "*2024-01-08*"} |
>> Where-Object {$_.message -like "*C:\Users\Sophie\download\*"} |Format-List m*


Message         : Process Create:
                  RuleName: -
                  UtcTime: 2024-01-08 14:15:00.688
                  ProcessGuid: {c5d2b969-0364-659c-d500-000000002701}
                  ProcessId: 5992
                  Image: C:\Users\Sophie\download\antivirus.exe
                  CommandLine: "C:\Users\Sophie\download\antivirus.exe"
                  CurrentDirectory: C:\Users\Sophie\download\
                  User: SHIELDED-FUTURE\Sophie
                  ParentProcessGuid: {c5d2b969-0266-659c-9c00-000000002701}
                  ParentProcessId: 3696
                  ParentImage: C:\Windows\explorer.exe
                  ParentCommandLine: C:\Windows\Explorer.EXE
                  ParentUser: SHIELDED-FUTURE\Sophie
MachineName     : SHIELDED-FUTURES-012
MatchedQueryIds : {}

Message         : Process Create:
                  RuleName: -
                  UtcTime: 2024-01-08 14:24:18.804
                  ProcessGuid: {c5d2b969-0592-659c-1f01-000000002701}
                  ProcessId: 4544
                  Image: C:\Users\Sophie\download\decryptor.exe
                  CommandLine: "C:\Users\Sophie\download\decryptor.exe"
                  CurrentDirectory: C:\Users\Sophie\download\
                  User: SHIELDED-FUTURE\Sophie
                  ParentImage: C:\Windows\explorer.exe
              

```
- The installer was downloaded at `14:15:00.688`. Next, the attacker established an RDP connection at `14:19:44.364`. Finally, decryptor.exe was downloaded after the attacker gained remote access at `14:24:18.804`, where it decrypted all the files.

Ans: ***2024-01-08 14:24:18***

---
# Doesn't Make Sense
"So you're telling me that someone accessed my computer and changed my files but later undid the changes?"

"That doesn't make any sense. Why infect my machine and clean it afterwards?"

"Can you help me make sense of this?"


Arrange the following events in sequential order from 1 to 7, based on the timeline in which they occurred.

1. Sophie downloaded the malware and ran it.
2. The downloaded malware encrypted the files on the computer and showed a ransomware note.
3. After seeing the ransomware note, Sophie ran out and reached out to you for help.
4. While Sophie was away, an intruder logged into Sophie's machine via RDP and started looking around.
5. The intruder realized he infected a charity organization. He then downloaded a decryptor and decrypted all the files.
6. After all the files are restored, the intruder left the desktop telling Sophie to check her Bitcoin.
7. Sophie and I arrive on the scene to investigate. At this point, the intruder was gone.

# at the end

"Adelle from Finance just called me. She says that someone just donated a huge amount of bitcoin to our charity's account!"

"Could this be our intruder? His malware accidentally infected our systems, found the mistake, and retracted all the changes?"

"Maybe he had a change of heart?"

# Smmit Walkthrough

In this room we chase a simulated adversary up the Pyramid of Pain until they finally back down? This is a room to test the knowledge gained during the Cyber Defense Frameworks module.

This room is part of the SOC Level 1 Path.

[room url](https://tryhackme.com/r/room/summit)



# Task 1: Challenge

After participating in one too many incident response activities, PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its 

malware detection capabilities. You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. At the same time, you will need to configure PicoSecure’s security tools to detect and prevent the malware from executing.

Following the Pyramid of Pain’s ascending priority of indicators, your objective is to increase the simulated adversaries’ cost of operations and chase them away for good. 

Each level of the pyramid allows you to detect and prevent various indicators of attack.


# Questions

**1- What is the first flag you receive after successfully detecting sample1.exe?**

We need to follow Sphinx’s instructions and help see if PicoSecure’s security tools can detected the malware samples executed by him. He will start with something sample, 

but each sample will be more dificult.This first file (sample1.exe) will need to be scanned by the Malware Sandbox tool, and afterwards we need to review the generated report. 

Maybe there’s a unique way for us to distinguish this file and add a detection rule to block it.

Bloch the file from execution based on its hashed value

scan sample1.exe:

![alt](https://www.jalblas.com/wp-content/uploads/2024/12/Screenshot-2024-12-26-210010.jpg.webp)

There is a lot of malicious and suspicious behavior related to the binary.

We need to make sure to block the binary by going to “Manage Hashes” in the menu. 

![image](https://github.com/user-attachments/assets/cd7e2a7b-417e-4a3b-a541-9fe73f7e237c)

We can add the following MD5 hash:

cbda8ae000aa9cbe7c8b982bae006c2a

You prevented sample1.exe from executing by detecting its unique hash value.

Answer: ***THM{f3cbf08151a11a6a331db9c6cf5f4fe4}***

........................................................................................................................................................................


**2- What is the second flag you receive after successfully detecting sample2.exe?**

Good work. That detection you added blocked my malware from executing. Since file hashes and digests are unique to each file, they are, by far, the highest confidence indicators out there. You can be sure it’s my malware sample the next time you see that hash.

However, by design, that is also one of the significant downfalls of simply relying on hashes for detection mechanisms. Since they are so susceptible to change, I only need to alter a single bit of the file, and the detection rule you added will fail.

In fact, all I did this time was recompile the malware, and I generated a new file hash and executed it without issue. See if you can come up with a new way to detect sample2.exe !

Block the file from execution based on its IP address

scan sample2.exe

![image](https://github.com/user-attachments/assets/3198f12d-f98c-41b6-808f-f26c3455b04f)

We get different results now. We also see some information under Network Activity. As we can see the binary makes a suspicious request to the url with the ip: 154.35.10.113:4444. We should probably block that!

We can do this in the Firewall Rule Manager, again found in the menu!

Press the “Create Firewall Rule” button and you will see the following screen:

![image](https://github.com/user-attachments/assets/75fd7641-6b52-4150-b4ee-eaf3c8df94ef)

Fill out the Destination IP with the IP previously found. The Source IP should be set to Any. The Action is Deny. The Type is more tricky but it should be set on Egress. The definition is as follows:

The main difference between data egress and ingress is the direction of data flow: ingress refers to data entering a system or network, while egress refers to data leaving a system or network.

Save the rule and you should get a message that a new mail has arrived, with the second flag.

Answer: ***THM{2ff48a3421a938b388418be273f4806d}***


........................................................................................................................................................................


**3- What is the third flag you receive after successfully detecting sample3.exe?**

It seems like you stopped me again. You must have found the IP address to which my malware sample connected. Clever!

This method isn’t bulletproof, though, as it’s trivial for a motivated adversary to get around it using a new public IP address. I just signed up for a cloud service provider and now have access to many more public IPs!

This time, you’ll need to detect sample3.exe another way. I already have my server running from a new IP address and have plenty more backups to failover in case they get blocked!

Bock the file from execution based on its domain name

scan sample3.exe

![image](https://github.com/user-attachments/assets/d70e94e3-f034-479e-8d26-3a7fb259cab4)

Again, a lot of interesting results. The thing that stands out under HTTP Requests, Connections, and DNS requests is the suspicious URL emudyn.bresonicz.info

Luckily, we have access to the DNS Rule Manager in the menu.

Go there now, and press the “Create DNS Rule” button:

Enter your own Rule Name, Set the Category to “Malware”, enter the domain name emudyn.bresonicz.info, and set the Action to Deny.
![image](https://github.com/user-attachments/assets/93f39686-ad00-4348-86c7-db0d52a5de48)

You should see the rule added to the active rules:

![image](https://github.com/user-attachments/assets/e0fae8b1-092c-44e9-8172-e1f120ebc4a6)

You should also have received a new email with the third flag:

Answer: ***THM{4eca9e2f61a19ecd5df34c788e7dce16}***


........................................................................................................................................................................


**4- What is the fourth flag you receive after successfully detecting sample4.exe?**

It looks like you were able to block my domain this time because every new IP address I try gets detected.

This time – blocking hashes, IPs, or domains won’t help you. If you want to detect sample4.exe, consider what artifacts (or changes) my malware leaves on the victim’s host system

Block the file execution based on its artifacts

scan sample4.exe

![image](https://github.com/user-attachments/assets/5162ab23-26e3-4f81-89d9-014bad2b99f1)

this malware will make changes to the registry manager, so we will add a rule preventing registry modification 

If we look at the sample4.exe binary row, we can see that it writes to a spot in our registry:


sample4.exe	                     Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
Operation: write	                Name: DisableRealtimeMonitoring

Now we have to use the Sigma Rule Builder section, again found in the menu.

Press Create Sigma Rule. On the next screen select Sysmon Event Logs, followed by Registry Modifications.

![image](https://github.com/user-attachments/assets/a2eea454-b268-4ef5-831a-b882d5d06c28)

Proceed by entering the above value. The key, name and value can be found in the scan results. The ATT&CK ID is Defense Evasion as the Malware tries to disable RealtimeMonitoring of Windows Defender.

Create the rule, and you will get a new mail!

Answer: ***THM{c956f455fc076aea829799c0876ee399}***

........................................................................................................................................................................


**5- What is the fifth flag you receive after successfully detecting sample5.exe?**

I finally have sample5.exe for you to detect. Different approach this time. In this sample, all of the “heavy lifting” and instruction occurs on my back-end server, so I can easily change the types of protocols I use and the artifacts I leave on the host. You’ll have to find something unique or abnormal about the behavior of my tool to detect it.

I attached the logs of the outgoing network connections from the last 12 hours on the victim machine. That may help you correlate something.


Let’s open the binary in the Attachment Viewer.

![image](https://github.com/user-attachments/assets/a0e31153-fe94-4ace-89a6-67c3c8a80871)

A few things stand out. Every half an hour there is an outgoing connection to 51.102.10.19, with a size of 97 byes. In addition, there are 2 connections made to port 80 that look different from the other connections on port 443. As you might know, port 80 is made over HTTP, while port 443 is the more secure HTTPS. But that could just be regular web server requests. So let’s focus on the frequent connections of 97 bytes made every 30 minutes.

It’s time to go to the Sigma Rule Builder again. This time select Sysmon Event Logs, followed by Network Connections.

![image](https://github.com/user-attachments/assets/9cf5a892-82a0-4a35-8319-ae90f00d58b3)

I started by entering the specific IP and port from the log, but you will get a message saying that the attacker is smart enough now. So set both Remote IP and Remote Port to Any.

The size should be set to 97 byes, the frequency to 1800s (every half hour), and the ATT&CK ID should probably be set to Command and Control (TA0011), as the log seems to imply that the communication is some part of connection to remote host to get instructions.

It succeeds and you will get another mail with the fifth flag!

Answer: ***THM{46b21c4410e47dc5729ceadef0fc722e}***

........................................................................................................................................................................



**6- What is the final flag you receive from Sphinx?**

For my last trick, I have sample6.exe. This time, you will need more than artifacts or tool detection to help you. You’ll need to focus on something extremely hard for me to change subconsciously – my techniques and procedures.

I’ve attached the recorded command logs from all my previous samples to understand better what actions I tend to perform on my victims to extract info once I have remote access. Good luck!

So, according to Sphinx we need to focus on his techniques and procedures.

You might remember from the ***Pyramid of Doom room*** that the final stage of the pyramid is the TTP stage. TTPs stands for Tactics, Techniques & Procedures. This includes the whole MITRE ATT&CK Matrix, which means all the steps taken by an adversary to achieve his goal, starting from phishing attempts to persistence and data exfiltration.

We have received a commands.log file:

![image](https://github.com/user-attachments/assets/e6381f7a-1705-48b8-89c7-a96a24ee5bef)

The log file seems to show a bunch of commands that are run and written to a exfiltration log file called exfiltr8.log.

This sounds like the [Automated Exfiltration technique](https://attack.mitre.org/techniques/T1020/)

It time for the Sigma Rule Builder again, which should allow us to block the creation of the exfiltration file.

Choose the following options: Sysmon Event Logs > File Creation and Modification:

![image](https://github.com/user-attachments/assets/af9cd88e-a8ee-494b-adc5-2a3caf781cf6)

Then write %temp% as File Path, exfiltr8.log as filename, and Exfiltration (TA0010) as ATT&CK ID.

Validate the rule, and you should get a new mail with the final flag!

Answer: ***THM{c8951b2ad24bbcbac60c16cf2c83d92c}***




source:
[Summit Walkthough](https://www.jalblas.com/blog/tryhackme-summit-walkthrough-soc-level-1/)



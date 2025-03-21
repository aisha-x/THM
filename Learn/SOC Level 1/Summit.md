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

**What is the first flag you receive after successfully detecting sample1.exe?**

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


**What is the second flag you receive after successfully detecting sample2.exe?**

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


**What is the third flag you receive after successfully detecting sample3.exe?**

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







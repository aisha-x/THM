# TryHackMe: Snort Challenge - Live Attacks

Room URL: https://tryhackme.com/room/snortchallenges2

---
# scenario 1 | Brute-Force:

### Your Mission:

- Analyze traffic with Snort.
- Detect the anomaly (the brute-force behavior).
- Write a Snort rule to stop the attacker and protect Shot4J.


1. `ifconfig` to learn network information
   -![Screenshot 2025-04-30 110501](https://github.com/user-attachments/assets/03d0cb09-1514-4343-8552-74b9374e345c)
  

2. started with sniffing mode to take an overview on the traffic  
    - `sudo snort -vXi eth0:eth1`
    - or if you want to inspect it more `sudo snort -vi eth0:eth1 -l .`
    - when I inspect the logs with `sudo strings <snort.log>` I noticed that there is multiple ssh key exchange details which will be visible because ssh starts in plaintext before encryption, this could be an indication of **Brute-force attack** because each failed attempt causes a new SSH session -> and restarts key exchange
3. according to the instructions, edit the `local.rules` file from the `/etc/snort/rules` and add a rule to drop ssh packet
   - `sudo gedit local.rules` to open the file
   - ![Screenshot 2025-04-30 142533](https://github.com/user-attachments/assets/94bb16a8-0d1d-415b-94dc-bb6ec2ea01d4)

4. then from the Desktop directory run this command till you see the `flag.txt` in your desktop
    - `sudo snort -c /etc/snort/snort.conf -vi eth0:eth1 -q -Q --daq afpacket -A full`
    
5. and we get the flag!
   - ![Screenshot 2025-04-30 141925](https://github.com/user-attachments/assets/dba98a7a-bece-4199-9607-287b85c714cf)

6. this is the alert file
   - ![image](https://github.com/user-attachments/assets/9c2caf3a-123c-4d08-a6a6-befdba93af14)

### Answers:

1. the flag -> ***THM{81b7fef657f8aaa6e4e200d616738254}***
2. The name of the service under attack -> ***SSH***
3. the used protocol/port in the attack -> ***TCP/22***


--- 
# Scenario 2 | Reverse-Shell



### your mission:

- analysis the outbound traffic with snort
- Detect the anomaly (possible reverse shell)
- Create a rule to stop the reverse shell


1. Print network information
   - ![Screenshot 2025-04-30 152142](https://github.com/user-attachments/assets/032d4f63-953a-464c-9786-0035dc32c1b5)

2. start with snort sniff mode and log the result for inspection. 
   - `sudo snort -vXi eth0 -l .`

3- There are multiple connections from this IP `10.10.144.156:4444` -> `10.10.196.55`

4- I used `strings` command to extract readable characters from the payload: 
   - ![Screenshot 2025-04-30 165002](https://github.com/user-attachments/assets/2e31c733-01fe-4e54-8334-c95b64592409)

   1. The attacker echoes base64-encoded binary to a file (`/tmp/NlsQY.b64`).
   - This is the file after being decoded as a binary file, **ONLY RUN it in a SandBox**
   - ![Screenshot 2025-04-30 164305](https://github.com/user-attachments/assets/ebc97ca6-d1d8-441d-8e2c-82f6a3c985cd)

   2. Tries to decode it using `base64`, `openssl`, `python`, or `perl`.
   3. Saves it as `/tmp/anCTe`, makes it executable.
   4. Executes it in the background.
   5. Deletes both the binary and the base64 file to cover tracks.


5- So, the attacker:
   - Sent a base64-encoded ELF reverse shell binary.
   - Used port `4444` to receive an incoming connection. Port 4444 is a common Metasploit/reverse shell port.
   - Hoped the payload would be decoded, executed, and connect back.
   - Originated from IP `10.10.144.156`.

6- Now, let's start creating an IPS rule to drop all traffic coming from this port `4444`
   - from `/etc/snort/rules/` edit local.rules
   - ![Screenshot 2025-04-30 172949](https://github.com/user-attachments/assets/9fedb51d-ba70-444f-aac3-a61f97640918)


7- and we get the flag!
  -![Screenshot 2025-04-30 173531](https://github.com/user-attachments/assets/a3f1c741-2089-4de4-a5c9-88161eef3400)


### Answers:

- the flag -> ***THM{0ead8c494861079b1b74ec2380d2cd24}***
- the used protocol/port in the attack -> ***tcp/4444***
- Which tool is highly associated with this specific port number? -> ***Metasploit***

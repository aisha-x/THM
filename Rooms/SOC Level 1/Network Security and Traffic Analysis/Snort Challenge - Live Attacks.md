# TryHackMe: Snort Challenge - Live Attacks

Room URL: https://tryhackme.com/room/snortchallenges2

---
# scenario 1 | Brute-Force:

### Your Mission:
**You must:**
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

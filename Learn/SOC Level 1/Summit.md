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

scan sample1.exe
(alt)[https://www.jalblas.com/wp-content/uploads/2024/12/Screenshot-2024-12-26-210010.jpg.webp]

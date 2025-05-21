# TryHackMe: Incident handling with Splunk Room Summary

Room URL: https://tryhackme.com/room/splunk201

# Table of Contents

1. [Reconnaissance Phase](#reconnaissance-phase)
2. [Exploitation Phase](#exploitation-phase)
3. [Installation Phase](#installation-phase)
4. [Action on Objective](#action-on-objective)
5. [Command and Control Phase](#command-and-control-phase)
6. [Weaponization Phase](#weaponization-phase)
7. [Delivery Phase](#delivery-phase)
8. [Conclusion](#conclusion)

# Incident Handling: Scenario

In this exercise, we will investigate a cyber attack in which the attacker defaced an organization's website. This organization has Splunk as a SIEM solution setup. Our task as a Security Analysis would be to investigate this cyber attack and map the attacker's activities into all 7 of the Cyber Kill Chain Phases. It is important to note that we don't need to follow the sequence of the cyber kill chain during the Investigation. One finding in one phase will lead to another finding that may have mapped into some other phase.

## Cyber Kill Chain 
We will follow the Cyber kill Chain Model and map the attacker's activity in each phase during this Investigation. When required, we will also utilize Open Source Intelligence (OSINT) and other findings to fill the gaps in the kill chain. It is not necessary to follow this sequence of the phases while investigating.

- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command & Control
- Actions on Objectives


## Scenario   

 A Big corporate organization **Wayne Enterprises**  has recently faced a cyber-attack where the attackers broke into their network, found their way to their web server, and have successfully defaced their website `http://www.imreallynotbatman.com` . Their website is now showing the trademark of the attackers with the message **YOUR SITE HAS BEEN DEFACED**.  

They have requested " US " to join them as a **Security Analyst** and help them investigate this cyber attack and find the root cause and all the attackers' activities within their network.

## Disclaimer
As this is a public [dataset](https://github.com/splunk/botsv1) released by Splunk, which depicts a realistic scenario, it is advised that this dataset may contain profanity, slang, vulgar expressions, and/or generally offensive terminology. Please use with discretion.

# Reconnaissance Phase


Reconnaissance is an attempt to discover and collect information about a target. It could be knowledge about the system in use, the web application, employees or location, etc.

## Steps to take in the Reconnaissance phase:

1. start by examining any reconnaissance attempt against the webserver `imreallynotbatman.com`
    - `index=botsv1 imreallynotbatman.com`
    - inspect the source logs field to see which log includes the traces of our domain.
   
    ![image](https://github.com/user-attachments/assets/c5b89079-e458-48bc-b18b-1d1e8d02647a)

2. select `stream:http` log which contains the http traffic logs
    - `index=botsv1 imreallynotbatman.com sourcetype=stream:http`
    - since we are searching for reconnaissance attemp, we will be the destination target
    - look in the `src_ip ` field:
  
   ![Screenshot 2025-05-19 134231](https://github.com/user-attachments/assets/40d154f1-3764-46eb-a5d9-48e55c411f56)
 
       - `40.80.148.42`, `23.22.63.114`
       - The first IP seems to contain a high percentage of the logs as compared to the other IP
3. investigate `40.80.148.42`, 
       - `index=botsv1 imreallynotbatman.com src=40.80.148.42`
       - and look in the these fields: `User-Agent, Post request, URIs` to see what kind of traffic is coming from this particular IP.
4. use `suricata` logs to validate the scanning attempt from this suspicious ip address, and see if any rule is triggered on this communication.
      - `index="botsv1" imreallynotbatman.com sourcetype=suricata dest_ip="192.168.250.70" eventtype=suricata_eve_ids_attack status=404 scan`
      - I used the `status` feild because the attacker will try to brute-force hidden pages in the website, as for `scan`, I wanted to search for any scan string. and this is what it returned
     
     ![Screenshot 2025-05-19 153328](https://github.com/user-attachments/assets/5f55553f-df88-4487-bb16-04c5e90f6402)


## Answer the questions below

### Q1. One suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value?
- `index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata`
- inspect the `alert.signature` field

![Screenshot 2025-05-19 142032](https://github.com/user-attachments/assets/8975628f-7dd7-42ca-b567-63482f05102b)

- [CVE-2014-6271](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)
- this flaw allows attackers to execute arbitrary commands on a system by crafting malicious **environment variables**, exploiting how Bash processes function definitions within these variables

![Screenshot 2025-05-19 134343](https://github.com/user-attachments/assets/9ec9edc9-63d8-4048-9803-890b0f342f61)

Ans: ***CVE-2014-6271***

### Q2. What is the CMS our web server is using?

- To find a CMS (**Content Management System**) in an HTTP response or website, you typically look at various fingerprints or metadata exposed in the HTML, headers, or URLs.
- CMS-specific comments or script URLs:
   - `/wp-content/` → WordPress
   -` /sites/all/` → Drupal
   - `/administrator/` → Joomla
   - `/index.php?option=com_ `→ Joomla componen

- `index="botsv1" imreallynotbatman.com src_ip="40.80.148.42" sourcetype=suricata http_method=POST` 

![Screenshot 2025-05-19 134419](https://github.com/user-attachments/assets/1c81461a-d0b0-4335-8af2-936ac347f66a)

Ans: ***joomla***

### Q3. What is the web scanner, the attacker used to perform the scanning attempts?
- [Acunetix Scanner](https://www.acunetix.com/vulnerability-scanner/)
Ans: ***acunetix***

### Q4. What is the IP address of the server imreallynotbatman.com?

- the attacker is burte-forcing the website, so the destionation is `imreallynotbatman.com` servevr

Ans:  ***192.168.250.70***


---
# Exploitation Phase

The attacker needs to exploit the vulnerability to gain access to the system/server.

In this task, we will look at the potential exploitation attempt from the attacker against our web server and see if the attacker got successful in exploiting or not.

## Steps to take in the Exploitation Phase

1. first see the number of counts by each source IP against the webserver.
   - `index=botsv1 imreallynotbatman.com sourcetype=stream* | stats count(src_ip) as Requests by src_ip | sort - Requests`
   
   ![image](https://github.com/user-attachments/assets/bda2d020-e752-4e7d-9158-368678a32791)
 
2. see the requests sent to our web server
   - `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"`
   - inspect both of `src_ip` and `http_method` fileds 
   
   ![Screenshot 2025-05-19 134435](https://github.com/user-attachments/assets/79296d27-7135-434e-b305-ccaa19bd2602)
   ![image](https://github.com/user-attachments/assets/b15f07d6-4184-41bb-9ec8-6b4ba7bde92a)

3. most of the requests coming to our server were from POST requests, narrwo down on the field `http_method=POST`
   - `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST `

  ![image](https://github.com/user-attachments/assets/d888aa68-e1e4-4812-8685-52c0b57ddda8)

   - The result in the `src_ip` field shows two IP addresses sending all the POST requests to our server.
   - inspect these fields: `src_ip, form_data, http_user_agent, uri`
4. in the `uri` field, our web server is using **Joomla** CMS (Content Management Service) in the backend.
   - The admin login page of the Joomla CMS will show as -> `/joomla/administrator/index.php`
   - this uri contains the **login page** to access the web portal therefore, we will be examining the traffic coming into this **admin** panel for a potential **brute-force attack**.
   - `index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip="192.168.250.70"  uri="/joomla/administrator/index.php"`
   - inspect the `form_data` field, it contains the requests sent through the form on the admin panel page, which has a login page
5. the attacker may have tried multiple credentials in an attempt to gain access to the admin panel
   - `ndex=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data`
  
  ![image](https://github.com/user-attachments/assets/d25d9c3c-e62b-4fb6-9f39-0cff00e4eb85)

   - It seems like the IP `23.22.63.114 ` is trying to brute-force the admin account.
6. Extracting Username and Passwd Fields using Regex
   - since we know the username admin is the target, use `rex` to extract the passwd values only. 
   - `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table src_ip creds`
   
   ![Screenshot 2025-05-20 122005](https://github.com/user-attachments/assets/b6b1f749-5710-4da5-8d2d-d42cd4a0778c)

7. Inspect `user_agent` field

   ![image](https://github.com/user-attachments/assets/160a1755-c914-40d4-ba98-43e3976718cb)

   - The first value clearly shows attacker used a Python script to automate the brute force attack against our server
   - The second browser came from `40.80.148.42` 

## Answer the questions below

### Q1. What was the URI which got multiple brute force attempts?
Ans:  ***/joomla/administrator/index.php***

### Q2. Against which username was the brute force attempt made?
Ans:  ***admin***

### 3. What was the correct password for admin access to the content management system running imreallynotbatman.com?

Ans:  ***batman***


### Q4. How many unique passwords were attempted in the brute force attempt?

- in the use_agent field, the attacker used a python script to automate the brute force attack against our server, but one request came from Mozilla browser. 
- if we exclude the one request came from  Mozilla browser, 412 request was send to our server to brout-force the admin account

Ans:  ***412***

### Q5.What IP address is likely attempting a brute force password attack against imreallynotbatman.com?

Ans:  ***23.22.63.114***

### Q6. After finding the correct password, which IP did the attacker use to log in to the admin panel?

Ans: ***40.80.148.42***


---
# Installation Phase

Once the attacker has successfully exploited the security of a system, he will try to install a backdoor or an application for persistence or to gain more control of the system. This activity comes under the installation phase.

In the previous Exploitation phase, we found evidence of the webserver `iamreallynotbatman.com` getting compromised via brute-force attack by the attacker using the python script to automate getting the correct password. The attacker used the IP" for the attack and the IP to log in to the server. This phase will investigate any payload / malicious program uploaded to the server from any attacker's IPs and installed into the compromised server.

## Steps to take in the Installation Phase

1.  we first would narrow down any http traffic coming into our server `192.168.250.70` containing the term **".exe."**
   - `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe`
   - ` part_filename{}` field contains two file names. an executable file **3791.exe** and a PHP file **agent.php**
   - `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"`
   
   ![Screenshot 2025-05-20 124819](https://github.com/user-attachments/assets/5e098413-3ea0-4e21-8962-2c237a81f6e0)

2. file **3791.exe** was uploaded on the server, we need to look on the **host-centric** log sources to confirm if the filed was executed
   - `index=botsv1 "3791.exe"`
   - Inspect the `source_log `field
   
   ![image](https://github.com/user-attachments/assets/f886d7e7-5e77-40ba-a218-5388b61b5a86)
 
   - XmlWinEventLog (contains Sysmon event logs), WinEventlog and fortigate_utm, have traces of the executable 3791. exe.
   - `index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1`

![image](https://github.com/user-attachments/assets/7015aa41-b393-43cf-b54b-f2484b2073b5)

   - from the `CommandLine` field, we can clearly we can clearly say that this file was executed on the compromised server.



## Answer the questions below

### Q1. Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?
- in the  `Hashes` field
Ans: ***AAE3F5A29935E6ABCC2C2754D12A9AF0***

### Q2.Looking at the logs, which user executed the program 3791.exe on the server?

- in the `User` field
Ans: ***NT AUTHORITY\IUSR***

### Q3. Search hash on the virustotal. What other name is associated with this file 3791.exe?

- in the DETAILS tab
- 
![Screenshot 2025-05-20 130834](https://github.com/user-attachments/assets/a0f3576f-165e-4fee-8013-41c5de7fb293)

Ans: ***ab.exe***


---
# Action on Objective

As the website was defaced due to a successful attack by the adversary, it would be helpful to understand better what ended up on the website that caused defacement.


## Steps to take in the Action on Objective phase
1. start the investigation by examining the Suricata log source and the IP addresses communicating with the webserver `192.168.250.70.`
   - `index=botsv1 src=192.168.250.70 sourcetype=suricata`

![image](https://github.com/user-attachments/assets/7d82ae00-766c-46bd-96b3-c9ee964394e9)

   - Usually, the web servers do not originate the traffic. 
   - Here we see three external IPs towards which our web server initiates the outbound traffic
3. Pivot into the destination IPs one by one to see what kind of traffic/communication is being carried out.
   - `index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114`
   - inspect the url field
 
  ![image](https://github.com/user-attachments/assets/590a1586-22c9-43ad-8c80-62b438722841)

4. The URL field shows 2 PHP files and one jpeg file
   - investigate the jpeg file
   - `index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url`

## Answer the questions below


### Q1. What is the name of the file that defaced the imreallynotbatman.com website ?

Ans: ***poisonivy-is-coming-for-you-batman.jpeg***

### Q2. Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?

- `index=botsv1 sourcetype="fortigate_utm" src_ip="40.80.148.42"`
- Inspect the attack field

![Screenshot 2025-05-20 133422](https://github.com/user-attachments/assets/da40c703-8d9a-46f7-9f43-6f87635f7151)

Ans: ***HTTP.URI.SQL.Injection***

---
# Command and Control Phase
The attacker uploaded the file to the server before defacing it. While doing so, the attacker used a Dynamic DNS to resolve a malicious IP. Our objective would be to find the IP that the attacker decided the DNS.

To investigate the communication to and from the adversary's IP addresses, we will be examining the network-centric log sources mentioned above.

## Steps to take in the 
1. first use `fortigate_utm` to review the firewall logs.
   - `index=botsv1 sourcetype=fortigate_utm"poisonivy-is-coming-for-you-batman.jpeg"`

![image](https://github.com/user-attachments/assets/c8f9871a-da21-4df9-aa56-e3ef679502bd)

   - we can see the src IP, destination IP, and URL, that our server is communicating with this ip `23.22.63.114`
3. Inspect the url field to identify FQDN (fully Qualified Domain Name)
   
   ![image](https://github.com/user-attachments/assets/b0e31b19-9430-4c61-95ee-2a72e5169681)

   - just to confirm our finding, search in the stream:http logs
   - `index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70`
4. We can also confirm the domain by looking at the log source stream:dns to see what DNS queries were sent from the webserver during the infection period.


### Q1. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

- we found the suspicious domain the attacker used on our server to request a malicious file from this domain `prankglassinebracket[.]jumpingcrab[.]com` 
- confirm the dns query:  
   - `index=botsv1 sourcetype="stream:dns" "prankglassinebracket.jumpingcrab.com"`

  ![Screenshot 2025-05-21 114735](https://github.com/user-attachments/assets/5ae104e7-5b1e-4ab2-a6f3-936e9244578f)

- as you can see, the attacker used `8.8.8.8` DNS, to resolve the malicious domain
> to solve the question, remove the defanging 
Ans: ***prankglassinebracket[.]jumpingcrab[.]com***

# Weaponization Phase
In the weaponization phase, the adversaries would:

- Create Malware / Malicious document to gain initial access / evade detection etc.
- Establish domains similar to the target domain to trick users.
- Create a Command and Control Server for the post-exploitation communication/activity etc.

We have found some domains / IP addresses associated with the attacker during the investigations. This task will mainly look into **OSINT** sites to see what more information we can get about the adversary.

## information we had:
- the attacker domain -> `prankglassinebracket.jumpingcrab.com`
- the equivalent ip address -> `23.22.63.114`

search the online Threat Intel sites for any information like IP addresses/domains / Email addresses associated with this domain which could help us know more about this adversary.

## Answer the questions below

### Q1. What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

- if we search in the [VirousTotal](https://www.virustotal.com/gui/domain/prankglassinebracket.jumpingcrab.com/relations) on `prankglassinebracket.jumpingcrab.com`, we will find in the RELATIONS tab the IP address associated with this domain

![Screenshot 2025-05-21 121125](https://github.com/user-attachments/assets/26bbf1b4-23ca-4ba2-aa28-59fc26f95a3f)

- now search for this ip `23.22.63.114`

![Screenshot 2025-05-21 121412](https://github.com/user-attachments/assets/89cfde64-0717-47ca-92aa-42836c74bd85)

- in the RELATIONS tab, we can see all the domains associated with this IP which look similar to the Wayn Enterprise company.

Ans: ***23.22.63.114***
### Q2. Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?

- use this [website](https://otx.alienvault.com/indicator/hostname/www.po1s0n1vy.com ) to search for `www.po1s0n1vy.com`

![Screenshot 2025-05-21 123355](https://github.com/user-attachments/assets/9425b1a9-2474-4388-b103-da53f0340b95)

Ans: ***lillian.rose@po1s0n1vy.com***


---
# Delivery Phase

Attackers create malware and infect devices to gain initial access or evade defenses and find ways to deliver it through different means. We have identified various IP addresses, domains and Email addresses associated with this adversary. Our task for this lesson would be to use the information we have about the adversary and use various Threat Hunting platforms and OSINT sites to find any malware linked with the adversary.

Threat Intel report suggested that this adversary group Poison lvy appears to have a secondary attack vector in case the initial compromise fails. Our objective would be to understand more about the attacker and their methodology and correlate the information found in the logs with various threat Intel sources.

## OSINT sites

- [Virustotal](http://virustotal.com/)
- [ThreatMiner](https://www.threatminer.org/host.php?q=23.22.63.114#gsc.tab=0&gsc.q=23.22.63.114&gsc.page=1)
- [ Hybrid-Analysis](https://www.hybrid-analysis.com/sample/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8?environmentId=100)

## Steps to take:
1. use VirusTotal to search for `23.22.63.114`, from the RELATIONS Tab inspect the Communicating Files 
 
  ![Screenshot 2025-05-21 131000](https://github.com/user-attachments/assets/a79dfd7b-a943-43d3-bb08-fb6bef34220a)

  - We found four files associated with this IP, one of them seems suspicious `MirandaTateScreensaver.scr.exe`
2. click on this file `MirandaTateScreensaver.scr.exe`
  
  ![image](https://github.com/user-attachments/assets/4736887f-5757-4715-b32d-0ee2238e87c2)
  
  - we can also use [ Hybrid-Analysis](https://www.hybrid-analysis.com/sample/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8?environmentId=100) to get a lot of information about this malware

## Answer the questions below

### Q1. What is the HASH of the Malware associated with the APT group?

Ans:  ***c99131e0169171935c5ac32615ed6261***
### Q2. What is the name of the Malware associated with the Poison Ivy Infrastructure?

Ans: ***MirandaTateScreensaver.scr.exe***


---
# Conclusion

## 1. Reconnaissance Phase:

We first looked at any reconnaissance activity from the attacker to identify the IP address and other details about the adversary.
## Findings:

- IP Address `40.80.148.42` was found to be scanning our webserver.
- The attacker was using **Acunetix** as a web scanner.

##  2. Exploitation Phase:

We then looked into the traces of exploitation attempts and found brute-force attacks against our server, which were successful.

## Findings 
- Brute force attack originated from IP `23.22.63.114`.
- The IP address used to gain access: `40.80.148.42`
- 142 unique brute force attempts were made against the server, out of which one attempt was successful which is the `batman` password

## 3. Installation Phase:

Next, we looked at the installation phase to see any executable from the attacker's IP Address uploaded to our server.

## Findings 
- A malicious executable file **3791.exe** was observed to be uploaded by the attacker.
- We looked at the sysmon logs and found the MD5 hash of the file


## 4. Action on Objectives:
After compromising the web server, the attacker defaced the website.

## Findings

- the attacker used this malicious server `prankglassinebracket[.]jumpingcrab[.]com` to uploade jpeg file to the webserver 
- the file name `poisonivy-is-coming-for-you-batman.jpeg` used to deface the webserver.


## 5. Command and Control Phase:

## Findings:
- the logs show the server initiating an outbound connection to `23.22.63.114`, and the associated URL revealed the use of a suspicious domain name.
- Inspection of the URL field revealed the domain: `prankglassinebracket.jumpingcrab.com`
- This domain was verified using stream:dns logs, where a DNS query was seen requesting resolution for the domain `prankglassinebracket.jumpingcrab.com`
- The DNS query was sent to Google’s public DNS server (8.8.8.8).

## 6. Weaponization Phase:

We used various threat Intel platforms to find the attacker's infrastructure based on the following information we saw in the above activities.

## Findings:
- Multiple masquerading domains were found associated with the attacker's IPs.
- An email of the user `Lillian.rose@po1s0n1vy.com` was also found associated with the attacker's IP address.
## 7. Deliver Phase:

In this phase, we again leveraged online Threat Intel sites to find malware associated with the adversary's IP address, which appeared to be a secondary attack vector if the initial compromise failed.

Findings:
- A malware name `MirandaTateScreensaver.scr.exe` was found associated with the adversary.
- MD5 of the malware was `c99131e0169171935c5ac32615ed6261`

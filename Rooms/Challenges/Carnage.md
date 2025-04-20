# TryHackme -- Carnage Walkthrough

Room URL: 





**Q1.What was the date and time for the first HTTP connection to the malicious IP?** 

- change the time display from the view par 
- ![q1 time change](https://github.com/user-attachments/assets/7033a90d-5fc2-4c16-8965-f849be17e0a1)
- search in the display filter for http and the time order from earliest to latest. so select the first packet
- ![q1 http filter](https://github.com/user-attachments/assets/95c2b3e0-adbe-455c-878b-0ff4c59e46de)

Ans: ***2021-09-24 16:44:38*** 


---
**Q2.What is the name of the zip file that was downloaded?**

- you can see it from the first http connection 
- ![q2 http filter](https://github.com/user-attachments/assets/4d34aa43-925c-4aa7-a074-8c817e424f3a)
- you can also filter for that zip file `http.request.uri contains "zip"`
- ![q2 zip filter](https://github.com/user-attachments/assets/283b3607-35a3-4007-aea1-cccd5ea0eeaa)

Ans: ***documents.zip*** 

---
**Q3.What was the domain hosting the malicious zip file?**

- right click on the http packet and follow HTTP stream
- in the http request header you can see the domain that hosting this malicious file
- ![q3](https://github.com/user-attachments/assets/66f80c1c-50d3-49e2-ada4-4ba206250d3a)
 

Ans: ***attirenepal.com*** 

---
**Q4.Without downloading the file, what is the name of the file in the zip file?**

- in the same conversation of the first http connection, look in the content
- ![q4 ans](https://github.com/user-attachments/assets/f34278e2-fdfb-4bab-abaf-2a3e116e09b0)
 

Ans: ***chart-1530076591.xls*** 

---
**Q5.What is the name of the webserver of the malicious IP from which the zip file was downloaded?**

- in the http response header 
- ![q5 ans](https://github.com/user-attachments/assets/e4d02e02-fdfa-426a-a3de-20b86a45f5f2)


Ans: ***LiteSpeed*** 

---
**Q6.What is the version of the webserver from the previous question?**

- in the x-powered-by header 
-![q6 ans](https://github.com/user-attachments/assets/f893082f-ca99-4634-9b5a-269bf613b397)


Ans: ***PHP/7.2.34*** 

**Note**

what is the different between x-powered-by header and Server header? 

1. Server Header: This header provides information about the web server software handling the request. It typically includes the name and version of the server software (e.g., Apache, Nginx).
2. X-Powered-By Header: This is a non-standard header that indicates the technology or framework used to build the web application (e.g., PHP, ASP.NET).

---
**Q7.Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved with this activity?**

- first filter by `tcp.port = 443` and look for the first message in the TLS Handshake with is `client hello`
- search for the Extension: server_name header and right click on the server name header and select apply as a column so we can search for the domain  
- ![q7 server column](https://github.com/user-attachments/assets/e6a75348-b089-41eb-b700-619647de4eb0)
- Now apply this filter `(tcp.port == 443 or tcp.port == 80 or tcp.port == 8080 ) && (tls.handshake.extensions_server_name != "")` 
- we will a plenty of servers, finding the right answers was the one that fit the answer format  

Ans: ***finejewels.com.au, thietbiagt.com, new.americold.com*** 

---
**Q8.Which certificate authority issued the SSL certificate to the first domain from the previous question?**

- filter based on this server name `tls.handshake.extensions_server_name == "finejewels.com.au"`
- follow this packet tcp stream 
- ![q8 tcp stram](https://github.com/user-attachments/assets/8df50032-abf0-485a-aeb2-95ba47d3cd48)
- again filter on this tcp stream the TLS handshake type to filter only the certification message
- `tcp.stream eq 90 and tls.handshake.type == 11`
- ![q8 filter](https://github.com/user-attachments/assets/add4f6f8-5cf4-4d90-92a0-d128cc0e17e3)
- expand Handshake Protocol: Certificate tree and expand each certification section and inspect it
- ![q8 ans](https://github.com/user-attachments/assets/e415ac90-318e-4e12-aa6f-413b46610f15)

Ans: ***GoDaddy*** 

---
**Q9. What are the two IP addresses of the Cobalt Strike servers? Use VirusTotal (the Community tab) to confirm if IPs are identified as Cobalt Strike C2 servers. (answer format: enter the IP addresses in sequential order)**

- lets search first on [Cobalt Strike](https://attack.mitre.org/software/S0154/) in Mitre attack framework to find what port or ip addresses that Cobalt Strike associate with
- ![mire attack framework](https://github.com/user-attachments/assets/8e8eb51b-69ef-4aa7-b1ba-6b073ec8ef3c)
- since we know that is uses https and http for c2 servers, return to Wireshark and go to statistics -> Conversitions 
- in the tcp tap foucs on the destination port and inspect http and https ports 
- the local machine is repeatedly connecting to the same ip and port (80,8080) but using different source ports this is likely automated or scripted behavior or presistent or repeated traffic 
- ![80 port](https://github.com/user-attachments/assets/2c912804-75cd-4590-b9d4-80927c9b2e73)
- ![8080 port](https://github.com/user-attachments/assets/0f81fd8e-3dc8-43af-b449-f00dce79cee4)
- inspect these IPs in Virustotal and look in the community tap 
- ![q9 community confirm](https://github.com/user-attachments/assets/95c1fd53-46a3-4ae2-b172-f3720213f1e3)


Ans: ***185.106.96.158, 185.125.204.174***

---
**Q10.What is the Host header for the first Cobalt Strike IP address from the previous question?**

- filter for this specific ip address `ip.addr ==185.106.96.158 ` and follow tcp stream
- ![q10 follow stream](https://github.com/user-attachments/assets/be9d4eeb-2763-48a7-b3dd-3bd0e349799c)
- ![q10 ans](https://github.com/user-attachments/assets/5106d836-0d7b-459d-9d3d-8677214ecef6)

Ans: ***ocsp.verisign.com***

---
**Q11.What is the domain name for the first IP address of the Cobalt Strike server? You may use VirusTotal to confirm if it's the Cobalt Strike server (check the Community tab).**

- ![q11](https://github.com/user-attachments/assets/986cf7c1-fc5e-489b-9acb-ec172ed707bd)

Ans: ***survmeter.live***

---
**Q12.What is the domain name of the second Cobalt Strike server IP?  You may use VirusTotal to confirm if it's the Cobalt Strike server (check the Community tab).**

- ![q12 ans](https://github.com/user-attachments/assets/cd31aaaa-796f-4173-8881-1db777a75cbb)

Ans: ***securitybusinpuff.com***

---
**Q13.What is the domain name of the post-infection traffic?**

- filter for `http.request.method == POST` and follow tcp stream of the first packet, you will find the domain name in the host header 
- ![q13 ans](https://github.com/user-attachments/assets/2c2fd220-f754-4a54-8872-a5f799a293a7)

Ans: ***maldivehost.net***

---
**Q14.What are the first eleven characters that the victim host sends out to the malicious domain involved in the post-infection traffic?**

- ![q14 ans](https://github.com/user-attachments/assets/cd22b525-06cc-448e-9ebd-338fe83f0840)

Ans: ***zLIisQRWZI9***

---
**Q15.What was the length for the first packet sent out to the C2 server?**

- filter for `http.request.method == POST` and sort by time
- ![q15 ans](https://github.com/user-attachments/assets/b13ee550-2881-4145-8c68-261a2577fb25)

Ans: ***281***


---
**Q16.What was the Server header for the malicious domain from the previous question?**

- follow http stream of the previous packet and look for the server header
- ![q16 ans](https://github.com/user-attachments/assets/57be0b8f-ca01-4f61-8e96-fc4cf899e688)

Ans: ***Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4***

---
**Q17.The malware used an API to check for the IP address of the victim’s machine. What was the date and time when the DNS query for the IP check domain occurred? (answer format: yyyy-mm-dd hh:mm:ss UTC)**

- filter for dns that contain api `dns contains api`
- ![q17 ans](https://github.com/user-attachments/assets/65355ccc-c324-47ee-bf6e-2322d9c23886)
- the domain api[.]ipify[.]org is a public IP address API service-it's commonly used to retrieve your public ip address. 

| use case:

- In scripts or malware to find out the infected machine’s external (public) IP.
- In penetration testing, to verify which public IP your traffic is coming from.
- In web apps, to get the client’s IP for logging or geo-IP lookups.

Basic Example (Using curl):

`curl https://api[.]ipify[.]org`

Response:

`203.0.113.45`

Suspicious Context?

If you saw api.ipify.org in a packet capture:

- It could be legitimate if a user/script was checking their public IP.
- But it’s also commonly used by malware or C2 clients to:
	- Check if they’re behind NAT/firewall
	- Log infected host’s IP for tracking
	- Confirm internet access

Ans: ***2021-09-24 17:00:04***

---
**Q18.What was the domain in the DNS query from the previous question?**

- ![q18 ans](https://github.com/user-attachments/assets/3ebe677c-8e30-4802-93f0-7b642667b1d8)

Ans: ***api.ipify.org***

---
**Q19.Looks like there was some malicious spam (malspam) activity going on. What was the first MAIL FROM address observed in the traffic?**

- filter for `tcp contains MAIL` and select the first packet has MAIL FROM addres info
- ![q19 ans](https://github.com/user-attachments/assets/0abfe173-b422-4a26-903b-6d6d82879f72)

Ans: ***farshin@mailfa.com***

---
**Q20.How many packets were observed for the SMTP traffic?**

- filter for smtp protocol `smtp`

Ans: ***1439***



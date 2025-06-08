# TryHackMe: Snapped Phish-ing Line Challenge

Room URL: https://tryhackme.com/room/snappedphishingline

# Challenge Scenario

**Disclaimer**

Based on real-world occurrences and past analysis, this scenario presents a narrative with invented names, characters, and events.

> **Please note:** The phishing kit used in this scenario was retrieved from a real-world phishing campaign. Hence, it is advised that interaction with the phishing artefacts be done only inside the attached VM, as it is an isolated environment.


**An Ordinary Midsummer Day...**

As an IT department personnel of SwiftSpend Financial, one of your responsibilities is to support your fellow employees with their technical concerns. While everything seemed ordinary and mundane, this gradually changed when several employees from various departments started reporting an unusual email they had received. Unfortunately, some had already submitted their credentials and could no longer log in.

**You now proceeded to investigate what is going on by:**

1. Analysing the email samples provided by your colleagues.
2. Analysing the phishing URL(s) by browsing it using Firefox.
3. Retrieving the phishing kit used by the adversary.
4. Using CTI-related tooling to gather more information about the adversary.
5. Analysing the phishing kit to gather more information about the adversary.


---

## Answer the questions below


### Q1. Who is the individual who received an email attachment containing a PDF?

![Screenshot 2025-06-08 130950](https://github.com/user-attachments/assets/1784eb16-b386-4b0b-b117-cd5d53aeacf4)

Ans: ***William McClean***
---

### Q2. What email address was used by the adversary to send the phishing emails?

![Screenshot 2025-06-08 130950](https://github.com/user-attachments/assets/ae4735ac-c210-4d1a-b33b-49e557fec99a)


Ans: ***Accounts.Payable@groupmarketingonline.icu***

---

### Q3.What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)


- open Zoe's email, save the html attachment and extract the md5 hash to search for this file in VirusTotal

![Screenshot 2025-06-08 133145](https://github.com/user-attachments/assets/b2811903-cddd-4b24-aff2-6386d3374542)

![Screenshot 2025-06-08 133133](https://github.com/user-attachments/assets/288a2578-f120-4df9-a1e0-2dbc1624fd02)


Ans: ***hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error***

---

### Q4.What is the URL to the .zip archive of the phishing kit? (defanged format)

- use `curl` to get us a detailed information about the HTTP response headers

![Screenshot 2025-06-08 140017](https://github.com/user-attachments/assets/9751bff6-de86-4a6b-9d53-474597cdbe40)


Ans: ***hxxp[://]kennaroads[.]buzz/data/Update365[.]zip***

---

### Q5. What is the SHA256 hash of the phishing kit archive?

- I used `curl` again to get the zip file and save it on the VM

![Screenshot 2025-06-08 140513](https://github.com/user-attachments/assets/8880156c-3b36-4faa-bcdc-975ca9686331)


Ans: ***ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686***

---

### Q6.When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

- copy the sha256 hash and search for it in [VirusTotal](https://www.virustotal.com/gui/file/ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686/details)

![Screenshot 2025-06-08 140703](https://github.com/user-attachments/assets/bfce932e-5c08-4595-aa2d-307545324381)


Ans: ***2020-04-08 21:55:50 UTC***

---

### Q7. When was the SSL certificate the phishing domain used to host the phishing kit archive first logged? (format: YYYY-MM-DD)


Ans: ***2020-06-25***

---

### Q8.What was the email address of the user who submitted their password twice?

- I explored the subdomains in VM and found a log.txt that contains user's emails and passwords

![Screenshot 2025-06-08 143959](https://github.com/user-attachments/assets/b703d1d9-d0fe-4477-8dd5-9e27438bf924)


Ans: ***michael.ascot@swiftspend.finance***

---

### Q9. What was the email address used by the adversary to collect compromised credentials?

- download the zip in the vm and unzip it

![Screenshot 2025-06-08 144740](https://github.com/user-attachments/assets/c1e61060-17ca-4cfd-b605-73615b939093)

- it was in the `office365/Validation/submit.php` file

![Screenshot 2025-06-08 145000](https://github.com/user-attachments/assets/f16fe4ec-4ea3-4292-aeb5-528926c161cc)


Ans: ***m3npat@yandex.com***

---

### Q10. The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?

- the other email wan it this location:  `office365/Validation/update`

![Screenshot 2025-06-08 145641](https://github.com/user-attachments/assets/e26b2be7-ced5-452a-86c8-e989c621484f)


Ans: ***jamestanner2299@gmail.com***

---

### Q11. What is the hidden flag?

- there was nothing in the zip file, so after some research I find it hidden in this location "office365/", you have to type flag.txt.

![Screenshot 2025-06-08 153036](https://github.com/user-attachments/assets/b54043f2-1903-44ec-901c-e3dcca55e42b)

![Screenshot 2025-06-08 153044](https://github.com/user-attachments/assets/245ea0b6-a61a-4c63-bd83-afafe2a4783c)


- the text was reversed so i used python to reverse it again

![Screenshot 2025-06-08 153024](https://github.com/user-attachments/assets/4270e806-3489-4d03-8c55-831cf3e4b07d)

Ans: ***THM{pL4y_w1Th_tH3_URL}***

---

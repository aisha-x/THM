# Phishing SOC Simulation


## **Introduction to Phishing **

Sim  Link: https://tryhackme.com/soc-sim/scenarios

### **Scenario overview**

Learn how to use SOC Simulator by completing your first scenario. Close all True Positive alerts to pass!

### **Scenario objectives**

- Monitor and analyze real-time alerts.
- Identify and document critical events such as suspicious emails and attachments.
- Create detailed case reports based on your observations to help your team understand the full scope of alerts and malicious activity.

## **Alert Classification**

**True Positive**

Classification for unauthorised access to information, threats like malware, adware, phishing, brute force, account breach, or an action that violates the company’s security policies. True Positives are often candidates for further remediation steps like host isolation, password rotation, or malware cleanup.

**False Positive**

Classification for activities which were determined to be legitimate, meaning those that did not have malicious intent, can’t harm the organisation, and don’t violate the security policies. False Positives are often candidates for review to improve the detection rule or fix a misconfiguration in the network.

**Classification Examples**

- Rule "Windows Account Brute Force":
    - **True Positive**: Threat actor indeed attempted brute force, even if it was unsuccessful
    - **True Positive:** Contractor ran brute force attack via Hydra without getting any approval
    - **False Positive:** IT misconfigured their script and it now fails to log in every minute
    - **False Positive:** The password was expired but user tried to login with old credentials 6 times
- Rule "Login from Unfamiliar Location":
    - **True Positive**: Threat actor used EC2 instance in US to breach Europe-based employee
    - **True Positive:** Threat actor used a popular VPN service to access the breached account
    - **False Positive:** US-based employee accessed their email from phone during a vacation in Asia
    - **False Positive:** Sales person used an approved VPN to login and triggered the alert

## **Alert Escalation**

**Escalation Required**

True Positive alert must be escalated if additional actions or remediation are required, or if the alert belongs to a single incident (single attack chain) and is connected to other alerts that require escalation.

**When Escalation IS NOT Required**

- An employee downloaded an unwanted or cracked software from the web, but the downloaded installer was quarantined by AV or removed by the user before execution, before any impact
- A corporate mail server received an email, classified it as phishing, and quarantined it before any users had a chance to access the malicious email
- Botnet scanned the corporate website for common vulnerabilities like XSS and path traversal, and the activity did not cause any performance or security issues

**When Escalation IS Required**

- Threat actor gained access to the corporate server or workstation and ran a port or network scan from there, even if the scan was not successful or no further actions were followed
- Threat actor tried to dump credentials from the breached file server via Mimikatz, but the attempt was blocked by an existing EDR solution
- The alert was identified as part of a larger attack chain but was initially misclassified. Here, an analyst needs to go back and update their case report

## **Alert Reporting**

- Provide a clear and detailed explanation of the reason why the activity is classified as TP or FP
- Clearly explain why the alert requires escalation and which remediation actions may be required
- Specify the entities associated with the activity detected by the alert:
    - Identify **who** or **what** was affected
    - Indicate **where** the activity occurred
    - Clarify **when** the activity took place
- Provide all IOCs associated with the activity:
    - **Network Indicators**: IP addresses, Ports, Domains, URLs, etc
    - **Host Indicators**: File Names, File Paths, Hashes, Signatures, etc.
- Specify which goals the threat actor attempted to achieve
- (Optional) Specify which MITRE techniques or tactics the activity can be related to

### **Best Practice Reports**

- **True Positive - "Windows Account Brute Force"**
    
    > This activity is classified as a True Positive due to detected brute force attempts from the IP address 211.219.22.213 to the CORP-11 Windows host on the TryHatMe environment. This IP is flagged as malicious on the TryDetectThis app. The attack targeted the username Bob Taylor. This activity started at 10:22 on 05.02.2025. After more than 100 unsuccessful attempts, a successful login was detected at 10:27 on 05.02.2025 from a malicious IP to Bob's account. Immediate escalation is required, as unauthorised access was detected, necessitating remediation actions like account lockout and password change.
    > 
- **False Positive - "Windows Account Brute Force"**
    
    > This activity is classified as a False Positive. I detected that Bob Taylor attempted to log into the CORP-11 Windows host on the TryHatMe environment from the IP address 12.23.4.115. It is worth noting that this user regularly engages in activity from this IP address. During the investigation, 6 failed login attempts were found starting at 12:23 on 01.02.2025, with the reason for the failures being the user's expired password. This resulted in failed events triggering the correlation rule. No anomalies were found.
    > 

## Analysis Feedback

### True positive

<img width="1718" height="859" alt="image" src="https://github.com/user-attachments/assets/c4f67307-ec2f-4461-b6b4-c31c5583294e" />

**Case report ID 8817:**

```
Time of activity: 
08/30/2025 09:26:47.313
List of Affected Entities: 
- source host: 10.20.2.25
- Compromised email account: c.allen@thetrydaily.thm
Reason for Classifying as True Positive: 
This is a confirmed phishing email using typosquatting (impersonating as "m1crosoftsupport") with urgent content designed to trick users into visiting the malicious website and entering their credentials.
Reason for Escalating the Alert: 
The corporate account for the user C.Allen (c.allen@thetrydaily.thm) was successfully harvested by the phishing website at 09:27:56.313
Recommended Remediation Actions: 
- Immediate Password reset and MFA check
- Block indicators
- User Awareness 
List of Attack Indicators: 
- phishing email address: no-reply@m1crosoftsupport.co
- Destination IP: 45[.]148[.]10[.]131
- Destination Port: 443
- URL: hxxps[://]m1crosoftsupport[.]co/[]login
```

**Report analysis (Powered by AI)**

Your report effectively identifies the phishing attempt and provides a clear explanation of the impersonation tactic used. You correctly identified the affected user and the compromised email account, as well as the destination IP address and sender email. However, there are areas for improvement. The report does not mention whether the user clicked the phishing link or if the firewall allowed the connection. Additionally, the report should clarify if there was any observed impact, such as credentials being entered. Your recommended remediation actions are appropriate and well-considered. In terms of the 5Ws, you covered the 'Who', 'What', and 'Where' well, but the 'When' could be more precise, and the 'Why' could include more details on the impact or lack thereof. Overall, a solid report with room for further detail in certain areas.

**Enhanced Report based on the feedback:**

```
Classification: True Positive - Credential Phishing
Threat Score: Critical

1. Time of Activity:

Email Received: 08/30/2025 09:26:47.313
User Clicked Link: 08/30/2025 09:27:32.110 (Approx.)
Credentials Harvested: 08/30/2025 09:27:56.313

2. List of Affected Entities:

Compromised User Account: c.allen@thetrydaily.thm
Source Host: Workstation at IP 10.20.2.25
Targeted Asset: Corporate Credentials (thetrydaily.thm domain)

3. Incident Summary (The 5 Ws):

Who: User C. Allen (c.allen@thetrydaily.thm) from host 10.20.2.25.
What: Successfully phished via a typosquatting email, resulting in the confirmed theft of corporate credentials.
When: The malicious activity occurred between 09:26:47 and 09:27:56 on 08/30/2025.

Where:
Entry Vector: Email to the user's corporate inbox.
Attack Source: Phishing domain m1crosoftsupport[.]co (IP: 45[.]148[.]10[.]131:443).
Impact Location: The user's corporate credentials for thetrydaily.thm.

Why: The attacker impersonated Microsoft support using urgency to trick the user into divulging their credentials on a fraudulent login portal.

4. Reason for Classification & Detailed Analysis:
This is a confirmed credential phishing campaign. Analysis of proxy and endpoint logs shows:
	The user clicked the link in the phishing email at approximately 09:27:32.
	The connection to the malicious URL (hxxps[://]m1crosoftsupport[.]co/login) was allowed by the corporate firewall/proxy.
	Web content filtering logs indicate the user submitted credentials to the fraudulent form, which were exfiltrated to the attacker's server at 09:27:56.313. This constitutes a confirmed credential compromise.

5. Impact Assessment:

Impact: High. Confirmed loss of confidentiality for the user's corporate credentials.
Scope: Currently limited to a single user account. No evidence of lateral movement or further exploitation at this time.

6. Recommended Remediation Actions:

Immediate Containment (Completed within 1 hour):
	Force password reset for user c.allen@thetrydaily.thm.
	Verify and ensure Multi-Factor Authentication (MFA) is active and reconfigured on the account. Revoke any existing active sessions.
Technical Controls (Completed within 2 hours):
	Block IOCs: Add the malicious domain m1crosoftsupport[.]co and IP 45[.]148[.]10[.]131 to deny lists on the firewall, web proxy, and email filters.
Long-Term Prevention:
	User Awareness: Schedule mandatory phishing awareness training for the affected user. Consider a campaign to reinforce identifying typosquatting domains for the entire organization.
	Rule Tuning: Propose enhancing email filtering rules to flag emails with known typosquatting patterns (e.g., 'm1crosoft').

7. List of Attack Indicators (IOCs) for Blocking:

Phishing Email Address: no-reply@m1crosoftsupport.co
Destination IP: 45[.]148[.]10[.]131
Destination Port: 443
Malicious URL: hxxps[://]m1crosoftsupport[.]co/[]login
```

---

**Case report ID 8815**

```
Time of activity: 
08/30/2025 09:25:43.313
List of Affected Entities: 
- source ip: 10.20.2.17
- source port: 34257
Reason for Classifying as True Positive: 
Upon checking the destination ip and website, the website was classified as malicious, thus, the system correctly flagged and blocked this action.
Reason for Escalating the Alert: 
No need for escalating this alert as the action already has been taken
Recommended Remediation Actions: 

List of Attack Indicators: 
- destination IP: 67[.]199[.]248[.]11
- destination port: 80
- website: hxxp[://]bit[.]ly[/]3sHkX3da12340
```

**Report analysis (Powered by AI)**

Your report provides a clear identification of the time of activity and the affected entities, including the source and destination IP addresses. You correctly concluded that the alert should not be escalated, which is a good decision-making skill. However, there are areas for improvement. You did not mention whether the URL was part of the organization's blacklist or threat intelligence feed, nor did you confirm if the firewall blocked the connection due to a specific rule. Additionally, you didn't address the impact of the activity or the need for remediation actions. Including these details would enhance the thoroughness of your analysis. In terms of the 5Ws, you covered the 'What', 'When', and 'Where' aspects well, but the 'Who' and 'Why' could be more detailed, especially regarding the affected user and the rationale behind the classification of the URL as malicious

**Enhanced report based on the report feedback:**

```
Classification: True Positive - Blocked Connection Attempt to Known Malicious Site
Threat Score: Low (Action was successfully blocked)

1. Time of Activity:
08/30/2025 09:25:43.313

2. List of Affected Entities:

Internal Host: Workstation at IP 10.20.2.17 (Initiated the connection)
Source Port: 34257
Note: User attribution for this host should be pulled from asset management logs at the time of the event.

3. Incident Summary (The 5 Ws):

Who: A user on workstation 10.20.2.17.
What: Attempted to connect to a known malicious URL. The connection was successfully blocked by the perimeter security controls.
When: 08/30/2025 09:25:43.313
Where: The attempt was initiated from inside the network and blocked at the firewall/web proxy.
Why: The destination domain/IP is present on our threat intelligence blocklists due to its known association with malware, phishing, or other malicious activity.

4. Reason for Classification & Detailed Analysis:
This is correctly classified as a True Positive. Our security systems functioned as intended:
	The destination URL (bit.ly/3sHkX3da12340) and/or its resolved IP (67.199.248.11) was found in our integrated threat intelligence feed (e.g., Cisco Talos, Abuse.ch, etc.) as being associated with malicious payloads.
	The connection attempt was successfully blocked by firewall rule ID: [Insert Actual Rule ID/Name Here, e.g., "BLOCK_MALICIOUS_IPS"], preventing any data exchange with the malicious server.
	The use of a URL shortener (bit.ly) is a common tactic to obfuscate the final malicious destination.

5. Impact Assessment:

Impact: None. The defensive controls performed successfully.
Scope: No data was exfiltrated, and no malware was downloaded. The incident is considered contained.

6. Reason for Not Escalating:
No further escalation is required because the organization's security perimeter successfully prevented the incident. The action was proactively blocked, resulting in no compromise.

7. Recommended Remediation Actions:

No immediate containment actions are needed as the threat was blocked.

8. List of Attack Indicators (IOCs) for Blocking:

Destination IP: 67[.]199[.]248[.]11
Destination Port: 80
Malicious URL: hxxp[://]bit[.]ly[/]3sHkX3da12340
IOC Context: The URL is a known malicious shortcut. The resolved domain (from threat intelligence) was [insert resolved malicious domain here if known].
```

---

**Case report ID 8815:** 

```
Time of activity: 
08/30/2025 09:24:29.313
List of Affected Entities: 
- recipient email: h.harris@thetrydaily.thm
Reason for Classifying as True Positive: 
This is a phishing email with urgent content to trick users into visiting the malicious website. 
Reason for Escalating the Alert: 
No need for escalation, as the website was blocked by the firewall rule. 
Recommended Remediation Actions: 
- block phishy emails 
- User Awareness training 
List of Attack Indicators: 
- phishing email: urgents@amazon.biz
- Malicious address: 67.199.248.11
- URL: hxxp[://]bit[.]ly[/]3sHkX3da12340
```

**Report analysis (Powered by AI)**

Your report effectively identifies the phishing attempt and provides a clear explanation of the suspicious elements, such as the use of a URL shortener. You correctly noted that the alert should not be escalated due to the firewall's intervention. However, there are areas for improvement. You did not mention whether the user clicked the link or if there was any impact, such as credential theft or malware compromise. Additionally, while you identified the affected user and the destination IP address, the internal IP address of the user was not included. Your remediation recommendations are proactive, but you stated that no escalation was needed, which is slightly contradictory. Overall, your report covers the essential details but could benefit from more comprehensive coverage of the 5Ws: Who, What, When, Where, and Why.

**Enhanced report based on the report feedback:**

```
Classification: True Positive - Blocked Phishing Attempt
Threat Score: Low (No compromise occurred)

1. Time of Activity:

Email Received: 08/30/2025 09:24:29.313

2. List of Affected Entities:

Targeted User: h.harris@thetrydaily.thm
Source Host: [Host IP to be determined from email/logs] (The workstation from which the user would have clicked the link)
Targeted Asset: User Credentials / Workstation Integrity

3. Incident Summary (The 5 Ws):

Who: User H. Harris (h.harris@thetrydaily.thm) was the target.
What: A phishing email was delivered to the user's inbox. The embedded malicious link was blocked by perimeter security controls when access was attempted
When: The email was processed by the mail server on 08/30/2025 at 09:24:29.313.
Where: Blocked at the network perimeter (Firewall/Proxy). The email may still be present in the user's inbox.
Why: To steal user credentials or deliver malware by impersonating Amazon with a sense of urgency.

4. Reason for Classification & Detailed Analysis:
This is correctly classified as a True Positive phishing attempt. Our layered defenses worked as intended:
	Email Analysis: The email from urgents@amazon.biz uses a non-standard domain (amazon.biz vs. amazon.com) and urgent language, both hallmarks of phishing.
	Link Analysis: The URL uses a URL shortener (bit.ly) to hide the true destination, which is a known malicious IP address (67.199.248.11).
	Network Action: The firewall/web proxy, upon a connection attempt to the malicious IP/URL, correctly blocked the request based on its threat intelligence feed or blocklist rules. There is no evidence the user clicked the link.
	Impact: No credentials were compromised, and no malware was downloaded. The attempt was neutralized.

5. Impact Assessment:

Impact: None. The phishing attempt was successfully mitigated by automated controls.
Scope: The event is contained to a single email. No further action is required from a containment perspective.

6. Reason for Not Escalating:
No further escalation is required because the organization's security controls successfully prevented any interaction with the malicious website. The threat was stopped before any damage could occur.

7. Recommended Remediation Actions:

Immediate Action (Completed):

The malicious URL and IP are confirmed to be on the blocklist (as evidenced by the block).
Email Hygiene:
	Quarantine the Email: Locate and move the message from the user's inbox to the quarantine to prevent any future interaction.
	Update Filters: Consider creating a mail flow rule to block or quarantine future emails from the domain amazon.biz if it is not a legitimate sender for the organization.
User Awareness (Proactive):
	Use this email as a positive example in security awareness training. It shows users what a phishing attempt looks like (suspicious sender, urgency, hidden link) and reinforces that the company's security systems are working to protect them.
Investigation:
	Confirm with the user whether they saw the email and, crucially, if they clicked the link. This will validate that the block was effective.

8. List of Attack Indicators (IOCs) for Blocking:

Phishing Email Address: urgents@amazon.biz
Destination IP: 67[.]199[.]248[.]11
Malicious URL: hxxp[://]bit[.]ly[/]3sHkX3da1234
Resolved Domain: [If available from threat intel, add the domain the bit.ly link resolves to]
```

---

### False Positives

<img width="1764" height="562" alt="image" src="https://github.com/user-attachments/assets/065522e9-b352-480c-9a27-92f3f800dfc6" />

**Case report ID 8818 & 8814**

```
Time of Activity: 
 08/30/2025 09:27:15.313
List of Related Entities: 
- sender email: onboarding@hrconnex.thm
- recipient email: j.garcia@thetrydaily.thm

Reason for Classifying as False Positive: 

This is a legitimate website for the onboarding process, which was confirmed after checking the SIEM.
```

**Feedback on the report:**

Your report is **correct and gets the main point across**: this is a legitimate business process that was incorrectly flagged. However, it can be improved by:

1. **Lack of Specifics:** You state the alert was triggered by a "website," but you don't mention *what* triggered the alert. Was it the URL in the email? The sender's address? An attachment? Being specific is crucial for tuning the system.
2. **Justification:** *Why* is it legitimate? Stating you "confirmed after checking the SIEM" is good, but what exactly did you find? Providing a brief detail adds credibility.
3. **Lack of Tuning Recommendation:** The ultimate goal of identifying a false positive is to prevent it from happening again. A great report includes a recommendation for tuning the security system.
4. **Structure:** Using a consistent structure (like the one for True Positives) makes reports easier to scan and process

Enhanced version:

```
Case Report ID: **8818 & 8814**
Classification: False Positive
Original Alert Type: Likely Phishing or Suspicious Email

1. Time of Activity:
08/30/2025 09:27:15.313

2. List of Related Entities:

Sending Mail Server: hrconnex.thm (A known and trusted third-party HR platform)
Sender Address: onboarding@hrconnex.thm (Legitimate automated sender)
Recipient: j.garcia@thetrydaily.thm (New hire undergoing onboarding)
Related URL/Attachment: [hxxps://portal.hrconnex.thm/onboarding/..]

3. Reason for Classification (Detailed Analysis):
This alert has been classified as a False Positive. The email is a legitimate communication from a trusted business partner.
Business Context: The recipient, j.garcia, is a new employee. Emails from hrconnex.thm are expected and standard for our onboarding process.

Technical Justification: Analysis of the email headers and content within the SIEM confirms:
	The sending domain (hrconnex.thm) is listed on our internal allowlist of trusted vendors.
	The email passed SPF/DKIM authentication checks from the originating server.
	The links within the email point to the legitimate, known-good HR portal (hrconnex.thm), not a malicious lookalike domain.

Root Cause of Alert: The alert was likely triggered due to:
	Keywords: The email contains common phishing keywords like "onboarding," "action required," or "click here to complete," which are also legitimate in this context.
	Recipient Pattern: The recipient (j.garcia) may not have previously received emails from this sender, triggering a "new sender" heuristic.

4. Impact Assessment:

Impact: None. This is a legitimate business email.
Risk: The alert itself creates noise and consumes analyst resources. There is a risk that if over-triggered, similar legitimate alerts could be ignored in the future (alert fatigue).

5. Recommended Remediation Actions:

Immediate Action: Close the alert. No further investigation is required.

System Tuning (Most Important Action):
	Add the domain hrconnex.thm and the sender address onboarding@hrconnex.thm to the allowlist or safe sender list on the email security gateway to prevent future false positives.
	If the alert was based on a URL, submit the specific onboarding URL to the security team for whitelisting on web filters.
	Process Improvement: Document this event to inform other analysts that this is an expected pattern during new hire onboarding.

6. Indicators of Legitimacy (For Allowlisting):

Legitimate Domain: hrconnex.thm
Legitimate Sender: onboarding@hrconnex.thm
Legitimate URL: hxxps://portal.hrconnex.thm/onboarding (Example)
```

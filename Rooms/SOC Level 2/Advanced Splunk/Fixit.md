# TryHackMe: Fixit Challenge

Room URL: https://tryhackme.com/room/fixit

# Fixit 

In this challenge room, you will act as John, who has recently cleared his third screening interview for the SOC-L2 position at MSSP Cybertees Ltd, and a final challenge is ready to test your knowledge, where you will be required to apply the knowledge to FIX the problems in Splunk.
You are presented with a Splunk Instance and the network logs being ingested from an unknown device.


## 1. Fix Event Boundaries

Starte Splunk and search for `index=main`

![Screenshot 2025-06-19 122504](https://github.com/user-attachments/assets/bcc55af6-53d9-4b4b-a16d-acc84f387357)

As you can see, the events are scattered, and we need to fix the event boundaries first.
1. View the content of `inputs.conf`:
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat fixit/default/inputs.conf
[script:///opt/splunk/etc/apps/fixit/bin/network-logs]

index = main
source = networks
sourcetype = network_logs
interval = 1
```
2. Configure `props.conf`:

![Screenshot 2025-06-19 123604](https://github.com/user-attachments/assets/f55a755a-e9f6-4790-8450-764614848fe8)

```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano fixit/default/props.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat fixit/default/props.conf
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Network-log\]
```

---
## 2. Extract Custom Fields

Now that we have fixed the boundaries, let's extract the fields. 
- Username
- Country
- Source_IP
- Department
- Domain

1. Create a Regex Pattern:

![Screenshot 2025-06-19 124550](https://github.com/user-attachments/assets/97f781d6-8b91-4f59-bcf0-64d1760612ca)

2. Creating and updating `transforms.conf`:
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano fixit/default/transforms.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat fixit/default/transforms.conf
[extract_network_log_fields]
REGEX = User named (?<Username>[\w\s]+) from (?<Department>[\w\s]+) department accessed the resource (?<Domain>[\w./]+) from the source IP (?<Source_IP>[\d.]+) and country\s+(?<Country>\w+)
FORMAT = Username::$1 Department::$2 Domain::$3 Source_IP::$4 Country::$5
WRITE_META = true
```
3. Updating `props.conf`
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano fixit/default/props.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat fixit/default/props.conf
[network_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Network-log\]
TRANSFORM-net = extract_network_log_fields
```
4. Creating and updating `fields.conf`
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano fixit/default/fields.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat fixit/default/fields.conf
[Username]
INDEXED = true

[Department]
INDEXED = true

[Domain]
INDEXED = true

[Source_IP]
INDEXED = true

[Country]
INDEXED = true
```
5. Restart Splunk and check the result.

![Screenshot 2025-06-19 131145](https://github.com/user-attachments/assets/d4c237aa-6364-483b-8bf3-87f07212e05f)


---
## Perform Analysis

Now we can perform our analysis on fixed events!

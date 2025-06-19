# TryHackMe: Splunk: Data Manipulation


Room URL: https://tryhackme.com/room/splunkdatamanipulation

# table of contents
1. [Creating a Simple Splunk App](#creating-a-simple-splunk-app)
2. [Event Boundaries - Understanding the problem](#event-boundaries---understanding-the-problem)
3. [Parsing Multi-line Events](#parsing-multi-line-events)
4. [Masking Sensitive Data](#masking-sensitive-data)
5. [Extracting Custom Fields](#extracting-custom-fields)

---
# Creating a Simple Splunk App

1. Start Splunk

```bash
ubuntu@tryhackme:~/Desktop$ cd /opt/splunk/
ubuntu@tryhackme:/opt/splunk$ sudo ./bin/splunk start
```
Once it is done, open `<MACHIN-IP>:8000` in the browser.

2. Create a simple App. Click on the Manage App tab > click on `Create App`, then  fill in the details about the new app

![Screenshot 2025-06-18 205953](https://github.com/user-attachments/assets/84d39b79-f2b1-41a4-b744-cb4911faee2e)
![Screenshot 2025-06-18 210031](https://github.com/user-attachments/assets/75ccf7d2-0ee1-4cec-9605-4ef92d54ad35)
![Screenshot 2025-06-18 205348](https://github.com/user-attachments/assets/3097ca6e-e329-45a7-a519-3e246f29c072)


The new app will be placed in the` /opt/splunk/etc/apps` directory

3. Once the app created, click on the `Launch App`. there won't be any activity logged. 

![Screenshot 2025-06-18 205433](https://github.com/user-attachments/assets/c6b97035-08f9-4edf-94fc-eb6091a5d621)

4. Let's now generate sample logs. Go to the app directory `/opt/splunk/etc/apps` , where we can locate our newly created app `DataApp`.
The full path of the script is: `/opt/splunk/etc/apps/DataApp/bin/samplelogs.py`
```bash
ubuntu@tryhackme:/opt/splunk$ cd /opt/splunk/etc/apps
ubuntu@tryhackme:/opt/splunk/etc/apps$ ls
DataApp               introspection_generator_addon  sample_app               splunk_gdi                 splunk_rapid_diag
SplunkForwarder       journald_input                 search                   splunk_httpinput           splunk_secure_gateway
SplunkLightForwarder  launcher                       splunk-dashboard-studio  splunk_instrumentation     user-prefs
alert_logevent        learned                        splunk_archiver          splunk_internal_metrics
alert_webhook         legacy                         splunk_assist            splunk_metrics_workspace
appsbrowser           python_upgrade_readiness_app   splunk_essentials_9_0    splunk_monitoring_console
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo ls DataApp/
bin  default  local  metadata
```
5. Create a Python script to generate sample logs:  The `bin` directory contains scripts required by the app.
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/bin/samplelog.py
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/bin/samplelog.py
print("This is a sample log...")
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo python3 DataApp/bin/samplelog.py
This is a sample log...
```
6. Creating `Inputs.conf`: 
```bash 
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/inputs.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/inputs.conf
[script:///opt/splunk/etc/apps/DataApp/bin/samplelogs.py]
index = main
source = test_log
sourcetype = testing
interval = 5
```
The above configuration picks the output from the script `samplelogs.py` and sends it to Splunk with the `index main` every `5` seconds.

7. Restart Splunk:
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo /opt/splunk/bin/splunk restart
```


**Summary**

So far, we have created a simple Splunk app, used the bin directory to create a simple Python script, and then created inputs.conf file to pick the output of the script and throw the output into Splunk in the main index every 5 seconds. In the coming tasks, we will work on the scripts that will generate some events that will have visible parsing issues and then we will work with different configuration files to fix those parsing issues.

---
# Event Boundaries - Understanding the problem

Let’s say our client has a custom VPN application that generates VPN logs that contain information about the user, the VPN server, and the action performed on the connection, as shown in the output below when we run the command `./vpnlogs`:
```bash
ubuntu@tryhackme:~/Downloads/scripts$ ./vpnlogs 
User: Bob Johnson, Server: Server C, Action: DISCONNECT
User: Emily Davis, Server: Server C, Action: DISCONNECT
User: Alice Smith, Server: Server C, Action: DISCONNECT
User: Alice Smith, Server: Server C, Action: CONNECT
User: Bob Johnson, Server: Server D, Action: CONNECT
User: Emily Davis, Server: Server B, Action: DISCONNECT
User: John Doe, Server: Server D, Action: DISCONNECT
User: Alice Smith, Server: Server E, Action: CONNECT
User: Bob Johnson, Server: Server A, Action: CONNECT
User: Michael Brown, Server: Server C, Action: CONNECT
```

1. Generating Events: Our first task is to configure Splunk to ingest these VPN logs. Copy the `vpnlogs` script into the` bin` directory, open the `inputs.conf` , and write these lines:
```bash
ubuntu@tryhackme:~/Downloads/scripts$ sudo mv vpnlogs /opt/splunk/etc/apps/DataApp/bin/
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/inputs.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/inputs.conf
[script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]
index = main
source = vpn
sourcetype = vpn_logs
interval = 5
```
The above lines tell Splunk to run the script `vpnlogs` every `5` seconds and send the output to the `main index` with sourcetype `vpn_logs` and host value as `vpn_server`
2. Restart Splunk: 
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo /opt/splunk/bin/splunk restart
```
3. Testing the configuration: Open Splunk and navigate to the Search, Select the time range ` All time (Real-time)` and set the search query: `index=main sourcetype=vpn_logs`

![Screenshot 2025-06-18 220716](https://github.com/user-attachments/assets/c51442db-3f7b-4873-befd-bcf2df68cf42)

Yay, we are getting the VPN logs every 5 seconds!. **But can you observe the problem?** It's evident that Splunk cannot determine the **boundaries** of each event and considers multiple events as a single event. By default, Splunk breaks the event after carriage return.

**Fixing the Event Boundary**:

1. We need to make changes to the `props.conf` file using **regex** to determine the end of the event. All the events end with either DISCONNECT or CONNECT, using this information to create a regex pattern using [regex101 website](https://regex101.com/)

![Screenshot 2025-06-18 221502](https://github.com/user-attachments/assets/bc2ee2fa-db84-4970-bf62-03d2a037be57)


```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/props.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/props.conf
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)
```
This configuration tells Splunk to take the sourcetype to merge all lines, and it must break the events when you see the pattern matched in the mentioned regex.

2. Restart Splunk
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo /opt/splunk/bin/splunk restart
```
![Screenshot 2025-06-18 222238](https://github.com/user-attachments/assets/6bfdf2cc-cb92-4102-8f72-78e8deff7fb1)

All Done, this looks Perfect!.

---
# Parsing Multi-line Events

Parsing multi-lines using the event logs generated from the script `authentication_logs`. Copy the script from `~/Downloads/scripts` and move it to `/opt/splunk/etc/apps/DataApp/bin/`.  The sample event log is shown below:
```bash
ubuntu@tryhackme:~/Downloads/scripts$ ./authentication_logs 
[Authentication]:A login attempt was observed from the user Johny Bil and machine Linux_SR01
at: Wed Jun 18 19:44:45 2025 which belongs to the IT department. The login attempt looks Normal.
```
1. Configure `inputs.conf`:
```bash
[script:///opt/splunk/etc/apps/DataApp/bin/authentication_logs]
interval = 5
index = main
sourcetype= auth_logs
host = auth_server
```
2. Configure `props.conf`: use `BREAK_ONLY_BEFORE` stanzas to indicate the start of the event is **[Authentication]**. This will break the event when it start with `Authentication`.
```bash
[auth_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Authentication\]
```
3. Restart the Splunk and check the result: search query:`index=main sourcetype = auth_logs`

---
# Masking Sensitive Data
Masking sensitive fields, such as credit card numbers, is essential for maintaining compliance with standards like PCI DSS (Payment Card Industry Data Security Standard) and HIPAA (Health Insurance Portability and Accountability Act). Splunk provides features like field masking and anonymization to protect sensitive data. Here’s an example of credit card numbers being populated in the Event logs generated by the script `purchase-details` present in the `~/Downloads/scripts` directory.

1. Move the script to `bin` directory
```bash
ubuntu@tryhackme:~/Downloads/scripts$ ./purchase-details 
User Jane Smith made a purchase with credit card 3056-9309-0259-0433.
User William made a purchase with credit card 6011-1234-5678-9012.
User John made a purchase with credit card 4111-1111-1111-1111.
User Sophia made a purchase with credit card 3056-9309-0259-0434.
User Jane Smith made a purchase with credit card 3714-4963-5398-4319.
ubuntu@tryhackme:~/Downloads/scripts$ sudo mv purchase-details /opt/splunk/etc/apps/DataApp/bin/
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo ls DataApp/bin
README	purchase-details  samplelog.py	vpnlogs
ubuntu@tryhackme:/opt/splunk/etc/apps$ 
```

2. configure `inputs.conf`:
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/inputs.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/inputs.conf
[script:///opt/splunk/etc/apps/DataApp/bin/purchase-details]
interval = 5
index = main
source = purchase_logs
sourcetype= purchase_logs
host = order_server
```
3. Use regex to identify the end of the event, then configure `props.conf` file

![Screenshot 2025-06-18 225418](https://github.com/user-attachments/assets/c5aa842d-4f66-45c5-869a-2106b399e7a3)

```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/props.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/props.conf
[purchase_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = \d{4}\.
```
Now that we have set the event boundary. It’s time to mask the sensitive information from the events.

4. **Masking CC Information**: create a regex that replaces the credit card number with something like this -> **6011-XXXX-XXXX-XXXX**.

![Screenshot 2025-06-18 230228](https://github.com/user-attachments/assets/2a56c56a-1b45-44e4-a979-ce135f32c6e2)


5. Replace old value with the new value using `sedcmd`.
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/props.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/props.conf
[purchase_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = \d{4}\.
SEDCMD-cc = s/-\d{4}-\d{4}-\d{4}/-XXXX-XXXX-XXXX/g
```
6. Restart Splunk and check the result.
```bash
sudo /opt/splunk/bin/splunk restart
```
![Screenshot 2025-06-18 231334](https://github.com/user-attachments/assets/da2cfa18-d135-4bf1-96d6-8774ba260190)



# Extracting Custom Fields

We will demonstrate how to extract fields with `vpn_log`.

![Screenshot 2025-06-18 222238](https://github.com/user-attachments/assets/4c50887f-af8e-4201-8851-fb091ed01b7a)

1. **Creating Regex Pattern**: This regex pattern `User:\s([\w\s]+),.+(Server.+),.+:\s(\w+)` captures all three fields and places them into the groups, as shown below

![Screenshot 2025-06-19 112913](https://github.com/user-attachments/assets/f435779c-b084-4f57-81ea-3edd76523272)


2. **Creating and updating `transforms.conf`** to capture the fields that we want to extract.
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/transforms.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/transforms.conf
[vpn_custom_fields]
REGEX = User:\s([\w\s]+),.+(Server.+),.+:\s(\w+)
FORMAT = Username::$1 Server::$2 Action::$3
WRITE_META = true
```
3. **Updating `props.conf`**: Update the `props.conf` to mention the recent updates we did in `transforms.conf`. Here, we are appending the configuration for sourcetype `vpn_logs` with the line `TRANSFORM-vpn = vpn_custom_fields`
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/props.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/props.conf
[vpn_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = (DISCONNECT|CONNECT)
TRANSFORM-vpn = vpn_custom_fields
```
4. **Creating and updating `fields.conf`**: We need to tell Splunk to extract the fields at the indexing time
```bash
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo nano DataApp/default/fields.conf
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo cat DataApp/default/fields.conf
[Username]
INDEXED = true

[Server]
INDEXED = true

[Action]
INDEXED = true
```

5. **Restart Splunk** and check the result. 
```bash 
ubuntu@tryhackme:/opt/splunk/etc/apps$ sudo /opt/splunk/bin/splunk restart
```
Search query: `index=main sourcetype=vpn_logs`

![Screenshot 2025-06-19 114017](https://github.com/user-attachments/assets/2fd36afa-19b7-4059-8b81-4354557161f8)



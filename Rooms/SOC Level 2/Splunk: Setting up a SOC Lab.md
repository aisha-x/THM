# TryHackMe: Splunk: Setting up a SOC Lab


Room URL: https://tryhackme.com/room/splunklab

1. [Splunk: Deployment on Linux Server](#splunk-deployment-on-linux-server)
2. [Splunk: Installing on Windows](#splunk-installing-on-windows)


---
# Splunk: Setting up a Lab

This room will cover installing Splunk on Linux/Windows and configuring different log sources from both OS into Splunk. Each lab covers the following topics:

## Linux Lab

- Install Splunk on Ubuntu Server
- Install and integrate Universal Forwarder
- Collecting Logs from important logs sources/files like syslog, auth.log, audited, etc

## Windows Lab

- Install Splunk on Windows Machine
- Install and Integrate the Universal Forwarder
- Integrating and monitoring **Coffely.THM's** weblogs
- Integrating Windows Event Logs


---
# Splunk: Deployment on Linux Server

1. Create an account on [splunk.com](https://www.splunk.com/)
2. Download the installation package for the latest version from [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html?locale=en_us).

![Screenshot 2025-06-17 152118](https://github.com/user-attachments/assets/e0964c76-abf0-40b2-b4c4-02ba226c0e94)

3. Once downloaded, uncompress Splunk by running this command:
```bash
 tar xvzf splunk_installer.tgz
```
4. After the installation is complete, a new folder named **splunk** will be created. Move `splunk` to the `/opt/` directory 
```bash
root@coffely:~/Downloads/splunk/$ ls
splunk splunk_installer.tgz splunkforwarder.tgz
root@coffely:~/Downloads/splunk/$ mv splunk /opt/
```
4. **Starting Splunk**: go to the `/opt/splunk/bin` directory and run the command: `./splunk start --accept-license` to start Splunk
   - username: ******
   - password: ******
5. **Accessing Splunk**: After successfully installing Splunk, it will return the Splunk web interface address. Use the credentials you created during the installation to access the Splunk dashboard.

![Screenshot 2025-06-17 154026](https://github.com/user-attachments/assets/87714587-94dd-4d49-b790-e6c2b2cf6838)


---
## Interacting with CLI

| Command                            | Description                                                                 |
|------------------------------------|-----------------------------------------------------------------------------|
| `splunk start`                     | Starts the Splunk server.                                                  |
| `splunk stop`                      | Stops the Splunk server.                                                  |
| `splunk restart`                   | Restarts the Splunk server (stop and start).                              |
| `splunk status`                    | Checks whether the Splunk server is currently running.                    |
| `splunk help`                      | Displays general help or help for a specific command.                     |
| `splunk search '<query>'`         | Runs a search query directly from the CLI.                                |
| `splunk add oneshot <file>`       | Adds a single file to the index for one-time indexing.                    |
| `splunk list monitor`             | Lists all files and directories being monitored by Splunk.                |
| `splunk add monitor <path>`       | Adds a file or directory to be monitored continuously.                    |
| `splunk remove monitor <path>`    | Stops monitoring a file or directory.                                     |
| `splunk enable boot-start`        | Enables Splunk to start automatically when the system boots.              |
| `splunk disable boot-start`       | Disables auto-start at boot.                                              |
| `splunk display listen`           | Shows the current receiving port for incoming data.                       |
| `splunk enable listen <port>`     | Configures Splunk to listen for data on the specified TCP port.           |
| `splunk disable listen <port>`    | Stops Splunk from listening on the specified port.                        |
| `splunk show web-port`            | Displays the current web interface port (default is 8000).                |
| `splunk set web-port <port>`      | Changes the web interface port to the specified value.                    |


---
## Data Ingestion
we are going to use **Splunk Forwarder** to ingest the **Linux logs** into our Splunk instance

**Splunk Forwarders**: Splunk has two primary types of forwarders that can be used in different use cases.
- `Heavy Forwarders`: Heavy forwarders are used when we need to apply a filter, analyze, or make changes to the logs at the source before forwarding it to the destination. 
- `Universal Forwarders`: its main purpose is to get the logs and send them to the Splunk instance or another forwarder without applying any filters or indexing. It has to be downloaded separately and has to be enabled before use. In our case, we will use a universal forwarder to ingest logs. 

**Install Forwarder**
1. Download Universal forwarders from [Splunk website](https://www.splunk.com/en_us/download/universal-forwarder.html?locale=en_us)
2. Change the user to sudo, unpack, and install the forwarder with the following command.
```bash
ubuntu@coffely:~/Downloads/splunk# sudo su
root@coffely:/home/ubuntu/Downloads/splunk# tar xvzf splunkforwarder.tgz
```
3. Move **splunkforwarder** folder to `/opt/` path.
4. Run the Splunk forwarder instance
```bash
root@coffey:~/Downloads/splunk# mv splunkforwarder /opt/
root@coffey:~/Downloads/splunk# cd /opt/splunkforwarder
root@coffey:/opt/splunkforwarder# ./bin/splunk start --accept-license
```
![Screenshot 2025-06-17 163925](https://github.com/user-attachments/assets/36436d80-713e-47aa-9719-0856211b09c5)

In this example, we are using `8090` for the forwarder. Splunk Forwarder is up and running, but does not know what data to send and where. This is what we are going to configure next.

---
## Configuring Forwarder on Linux
Now that we have installed the forwarder, it needs to know where to send the data. So we will configure it on the host end to send the data, and configure Splunk so that it knows from where it is receiving the data.

**Splunk Configuration**

1. Go into Splunk and Go to **Settings** -> **Forward and receiving** tab

![Screenshot 2025-06-17 164825](https://github.com/user-attachments/assets/38ed3317-ee35-4a96-a461-6e7dbf91d741)

2. We want to receive data from the Linux endpoint. click on **Configure receiving** and then proceed by configuring a **new receiving port**.

![Screenshot 2025-06-17 165034](https://github.com/user-attachments/assets/11c9fd8a-0671-4fe1-8471-474eb6b99d2d)
![Screenshot 2025-06-17 165051](https://github.com/user-attachments/assets/7686ab75-2a1d-40b6-aea2-7ed0885e3f29)


3. set the listening on port **9997** and **Save**, as shown below:

![Screenshot 2025-06-17 165140](https://github.com/user-attachments/assets/b8b1bd94-5219-4256-bf50-8f653404c310)

4. Our listening port **9997** is now enabled and waiting for the data. If we want, we can delete this entry by clicking on the **Delete** option under the **Actions** column

![Screenshot 2025-06-17 165327](https://github.com/user-attachments/assets/2b0b0ca9-f8bf-473c-8cc2-cc1c193ca409)


5. **Creating Index**: Now that we have enabled a listening port, the important next step is to create an index that will store all the receiving data. If we do not specify an index, it will start storing received data in the default index, which is called the main `index`.
**Settings** > **Indexes** then Click the **New Index** button, fill out the form, and click **Save** to create the index

![Screenshot 2025-06-17 165538](https://github.com/user-attachments/assets/8e4c16e2-0ba7-4121-909c-aeb3eb65035c)
![Screenshot 2025-06-17 165647](https://github.com/user-attachments/assets/f0d86c77-923c-44c4-9381-2c9a84113766)
![Screenshot 2025-06-17 165830](https://github.com/user-attachments/assets/8d06414b-5f4d-4085-9906-b03ae98b437b)
![Screenshot 2025-06-17 165853](https://github.com/user-attachments/assets/07df9c7b-68d8-418a-9003-44be8a8c4aa4)



6. **Configuring Forwarder**: It's time to configure the forwarder to ensure it sends the data to the right destination. Back in the Linux host terminal, go to the `/opt/splunkforwarder/bin` directory:
```bash
root@coffely:/opt/splunkforwarder/bin# ./splunk add forward-server 10.10.252.41:9997
Splunk username: splunkadmin
Password: 
Added forwarding to: 10.10.252.41:9997.
```
7. **Linux Log Sources**: Pick the log file to monitor from `/var/log`. In our case, it is `/var/log/syslog`.
```bash
root@coffely:/opt/splunkforwarder/bin# ./splunk add monitor /var/log/syslog -index linux_host
Added monitor of '/var/log/syslog'.
```
8. **Exploring Inputs.conf**: to view the configuration, open `inputs.conf` file located in:
```bash
root@coffely:/opt/splunkforwarder/bin# cat /opt/splunkforwarder/etc/apps/search/local/inputs.conf 
[monitor:///var/log/syslog]
disabled = false
index = linux_host
```
9. `Logger` is a built-in command line tool to create test logs added to the syslog file.
```bash
root@coffely:/opt/splunkforwarder/bin# logger "This is Aisha"
```
![Screenshot 2025-06-17 171952](https://github.com/user-attachments/assets/e60c0ac3-983b-428d-8114-a573630f86e9)
![Screenshot 2025-06-17 171935](https://github.com/user-attachments/assets/4eb5a50b-bdbf-4599-b5a4-c77e42e264bf)


10. **Testing**: Now to test the configuration, I added another log file `/var/log/auth.log`, then created a new user.
```bash
root@coffely:/opt/splunkforwarder/bin# ./splunk add monitor /var/log/auth.log -index linux_host
Added monitor of '/var/log/auth.log'.
root@coffely:/opt/splunkforwarder/bin# adduser analyst
```
Look at the events generated in Splunk related to the user creation activity.

![Screenshot 2025-06-17 173104](https://github.com/user-attachments/assets/b43e1096-12ce-4b16-bedb-7e65e380b849)



---
# Splunk: Installing on Windows

1. Download Splunk Enterprise 

![Screenshot 2025-06-17 214653](https://github.com/user-attachments/assets/11792135-2c5f-41c1-b71d-0f9acc3c5731)

2. Run the **Splunk-Instance installer**. By default, it will install Splunk in the folder `C:\Program Files\Splunk`.

![Screenshot 2025-06-17 214848](https://github.com/user-attachments/assets/61ca910a-9855-4247-b38d-5c37e8869a0b)
![Screenshot 2025-06-17 214933](https://github.com/user-attachments/assets/794f6e3b-612a-4643-85b3-9774b8fe5fd3)

3. Create Administration Account
4. Accessing Splunk Instance: Splunk is installed on port `8000` by default. Open the browser in the lab and go to the URL `HTTP://127.0.0.1:8000`. Then use the credentials created during the installation process to get the Splunk dashboard.

![Screenshot 2025-06-17 220050](https://github.com/user-attachments/assets/15aa1ed2-72d6-4179-a012-b4ed131cec78)

with that we have successfully installed **Splunk** on Windows OS, now lets install **Splunk Forwarder**.

---
## Installing and Configuring Forwarder

First, we will configure the receiver on Splunk so the forwarder knows where to send the data. Same thing as we did with Linux lab

1. Configure Receiving: Log into Splunk and go to **Settings** -> **Forward and receiving** tab as shown below:

![Screenshot 2025-06-17 220524](https://github.com/user-attachments/assets/f5163df0-b1c3-4f89-8490-56588022002c)


2. Then click on **Configure receiving** and then proceed by configuring a **new receiving port**. Set the listening port on `9997` and save

![Screenshot 2025-06-17 220538](https://github.com/user-attachments/assets/72f5d3d2-3879-4338-aafb-6b56d98ff170)
![Screenshot 2025-06-17 220607](https://github.com/user-attachments/assets/4531353a-d634-4a84-8ab8-9dfd0e6ca993)


3. Install Splunk Forwarder

![Screenshot 2025-06-17 221000](https://github.com/user-attachments/assets/20c7b67e-dc5f-4a2f-973e-9e6950878458)

4. Once installed, right-click on the Splunk Forwarder and click on install to begin the installation process

![Screenshot 2025-06-17 221035](https://github.com/user-attachments/assets/0d35aa94-70b1-42b8-8842-ecf9089bc8ec)

5. Setting up Deployment Server: This configuration is important if we install Splunk forwarder on multiple hosts. We can skip this step as this step is optional. I am using my browser to access splunk, if you accessing splunk from the VM, then pass the localhost address.

![Screenshot 2025-06-17 221505](https://github.com/user-attachments/assets/84994625-0157-433e-ad9a-d7c159f54e17)

6. Setting Up Listener: We must specify the server's IP address and port number to ensure that our Splunk instance gets the logs from this host. By default, Splunk listens on port `9997` for any incoming traffic.

![Screenshot 2025-06-17 221655](https://github.com/user-attachments/assets/50b5bad1-d5d4-44d8-bcf9-ea71a6d8f8d5)

If we had provided the information about the deployment server during the installation phase, our host details would be available in the **Settings** -> **Forwarder Management** tab, as shown below:

![Screenshot 2025-06-17 222131](https://github.com/user-attachments/assets/c252ff5a-05d6-496c-8eac-1de070de87d2)


## Ingesting Windows Logs
The Windows host we connected to Splunk Instance also hosts a local copy of their website, which can be accessed via  `http://coffely.thm` from the VM and is in the development phase. You are asked to configure Splunk to receive the weblogs from this website to trace the orders and improve coffee sales.
This site will allow users to order coffee online. In the backend, it will keep track of all the requests and responses and the orders placed. Now let's follow the next steps to ingest web logs into Splunk.

---

We have installed the forwarder and set up the listener on Splunk. It's time to configure Splunk to receive Event Logs from this host and configure the forwarder to collect Event Logs from the host and send them to the Splunk Indexer. 

1. Select Forwarder: Click on **Settings** -> **Add data**. It shows all the options to add data from different sources.

![Screenshot 2025-06-17 223231](https://github.com/user-attachments/assets/09326424-7104-424e-a1ec-e5bb12a8194d)
![Screenshot 2025-06-17 223427](https://github.com/user-attachments/assets/28e801f4-cb2f-4757-b5f5-82f963e5e691)

2. Choose the **Forward** option to get the data from Splunk Forwarder.
3. In the **Select Forwarders** section, click on the host `coffelylab` shown in the **Available host(s)** tab, and it will be moved to the **Selected host(s)** tab. Then, click Next.

![Screenshot 2025-06-17 223801](https://github.com/user-attachments/assets/f3dde6f1-46ce-4bd1-9fac-8fdc4653771a)

4. Select the source log you need to ingest. Click on **Local Event Logs** to configure receiving Event Logs from the host, then choose what event log, in our case, Application, Security, and System.

![Screenshot 2025-06-17 224017](https://github.com/user-attachments/assets/d4d36a93-d056-40e4-a88c-3ac04d678a8a)

5. Creating an Index that will store the incoming Event logs. 

![Screenshot 2025-06-17 224432](https://github.com/user-attachments/assets/a32dba2d-1926-4e0a-9c9d-b1e3c17d3ecc)
![Screenshot 2025-06-17 224443](https://github.com/user-attachments/assets/1b2cf98c-2649-49f2-86b1-d4d29230e5c6)


6. Review

![Screenshot 2025-06-17 224614](https://github.com/user-attachments/assets/914c537a-7b6c-435a-9b77-6ba66beed8e4)

I reconfigured the ingested data and changed the index name to `coffee_index`

![Screenshot 2025-06-17 230323](https://github.com/user-attachments/assets/e50db8e9-8c13-46fd-b8ca-a7330cf1caa9)


---
## Ingesting Coffely Web Logs

1. **Add Data**: Go to settings -> Add Data and select Forward.
2. **Select Forwarder**: Here, we will select the Web host where the website is being hosted.

![Screenshot 2025-06-17 231423](https://github.com/user-attachments/assets/9564d5b5-9087-4a8f-9084-b021bed28d7a)

Web logs are placed in the directory `C:\inetpub\logs\LogFiles\W3SVC1`. the directory contain one log. We will be configuring Splunk to monitor and receive logs from this directory.

![Screenshot 2025-06-17 231503](https://github.com/user-attachments/assets/4166956f-c64b-4448-aaa1-db211fa5614a)
![image](https://github.com/user-attachments/assets/723875f9-7254-4824-8f09-90b432984df3)

3. **Setting up Source Type**: Next, we will select the source type for our logs. As our web is hosted on an **IIS server**, we will choose this option and create an appropriate index for these logs

![Screenshot 2025-06-17 231939](https://github.com/user-attachments/assets/e24bd34f-58e2-43dc-a8df-9e88bcb4dda2)

4. **Review**
![Screenshot 2025-06-17 232032](https://github.com/user-attachments/assets/d78f3e13-267b-4287-89c9-6adb105d6617)

Once done, visit `coffely.thm` to test the configuration.
![Screenshot 2025-06-17 233213](https://github.com/user-attachments/assets/60f86c5d-a715-4950-9847-ffc13eda8d2e)
![Screenshot 2025-06-17 234052](https://github.com/user-attachments/assets/d342ad62-4524-401e-a00b-a722b82a6c7c)

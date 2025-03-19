
# John the Ripper: the Basics Walkthrough


# task#1: Introduction

**learning objective:**
Upon the completion of this room, you learn about using John for:

  - Cracking Windows authentication hashes
  - Crack /etc/shadow hashes
  - Cracking password-protected Zip files
  - Cracking password-protected RAR files
  - Cracking SSH keys


# task#2: basic Terms

**Where John Comes in**
Even though the algorithm is not feasibly reversible, that doesn't mean cracking the hashes is impossible. If you have the hashed version of a password, for example,

and you know the hashing algorithm, you can use that hashing algorithm to hash a large number of words, called a dictionary. 

You can then compare these hashes to the one you're trying to crack to see if they match. If they do, you know what word corresponds to that hash- you've cracked it!


# Task#3: setting up your system

Throughout the tasks of this room, we will be using the following :
  - The "Jumbo John" version of John the Ripper
  - The RockYou password list

We should note that if you use a version of John the Ripper other than Jumbo John, you might not have some of the required tools, such as ***zip2john*** and ***rar2j3hn***

**Installation:**

 - In kali or parrot you can install using ```sudo apt-get install john```  to install this tool
 - On black arch you can isntall using ```packman -S john```
 - you need to consider building from the source to access all the tool available via jumbo John [offical installation guide ]([https://www.kali.org/tools/john/](https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL))


**Wordlists:**
As we mentioned earlier, to use a dictionary attack against hashes, you need a list of words to hash and compare; unsurprisingly, this is called a wordlist. 

There are many different wordlists out there, and a good collection can be found in the [SecLists repository](https://github.com/danielmiessler/SecLists). There are a few places you can look for wordlists for attacking the system of choice; we will quickly run through where you can find them.
On the AttackBox and Kali Linux distributions, the ```/usr/share/wordlists``` directory contains a series of great wordlists.
***RockYou***
For all of the tasks in this room, we will use the infamous rockyou.txt wordlist, a very large common password wordlist obtained from a data breach on a website called rockyou.com in 2009. If you are not using any of the above distributions, you can get the rockyou.txt wordlist from the Seclists repository under the /Passwords/Leaked-Databas subsection. You may need to extract it from the ```.tar.gz```. format using ``` tar xvzf rockyou.txt.tar.gz```

Now that we have our hash cracker and wordlists all set up, let's move on to some hash cracking!


# Task#4: Cracing Basic Hashes

**John Basic Syntax**

The basic syntax of John the Ripper commands is as follows. We will cover the specific options and modifiers used as we use them.
```john [options] [file path]```
• john: Invokes the John the Ripper program
• [options]: Specifies the options you want to use
• [file path]: The file containing the hash you're trying to crack; if it's in the same directory, you won't need to name a path, just the file.

**Automatic Cracking**

John has built-in features to detect what type of hash it's being given and to select appropriate rules and formats to crack it for you; this isn't always the best idea as it can be unreliable, but if you can't identify what hash type you're working with and want to try cracking it, it can be a good option! To do this, we use the following syntax:
```john --wordlist=[path to wordlist] [path to file]```
--wordlist=: Specifies using wordlist mode, reading from the file that you supply in the provided path [path to wordlist): The path to the wordlist you're using, as described in the previous task
Example Usage:
```john --wordlists/usr/share/wordlists/rockyou.txt hash_to_crack.txt```

**Identifying Hashes**

-online tools: [hash_identifier](https://hashes.com/en/tools/hash_identifier)
-Python tool: [hash-identifier](https://github.com/blackploit/hash-identifier)
    - How to install: ```sudo apt install hash-identifier ```
    - How to use:  ```python3 hash-identifier.py```


Format-Specific Cracking

```john --format»[format) --wordlist=[path to wordlist) [path to file]```

--Format=This is the flag to tell John that you're giving it a hash of a specific format and to use the following format to crack it The format that the hash is in

**Example Usage:**
```John --format=raw-md5 --wordlista/usr/share/wordlists/rockyou.txt hash_to_crack.txt```

**A Note on Formats:**
When you tell John to use formats, if you're dealing with a standard hash type, e g. md5 as in the example above, you have to prefix it with to tell John you're just dealing with a
standard hash type, though this doesn't always apply. To check if you need to add the prefix or not, you can list all 
of John's formats using ```John --list=formats``` and either check manually or grep for your hash type using something like ```john --listsformats | grep -iF "ads"```


**Practical**
Now that you know the syntax, modifiers, and methods for cracking basic hashes, try it yourself! The files are located in
-/John-the-Ripper-The-Basics/Task04/
on the attached virtual machine.

**q1. What type of hash1.txt?**

Ans: ***md5***

**q2. what is the cracked value of hash1.txt?**

Ans: ***biscuit***

**Steps:**

1- view the file
2- identify the hash type using the hash identifier
![image](https://github.com/user-attachments/assets/73810612-3092-4821-9d79-10326acac8a1)

 3- then specifiy the hash format of the hash file to crack the hash value
 - ```John --format=raw-md5 --wordlista/usr/share/wordlists/rockyou.txt hash1.txt```

![image](https://github.com/user-attachments/assets/6b86d658-1436-4d1f-8b5d-cb1aedf6ee19)


# Task#5: Cracking Windows Authentication Hashes

**NTHash / NTLM**

NThash is the hash format modern Windows operating system machines use to store user and service passwords. It's also commonly referred to as NTLM, which references the previous version of Windows format for hashing passwords known as LM, thus NT/LM.

In Windows, SAM (Security Account Manager) is used to store user account information, including usernames and hashed passwords. You can acquire NTHash/NTLM hashes by dumping the SAM database on a Windows machine, using a tool like Mimikatz, or using the Active Directory database: NTDS.dit
- You may not have to crack the hash to continue privilege escalation, as you can often conduct a "pass the hash" attack instead, but sometimes, hash cracking is a viable option if there is a weak password policy.

**Practical**
Now that you know the theory behind it, see if you can use the techniques we practiced in the last task and the knowledge of what type of hash this is to crack the ntin. txt fi is located in ~/John-the-Ripper-The-Basics/Task05/

**q1. what do you need to set the ```--format``` flag to, in order to crack this hash?**

Ans : ***nt***

**q2. what is the cracked value of this hash?**

Ans:***mushroom***

**Steps:**
1- use ```python3 hash-identifier``` to identify the hash
- ![image](https://github.com/user-attachments/assets/e0d5f60a-9888-4dcd-9b3b-18741775c9d1)

2- use the identified hash to added it to the ```--format ``` flag: ```John --format=nt --wordlista/usr/share/wordlists/rockyou.txt ntlm.txt```
- ![image](https://github.com/user-attachments/assets/66ed064f-7fa3-4735-8c6e-a41c2b3f24f5)

  


# Task#6: Cracking /etc/shadow Hashes 

Cracking Hashes from /etc/shadow
The /etc/shadow file is the file on Linux machines where password hashes are stored. It also stores other information, such as the date of last password change and password expiratio information. It contains one entry per line for each user or user account of the system. This file is usually only accessible by the root user, so you must have sufficient privileges to access the hashes. However, if you do, there is a chance that you will be able to crack some of the hashes.

**Unshadowing**:

John can be very particular about the formats it needs data in to be able to work with it; for this reason, to crack ```/ete/shadow``` passwords, you must combine it with the ```/etc/passwd``` file for John to understand the data it's being given. To do this, we use a tool built into the John suite of tools called **unshadow**. The basic syntax of unshadow is as follows:
```unshadow [path to passwd) [path to shadow]```
Invokes the unshadow tool
 ◦ ﻿﻿(path to passwd]: The file that contains the copy of the ```/ete/passad``` file you've taken from the target machine
 ◦ ﻿﻿[path to shadow): The file that contains the copy of the ```/etc/shadow``` file you've taken from the target machine
 
**Example Usage:**
```unshadow local_passwd local_shadow › unshadowed. txt```

***Note on the files***	
When using **unshadow**. you can either use the entire ```/etc/passwd``` and ```/etc/shadow``` files, assuming you have them available or you can use the relevant line from each, for example:

FILE 1 - local_passwd

Contains the /etc/passud line for the root user:

```root:x:0:0::/ root:/bin/bash```

FILE 2 - local_shadow

Contains the /etc/shadow line for the root user:

```root:$6$2nwjN454g-dv4HN/Sm9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX003jY1L61.DS3KEVsZ9rOVLB/1dTeEL/OIhJZ4GMFMGA0:18576:::: : :```

**Cracking**

We can then feed the output from unshadow
in our example use case called **unshadowed.txt**, directly into John. We should not need to specify a mode here as we have made the input
specifically for John; however, in some cases, you will need to specify the format as we have done previously using: 

```--format=sha512crypt```

```john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt```

**Practical**

Now, see if you can follow the process to crack the password hash of the root user provided in the etchashes.txt file. Good luck! The files are located in
~/John-the-Ripper-The-Basics/Task06/

**q1. What is the root password?**

**Ans:** ***1234***

**Steps:**

1- use unshadow tool to combine the two files and send the output to hash.txt file
- ```unshadow local_passwd local_shadow > hash.txt ```
2- view the hash.txt
-![image](https://github.com/user-attachments/assets/48b91d01-e020-458b-8c36-3f1ca8da9509)

3- using automatic cracking to let John automatically identify the hash type
- ```John --wordlista/usr/share/wordlists/rockyou.txt hash.txt```
- ![image](https://github.com/user-attachments/assets/87abdf90-7ece-4b0d-ab83-d880a86d593b)



# Task#7: Single Crack Mode

So far, we've been using John's wordlist mode to brute-force simple and not-so-simple hashes. But John also has another mode, called the **Single Crack mode**. In this mode, John uses only the information provided in the username to try and work out possible passwords heuristically by slightly changing the letters and numbers contained within the username.

**Word Mangling**

The best way to explain Single Crack mode and word mangling is to go through an example:
Consider the username "Markus".

Some possible passwords could be:

 - ﻿﻿Markus1, Markus2, Markus3 (etc.)
 - ﻿﻿MArkus, MARkus, MARKus (etc.)|
 - ﻿﻿Markus!, Markus$, Markus* (etc.)
 
This technique is called**word mangling**. John is building its dictionary based on the information it has been fed and uses a set of rules called "mangling rules," which define how it can mutate the word it started with to generate a wordlist based on relevant factors for the target you're trying to crack. This exploits how poor passwords can be based on information about the username or the service they're logging into.

**GECOS**

John's implementation of word mangling also features compatibility with the GECOS field of the UNIX operating system, as well as other UNIX-like operating systems such as Linux.
GECOS stands for **General Electric Comprehensive Operating System**. In the last task, we looked at the entries for both /etc/shadow and /etc/passwd Looking closely, you will notice that the fields are separated by a colon ```:``` The fith field in the user account record is the GECOS field. stores general information about the user, such as the user's full name, office number, and telephone number, among other things. John can take information stored in those records, such as full name and home directory name, to add to the wordlist it generates when cracking /etc/shadow hashes with single crack mode.


**Using Single Crack Mode**

To use single crack mode, we use roughly the same syntax that we've used so far; for example, if we wanted to crack the password of the user named "Mike", using the single mode, we'd

```john --single --format=[format] [path to file]```

 ◦ ﻿﻿--single : This flag lets John know you want to use the single hash-cracking mode
 ◦ ﻿﻿--format=[format] : As always, it is vital to identify the proper format.
 
**Example Usage:**

```john --single --format=raw-sha256 hashes.txt```

**A Note on File Formats in Single Crack Mode:**

If you're cracking hashes in single crack mode, you need to change the file format that you're feeding John for it to understand what data to create a wordlist from. You do this by prepending the hash with the username that the hash belongs to, so according to the above example, we would change the file hashes.txt
From ```lefee03cdcb96d90ad48ccc7b8666033```

To ```mike:1efee03cdcb96d90ad48cCc7b8666033```

**Practical**

Now that you're familiar with the Syntax for John's single crack mode, access the hash and crack it, assuming that the user it belongs to is called "Joker". The file is located in ```~/ John-the-Ripper-The-Basics/Task07/```

**Q1.What is the Joker's password?**

Ans:***Jok3r***

**Steps:**

1- identify the hash type using the hash-identifier website

![image](https://github.com/user-attachments/assets/c4625a1d-558f-432e-90bc-f057dcaf0cc5)



2- view the hash and use nano text editor to modify the file and add Joker's name next to the hash value
![image](https://github.com/user-attachments/assets/60d57132-6387-469b-9254-648f86f988e9)

3- use this command ```john --single --format=raw-md5 hash07.txt ``` to tell john to do a word mangling based on the Joker's name and hash it then compare the hashed
value to the hash we want to crack. 
![image](https://github.com/user-attachments/assets/baacbd85-08f8-4965-8cfe-6590f26bd06e)




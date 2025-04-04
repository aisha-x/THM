
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
- john: Invokes the John the Ripper program
- [options]: Specifies the options you want to use
- [file path]: The file containing the hash you're trying to crack; if it's in the same directory, you won't need to name a path, just the file.

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


# Task 8: Custom Rules

**What are Custom Rules?**

As we explored what John can do in Single Crack Mode, you may have some ideas about some good mangling patterns or what patterns your passwords often use that could be replicated with a particular mangling pattern. The good news is that you can define your rules, which John will use to create passwords dynamically. The ability to define such rules is beneficial when you know more information about the password structure of whatever your target is.

**Common Custom Rules**

Many organizations will require a certain level of password complexity to try and combat dictionary attacks. In other words, when creating a new account or changing your password, if you attempt a password like polopassword, it will most likely not work. The reason would be the enforced password complexity. As a result, you may receive a prompt telling you that passwords have to contain at least one character from each of the following:
 - ﻿﻿Lowercase letter
 - ﻿﻿Uppercase letter
 - ﻿﻿Number
 - ﻿﻿Symbol
   
Password complexity is good! However, we can exploit the fact that most users will be predictable in the location of these symbols. For the above criteria, many users will use something like the following:

```Polopassword1!```

Consider the password with a capital letter first and a number followed by a symbol at the end. This familiar pattern of the password, appended and prepended by modifiers (such as capital letters or symbols), is a memorable pattern that people use and reuse when creating passwords. This pattern can let us exploit password complexity predictability.

Now, this does meet the password complexity requirements; however, as attackers, we can exploit the fact that we know the likely position of these added elements to create dynamic passwords from our wordlist.

**How to create Custom Rules**

Custom rules are defined in the **john.conf file**. This file can be found in ```/opt/john/john.conf``` on the TryHackMe Attackbox. It is usually located in ```/etc/john/john.conf``` if you have installed John using a package manager or built from source with make

Let's go over the syntax of these custom rules, using the example above as our target pattern. Note that you can define a massive level of granular control in these rules. 
The first line:

```[List.Rules:THMRules]```

is used to define the name of your rule; this is what you will use to call your custom rule a John argument.
We then use a regex style pattern match to define where the word will be modified; again, we will only cover the primary and most common modifiers here:

  -Az: Takes the word and appends it with the characters you define
  -A0: Takes the word and prepends it with the characters you define
  -c: Capitalises the character positionally
  
These can be used in combination to define where and what in the word you want to modify.
Lastly, we must define what characters should be appended, prepended or otherwise included. We do this by adding character sets in square brackets ```[ ]``` where they should be used. These follow the modifier patterns inside double quotes```""```. Here are some common examples:

-```[0-9]```: Will include numbers 0-9
-```[0]```: Will include only the number o
-```[A-z]```: Will include both upper and lowercase
-```[A-Z]```: Will include only uppercase letters
-```[a-z]```: Will include only lowercase letters

**Please note that:**

 ◦ ﻿﻿[a]: Will include only a
 ◦ ﻿﻿[!%$#@]: Will include the symbols !,%,$,# and @
 
Putting this all together, to generate a wordlist from the rules that would match the example password ```Polopassword!``` (assuming the word polopassword was in our wordlist), we would create a rule entry that looks like this:

```[List.Rules:PoloPassword]```

```cAz"[0-9]﻿﻿ [!%$#@]"```

**Utilises the following:**

 - ﻿﻿c: Capitalises the first letter
 - Az: Appends to the end of the word
 - ﻿﻿[0-9] : A number in the range 0-9
 - [!%$#@]: The password is followed by one of these symbols

**Using Custom Rules:**

We could then call this custom rule a John argument using the rule-PoloPassworal tag.
As a full command: ```john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]```

As a note, I find it helpful to talk out the patterns if you're writing a rule; as shown above, the same applies to writing RegEx patterns.
Jumbo John already has an extensive list of custom rules containing modifiers for use in almost all cases. If you get stuck, try looking at those rules [around line 678] if your syntax isn't working correctly.

**Q1. What do custom rules allow us to exploit?**

Ans: ***password complexity predictability***

**Q2. What rule would we use to add all capital letters to the end of the word**

Ans: ***Az"[A-Z]"***

**Q3. What falg would we use to call a custom rule called ```THMRules```?**

Ans: ***--rule=THMRules***


# Task:9 Cracking password-protected Zip Files

Yes! You read that right. We can use John to crack the password on password-protected Zip files. Again, we'll use a separate part of the John suite of tools to convert the Zip file into a format that John will understand, but we'll use the syntax you're already familiar with for all intents and purposes.

**Zip2John**

Similarly to the unshadow tool we used previously, we will use the ```zip2john``` tool to convert the Zip file into a hash format that John can understand and hopefully crack. The primary usage is like this:

```zip2john [options] [zip file] > [output file]```

 - ﻿﻿[options] : Allows you to pass specific checksum options to zip2john ; this shouldn't often be necessary
 - ﻿﻿[zip file]: The path to the Zip file you wish to get the hash of
 - ﻿﻿>: This redirects the output from this command to another file
 - ﻿﻿[output filel: This is the file that will store the output

   
**Example Usage**

```zip2john zipfile.zip › zip_hash.txt```

**Cracking**

We're then able to take the file we output from zip2john in our example use case, zip hash.txt.
, and, as we did with unshadow, feed it directly into John as we have made the input
specifically for it.

```john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt```

**Practical**

Now, have a go at cracking a "secure" Zip file! The file is located in ```~/John-the-Ripper-The-Basics/Task09/```

**Q1. What is the password for the secure.zip file?**

Ans: ***pass123***

**Q2. What is the contents of the flag inside the zip file?**

Ans: ***THM{w3l|_dOn3_h4sh_rOy4l}***

**Steps**

1- list the files inside the directory, and as you can see, there is the secure.zip file and when we try to unzip it, it will ask for the password
![image](https://github.com/user-attachments/assets/c1801152-0b66-4c5e-a20b-1c616d98cd92)

2- to crack the protected zip file, first we need to convert the Zip file to hash format using this command ```zip2john secure.zip › ziphash.txt ```
![image](https://github.com/user-attachments/assets/dab2f1d2-cd7d-49bc-9875-e2447240f47c)


3- now crack the password of the protected Zip file using this command ```john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt ```. we didn't specify the hash format, we will let John automatically identify it

![image](https://github.com/user-attachments/assets/7146cb5c-cdc1-4a84-8c77-c444e313c241)

4- use the returned password to unlock the protected zip file and view the content of the flag
![image](https://github.com/user-attachments/assets/c956c698-feee-4839-9fbc-f096c7530dca)



# Task10: Cracking password protected RAR archives

Cracking a Password-Protected RAR Archive
We can use a similar process to the one we used in the last task to obtain the password for RAR archives. If you aren't familiar, RAR archives are compressed files created by the WinRAR archive manager. Like Zip files, they compress folders and files.

**Rar2John**

Almost identical to the zip2john tool, we will use the rar2john tool to convert the RAR file into a hash format that John can understand. The basic syntax is as follows:
```rar2john [rar filel › [output filel]```

**Example Usage**

```/opt/john/rar2john rarfile.rar › rar_hash.txt```

**Cracking**

Once again, we can take the file we output from ```rar2john``` in our example use case, rar_hash. txt, and feed it directly into John as we did with ```zip2john```

```john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt```

**Practical**

Now, have a go at cracking a "secure" RAR file! The file is located in ```~/John-the-Ripper-The-Basics/Task10/```

**Q1. What is the password for the secure.rar file?**

Ans: ***password***

**Q2. What is the contents of the flag inside the rar file?**

Ans: ***THM(r4r_4rchlve5_th15_tlm3)***

**Steps:**

1- convert the rar file to a hash format ```rar2john secure.rar › rarhash.txt```
![image](https://github.com/user-attachments/assets/aab575b5-49a3-4a6d-8516-2deecf0859d4)

2- crack the protected rar using the hashed file ```john --wordlist=/usr/share/wordlists/rockyou.txt rarhash.txt```
![image](https://github.com/user-attachments/assets/961f6aab-3f1c-47a5-8e70-93c7e761cc26)

3- extract the rar file using the password returned and view the flag.txt file
![image](https://github.com/user-attachments/assets/b5c81481-39fb-4f18-b23a-c14bff74d183)


# Task11: Cracking SSH keys with john

**Cracking SSH Key Passwords**

using John to crack the SSH private key password of id_rsa files. Unless configured otherwise, you authenticate your SSH login using a password. However, you can configure key-based authentication, which lets you use your private key, id_rsa , as an authentication key to log in to a remote machine over SSH. However, doing so will often require a password to access the private key; here, we will be
using John to crack this password to allow authentication over SSH using the key.

**SSH2John**

Who could have guessed it, another conversion tool? Well, that's what working with John is all about. As the name suggests, ```ssh2john``` converts the id_sa private key, which is used to log in to the SSH session, into a hash format that John can work with. Jokes aside, it's another beautiful example of John's versatility. The syntax is about what you'd expect. Note that if you don't have ssh2john installed, you can use ```sshzjohn.py```, located in the ```/opt/john/ssh2john.py```. If you're doing this on the AttackBox, replace the ```ssh2john``` command with ```python3 /opt/john/ssh2john.py ```or on Kali, ```python /usr/share/john/ssh2john.py```

```ssh2john [id_rsa private key file] › [output file]```

 - ﻿﻿ssh2john : Invokes the ssh2john tool
 - [id rsa private key file]: The path to the id_rsa file you wish to get the hash of
 - › : This is the output director. We're using it to redirect the output from this command to another file.
- [output file]: This is the file that will store the output from

**Example Usage**

```/opt/john/ssh2john.py id_rsa › id_rsa_hash.txt```

**Cracking**

For the final time, we're feeding the file we output from ssh2john, which in our example use case is called id rsa hash. txt and, as we did with rar2john, we can use this seamlessly with John:

```john --wordlist=/usr/share/wordlists/rockyou.txt id rsa hash.txt```

**Practical**

Now, I'd like you to crack the hash of the id_rsa file relevant to this task! The file is located in
```~/John-the-Ripper-The-Basics/Task11/```

**Q1. What is the SSH private key password?**

Ans: ***mango***

**Steps:**
1- convert the protected password on the private key to a hash format using this command ```/opt/john/ssh2john.py id_rsa › sshhash.txt```


![image](https://github.com/user-attachments/assets/12b91cd2-607f-4fff-89a5-cc0de008cc9e)

2- now crack the password using the converted hash file with this command 
```john --wordlist=/usr/share/wordlists/rockyou.txt sshhash.txt```

![image](https://github.com/user-attachments/assets/b47ea91a-61d6-493f-a100-8899d2f50f51)



........................................................................................

# the end


I followed this video
https://www.youtube.com/watch?v=V405LPqqCCA




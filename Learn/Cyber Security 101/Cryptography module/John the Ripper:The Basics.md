
# John the Ripper: the Basics Walkthrough
--------------

# task#1: Introduction

learning objective: 
Upon the completion of this room, you learn about using John for:

  - Cracking Windows authentication hashes
  - Crack /etc/shadow hashes
  - Cracking password-protected Zip files
  - Cracking password-protected RAR files
  - Cracking SSH keys

.....................

# task#2: basic Terms

Where John Comes in
Even though the algorithm is not feasibly reversible, that doesn't mean cracking the hashes is impossible. If you have the hashed version of a password, for example,

and you know the hashing algorithm, you can use that hashing algorithm to hash a large number of words, called a dictionary. 

You can then compare these hashes to the one you're trying to crack to see if they match. If they do, you know what word corresponds to that hash- you've cracked it!

..........................

# Task#3: setting up your system

Throughout the tasks of this room, we will be using the following :
  - The "Jumbo John" version of John the Ripper
  - The RockYou password list

We should note that if you use a version of John the Ripper other than Jumbo John, you might not have some of the required tools, such as ***zip2john*** and ***rar2j3hn***

Installation:

 - In kali or parrot you can install using ```sudo apt-get install john```  to install this tool
 - On black arch you can isntall using ```packman -S john```
 - you need to consider building from the source to access all the tool available via jumbo John [offical installation guide ]([https://www.kali.org/tools/john/](https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL))


Wordlists:
As we mentioned earlier, to use a dictionary attack against hashes, you need a list of words to hash and compare; unsurprisingly, this is called a wordlist. 

There are many different wordlists out there, and a good collection can be found in the [SecLists repository](https://github.com/danielmiessler/SecLists). There are a few places you can look for wordlists for attacking the system of choice; we will quickly run through where you can find them.
On the AttackBox and Kali Linux distributions, the ```/usr/share/wordlists``` directory contains a series of great wordlists.
***RockYou***
For all of the tasks in this room, we will use the infamous rockyou.txt wordlist, a very large common password wordlist obtained from a data breach on a website called rockyou.com in 2009. If you are not using any of the above distributions, you can get the rockyou.txt wordlist from the Seclists repository under the /Passwords/Leaked-Databas subsection. You may need to extract it from the ```.tar.gz```. format using ``` tar xvzf rockyou.txt.tar.gz```

Now that we have our hash cracker and wordlists all set up, let's move on to some hash cracking!

......................

# Task#4: Cracing Basic Hashes

John Basic Syntax

The basic syntax of John the Ripper commands is as follows. We will cover the specific options and modifiers used as we use them.
```john [options] [file path]```
• john: Invokes the John the Ripper program
• [options]: Specifies the options you want to use
• [file path]: The file containing the hash you're trying to crack; if it's in the same directory, you won't need to name a path, just the file.

Automatic Cracking

John has built-in features to detect what type of hash it's being given and to select appropriate rules and formats to crack it for you; this isn't always the best idea as it can be unreliable, but if you can't identify what hash type you're working with and want to try cracking it, it can be a good option! To do this, we use the following syntax:
```john --wordlist=[path to wordlist] [path to file]```
--wordlist=: Specifies using wordlist mode, reading from the file that you supply in the provided path [path to wordlist): The path to the wordlist you're using, as described in the previous task
Example Usage:
```john --wordlists/usr/share/wordlists/rockyou.txt hash_to_crack.txt```

Identifying Hashes

-online tools: [hash_identifier](https://hashes.com/en/tools/hash_identifier)
-Python tool: [hash-identifier](https://github.com/blackploit/hash-identifier)
    - How to install: ```sudo apt install hash-identifier ```
    - How to use:  ```python3 hash-identifier.py```


Format-Specific Cracking

```john --format»[format) --wordlist=[path to wordlist) [path to file]```

--Format=This is the flag to tell John that you're giving it a hash of a specific format and to use the following format to crack it The format that the hash is in
Example Usage:
```John --format=raw-md5 --wordlista/usr/share/wordlists/rockyou.txt hash_to_crack.txt```
A Note on Formats:
When you tell John to use formats, if you're dealing with a standard hash type, e g. md5 as in the example above, you have to prefix it with to tell John you're just dealing with a
standard hash type, though this doesn't always apply. To check if you need to add the prefix or not, you can list all 
of John's formats using ```John --list=formats``` and either check manually or grep for your hash type using something like ```john --listsformats | grep -iF "ads"```


Practical
Now that you know the syntax, modifiers, and methods for cracking basic hashes, try it yourself! The files are located in
-/John-the-Ripper-The-Basics/Task04/
on the attached virtual machine.

q1. What type of hash1.txt?

Ans: md5

q2. what is the cracked value of hash1.txt? 

Ans: biscuit

Steps: 
- view the file
- identify the hash type using the hash identifier
![image](https://github.com/user-attachments/assets/73810612-3092-4821-9d79-10326acac8a1)

 - then specifiy the hash format of the hash file to crack the hash value
 - ```John --format=raw-md5 --wordlista/usr/share/wordlists/rockyou.txt hash1.txt```

![image](https://github.com/user-attachments/assets/6b86d658-1436-4d1f-8b5d-cb1aedf6ee19)





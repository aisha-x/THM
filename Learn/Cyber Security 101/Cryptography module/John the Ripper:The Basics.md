
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



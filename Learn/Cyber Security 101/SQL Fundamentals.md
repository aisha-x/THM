# SQL Fundamentals | TryHackMe Walkthrough

Room URL: https://tryhackme.com/room/sqlfundamentals

# TASK 1: Introduction

Welcome, dear reader, to the fascinating, slightly chaotic, and deeply intertwined world of cybersecurity and databases. Imagine This: You’re diving into cybersecurity, and — surprise! — databases are everywhere. Whether you’re locking down a web app, analyzing threats in a Security Operations Center (SOC), or just trying to stop that overly curious user from seeing all the juicy data, databases are your trusty sidekick…or, occasionally, your arch-nemesis.

For the bold souls on the offensive side of security, databases are like a treasure chest just waiting for a clever SQL injection to crack it open. Want to retrieve some hidden data from a compromised service? A well-crafted SQL query can be your magic key! Meanwhile, for those valiantly defending the realm, databases are where you hunt for signs of shady activity. They’re also the first line of defense, helping you lock down access and keep the bad guys out.

With databases in every corner of the cybersecurity universe, understanding their basics is crucial. So, get ready to learn the essential terms, concepts, and types that make up this tech staple — then take a first dive into SQL, the language that lets you speak fluent “database.” Let’s go!



# TASK 2: Databases 101

Alright, so databases are basically everywhere, collecting all sorts of info about us, from login details to binge-watching habits. Let’s break it down: a database is just an organized collection of data, whether it’s for storing usernames and passwords, cataloging every comment you’ve ever left on a cat video, or tracking how many times you’ve re-watched The Office. Databases are the MVPs behind pretty much every system and service we use, big or small.

**Relational vs. Non-Relational Databases: Pick Your Fighter**

![image](https://github.com/user-attachments/assets/70f2a1fd-f43f-4e69-a915-01f5c77f61f2)


Imagine two types of databases squaring off: Relational (SQL) Databases and Non-Relational (NoSQL) Databases.

Relational Databases: Think of these as super organized data nerds. Everything is neatly stored in tables with rows and columns. You know what info to expect, and you can link different tables together for more context, like connecting a “Users” table to an “Order History” table. Structured, predictable, and great for things like e-commerce where accuracy is critical.
Non-Relational Databases: These guys are more chill, storing data in a flexible, non-tabular format. Got a mixed bag of data that doesn’t follow a strict structure? NoSQL’s got you. Perfect for user-generated content on social media, where you can have anything from text to photos to “what even is that” kinds of data.

**Tables, Rows, and Columns: The Building Blocks**

![image](https://github.com/user-attachments/assets/18e93651-dac5-4822-a42b-c1ab0fb65829)


In relational databases, data is organized in tables. Imagine a table called “Books” in a bookstore’s database. Each column represents a piece of info (like “Name” or “Published Date”), and each row is a new book. Different data types (like text, numbers, dates) go in different columns, and if you try to add incompatible data — nope, the database won’t have it.

**Primary and Foreign Keys: Making Data BFFs**

![image](https://github.com/user-attachments/assets/6a072fa9-36d8-4417-b74e-5188047588c2)


Primary Keys: These are the unique IDs for each record in a table, like a student ID that’s unique to each person.
Foreign Keys: These are links between tables, connecting related info, like matching an “Author ID” in the “Books” table with the “ID” in the “Authors” table. Think of it as making sure that every book has a rightful author.
So there you have it! Databases are the glue holding data together, whether it’s for your streaming recommendations or that carefully crafted SQL injection (just kidding, stay ethical!). And with a solid grasp on the basics, you’re well on your way to wrangling databases like a pro.

**Question: What type of database should you consider using if the data you’re going to be storing will vary greatly in its format?**

Answer: ***Non-relational database***

**Question: What type of database should you consider using if the data you’re going to be storing will reliably be in the same structured format?**

Answer: ***relational database***

**Question: In our example, once a record of a book is inserted into our “Books” table, it would be represented as a ___ in that table?**

Answer: ***row***

**Question: Which type of key provides a link from one table to another?**

Answer: ***foreign key***

**Question: Which type of key ensures a record is unique within a table?**

Answer: ***primary key***


# TASK 3: SQL

So, databases are cool and all, but how do we actually work with them? Enter SQL — Structured Query Language, or, as I like to call it, “Speak to the Database 101.” SQL lets you tell the database what to do: create tables, insert data, update information, and run all kinds of queries. Basically, SQL is like the magic spellbook for data wizards!

First, you need a Database Management System (DBMS), which is software that bridges the gap between you and the database. Popular DBMSs include MySQL, MongoDB, and Oracle Database. With SQL as your DBMS toolkit, you can query, manage, and manipulate data like a pro.

**Why SQL Rocks**

Speedy Gonzalez: SQL can pull massive amounts of data in seconds. No long waits, no fuss.
Super Simple: SQL is almost plain English! So, you’ll spend more time actually querying data than wrestling with syntax.
Accuracy On Lock: Relational databases have strict structures, meaning data stays accurate and easy to manage.
Flexible AF: From quick lookups to deep data analysis, SQL can handle it all without breaking a sweat.
Get Your Hands Dirty with SQL

Ready to dive in? Start up the machine, open that terminal, and type:

`mysql -u root -p`

(followed by tryhackme as the password). Voilà, you’re in the MySQL monitor, where you can start working your SQL magic! Say hello to your database, and let the querying begin.

**Question: What serves as an interface between a database and an end user?**

Answer: ***DBMS***

**Question: What query language can be used to interact with a relational database?**

Answer: ***SQL***


# TASK 4: Database and Table Statements

Alright, it’s time to dive into SQL commands and turn databases from theoretical talk into practical power. Think of SQL commands as the building blocks of a database architect’s empire — one “CREATE,” “SHOW,” and “DROP” at a time.

**Database Statements**

CREATE DATABASE: Want a new database? Just ask SQL politely with CREATE DATABASE your_database_name;! For example,

`CREATE DATABASE thm_bookmarket_db`

 - ; sets up a new little data world.
 - SHOW DATABASES: Curious about what databases are hanging out on the server? SHOW DATABASES; lists all the ones available, including some mysterious pre-installed ones 
   like mysql and sys — like your server’s built-in roommates.
 - USE DATABASE: Once you’ve got a database, you need to tell SQL, “Hey, let’s work with this one” with USE your_database_name;.
 - DROP DATABASE: No longer need that database? DROP DATABASE will take it out for you (but, you know, double-check before you hit ‘Enter’).

**Table Statements**

Now we’ve got a database, let’s fill it with tables! Tables are like folders where your data lives — every database has ‘em.

**CREATE TABLE:**

To add a new table, you use CREATE TABLE followed by a name and details about each column. Example:

```
CREATE TABLE book_inventory (
book_id INT AUTO_INCREMENT PRIMARY KEY,
book_name VARCHAR(255) NOT NULL,
publication_date DATE
);
```

Here, we’re setting up a “book_inventory” table with three columns. AUTO_INCREMENT means SQL will keep counting up book IDs for us.

**SHOW TABLES:**

Want to see all tables in your database? `SHOW TABLES;` will list them out. It’s the table roll call.

**DESCRIBE:**

If you need a peek at what columns and types make up a table, run `DESCRIBE your_table_name;`. It’s like an X-ray for your table structure.
Modifying Tables

**ALTER:**

Want to change things up? `ALTER TABLE` lets you add, remove, or rename columns. For example, if you suddenly realize you need a page count for each book, just add it:

`ALTER TABLE book_inventory ADD page_count INT;`

**DROP TABLE:**

Done with a table? Drop it like it’s hot with `DROP TABLE table_name;`.
With these commands, you’re ready to start creating, organizing, and editing databases like a SQL superstar. Now, go forth and start querying!

**Question: Using the statement you’ve learned to list all databases, it should reveal a database with a flag for a name; what is it?**

Answer: ***THM{575a947132312f97b30ee5aeebba629b723d30f9}***

**Question: In the list of available databases, you should also see the task_4_db database. Set this as your active database and list all tables in this database; what is the flag present here?**

Answer: ***THM{692aa7eaec2a2a827f4d1a8bed1f90e5e49d2410}***

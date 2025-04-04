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

**Modifying Tables**

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


# TASK 5: CRUD Operations

In the world of databases, CRUD is king! The big four — Create, Read, Update, Delete — are the bread and butter of data management. Here’s a rundown of each, using MySQL’s books table for all the real-world action. Ready? Let’s dive in!

**Create (INSERT)**

Creating records is like adding fresh ingredients to your data stew. Need a new entry? INSERT INTO is here to help:
```
INSERT INTO books (id, name, published_date, description)
VALUES (1, "Android Security Internals", "2014–10–14", "An In-Depth Guide to Android's Security Architecture");
```
Just like that, a book called “Android Security Internals” is now saved in our books table. Voilà! Fresh data added.

**Read (SELECT)**

Reading is where we play detective and uncover data mysteries. The SELECT statement lets you peek into your table’s soul:

`SELECT * FROM books;`
This retrieves all the columns, but if you only want specific details like name and description, use:

`SELECT name, description FROM books;`
Perfect for when you just need the highlights!

**Update (UPDATE)**

Sometimes things change, and our data has to keep up! The UPDATE command is like editing a typo in a story:
```
UPDATE books
SET description = "An In-Depth Guide to Android's Security Architecture."
WHERE id = 1;
```
This updates the description for the book with id = 1. Remember to specify which record to update with WHERE, or SQL will get a little overzealous and update everything.

**Delete (DELETE)**

Deleting data is like Marie Kondo-ing your table — it clears out what no longer “sparks joy.”

`DELETE FROM books WHERE id = 1;`
This removes the record with id = 1 from the books table. Use WHERE wisely here too, unless you want to say goodbye to all your data!

**Quick Summary**

 - **Create**: `INSERT` — Add new data to the table.
 - **Read**: `SELECT` — Retrieve data from the table.
 - **Update**: `UPDATE` — Modify existing data.
 - **Delete**: `DELETE` — Remove data from the table.

And there you have it — CRUD is the magic toolkit for managing data in your database! Now go forth and wield your new database superpowers. 🦸‍♂️

**Question: Using the tools_db database, what is the name of the tool in the hacking_tools table that can be used to perform man-in-the-middle attacks on wireless networks?**

Answer: ***Wi-Fi Pineapple***

**Question: Using the tools_db database, what is the shared category for both USB Rubber Ducky and Bash Bunny?**

Answer: ***USB attacks***

# TASK 6: Clauses

Let’s take a look at some SQL clauses that put you in control, helping your database return results your way. Meet DISTINCT, GROUP BY, ORDER BY, and HAVING — the squad that keeps your data clean, organized, and precise!

**DISTINCT: No Duplicates Allowed!**

Got some duplicates? DISTINCT helps you by filtering them out! Check this out:

`SELECT DISTINCT name FROM books;`

If you have two copies of “Ethical Hacking” in your books table, DISTINCT makes sure you only see it once. It’s like a bouncer keeping out duplicates at the data club!

**GROUP BY: Grouping Like a Pro**

When you need to aggregate data, GROUP BY is the go-to. It’s the secret to counting, summing, and more:

`SELECT name, COUNT(*) FROM books GROUP BY name;`

With this, you’ll see how many times each book shows up. It’s like grouping your socks by color so you know exactly how many pairs you have!

**ORDER BY: Setting the Perfect Order**

Sorting data? ORDER BY has your back. You can use it to sort in ascending (ASC) or descending (DESC) order:

`SELECT * FROM books ORDER BY published_date ASC;`

Now your books are in date order, perfect for when you want to binge-read in chronological order! Want it in reverse? Just change to DESC.

**HAVING: The Cool Filter for Groups**

When you want to filter groups after you’ve grouped them, HAVING steps in. It’s like WHERE’s cooler cousin:

`SELECT name, COUNT(*) FROM books GROUP BY name HAVING name LIKE '%Hack%';`

This filters the results of the grouped data to show only books with “Hack” in their title — giving you a filtered view based on your group criteria.

**Quick Recap**

- `DISTINCT` — Filters out duplicates.
- `GROUP BY` — Groups your data for summaries.
- `ORDER BY` — Sorts your data, just like Netflix’s “latest releases.”
- `HAVING` — Filters your grouped data based on conditions.

Now, armed with these clauses, your SQL game just leveled up!

**Question: Using the tools_db database, what is the total number of distinct categories in the hacking_tools table?**

Answer: ***6***

**Question: Using the tools_db database, what is the first tool (by name) in ascending order from the hacking_tools table?**

Answer: ***Bash Bunny***

**Question: Using the tools_db database, what is the first tool (by name) in descending order from the hacking_tools table?**

Answer: ***Wi-Fi Pineapple***

# TASK 7: Operators

SQL operators are like the controls of a powerful data filter. Here’s a breakdown of key operators that can help you build more precise and effective queries in SQL.

**Logical Operators**

**LIKE:**

Searches for a specified pattern within a column.

`SELECT * FROM books WHERE description LIKE "%guide%";`

This returns records where the description contains “guide.”

**AND:**

Combines multiple conditions and returns results where all conditions are true.

`SELECT * FROM books WHERE category = "Offensive Security" AND name = "Bug Bounty Bootcamp";`

This finds books in the “Offensive Security” category that match the exact name.

**OR:**

Combines conditions and returns results where any condition is true.

`SELECT * FROM books WHERE name LIKE "%Android%" OR name LIKE "%iOS%";`

This fetches records with either “Android” or “iOS” in the name.

**NOT:**

Excludes specific conditions.

`SELECT * FROM books WHERE NOT description LIKE "%guide%";`

This excludes results where “guide” appears in the description.

**BETWEEN:**

Checks if a value falls within a specified range.

`SELECT * FROM books WHERE id BETWEEN 2 AND 4;`

This selects books with IDs from 2 to 4.

**Comparison Operators**

**Equal To (=):**

Finds exact matches.

`SELECT * FROM books WHERE name = "Designing Secure Software";`

This finds records with the exact name “Designing Secure Software.”

**Not Equal To (!=):**

Excludes specific values.

`SELECT * FROM books WHERE category != "Offensive Security";`

This selects records where the category is anything other than “Offensive Security.”

**Less Than (<):**

Finds values smaller than a specified amount.

`SELECT * FROM books WHERE published_date < "2020–01–01";`

This fetches books published before January 1, 2020.

**Greater Than (>):**

Finds values larger than a specified amount.

`SELECT * FROM books WHERE published_date > "2020–01–01";`

This retrieves books published after January 1, 2020.

**Less Than or Equal To (<=):**

Selects values that are less than or equal to a specified amount.

`SELECT * FROM books WHERE published_date <= "2021–11–15";`

This query returns books published on or before November 15, 2021.

**Greater Than or Equal To (>=):**

Selects values that are greater than or equal to a specified amount.

`SELECT * FROM books WHERE published_date >= "2021–11–02";`

This query shows books published on or after November 2, 2021.

**Quick Recap**

- `LIKE`: Filters patterns in strings.
- `AND` / `OR`: Combines multiple conditions.
-`NOT`: Excludes specified conditions.
- `BETWEEN`: Finds values within ranges.
- Comparison Operators (`=`, `!=`, `<`, `>`, `<=`, `>=`): Checks for specific value comparisons.
With these operators in your SQL toolkit, you can filter data exactly as needed. Use them to keep your queries powerful and precise!

**Question: Using the tools_db database, which tool falls under the Multi-tool category and is useful for pentesters and geeks?**

Answer: ***Flipper Zero***

**Question: Using the tools_db database, what is the category of tools with an amount greater than or equal to 300?**

Answer: ***RFID cloning***

**Question: Using the tools_db database, which tool falls under the Network intelligence category with an amount less than 100?**

Answer: ***Lan Turtle***

# TASK 8: Functions

SQL functions are powerful tools for manipulating data, enabling us to streamline queries, transform data, and gain insights. Here’s a guide to some essential SQL functions.

**String Functions**

**CONCAT():**

Joins multiple strings into one.
`SELECT CONCAT(name, " is a type of ", category, " book.") AS book_info FROM books;`
This concatenates book names and categories into a single sentence.

**GROUP_CONCAT():**

Concatenates values from multiple rows into a single field, useful for grouping.
`SELECT category, GROUP_CONCAT(name SEPARATOR ", ") AS books FROM books GROUP BY category;`
This groups books by category, listing book titles in a single string for each category.

**SUBSTRING():**

Extracts a part of a string starting at a specified position.
`SELECT SUBSTRING(published_date, 1, 4) AS published_year FROM books;`
This extracts the year from the published_date, storing it as published_year.

**LENGTH():**

Returns the number of characters in a string (including spaces and punctuation).
`SELECT LENGTH(name) AS name_length FROM books;`
This calculates and displays the length of each book title.

**Aggregate Functions**

**COUNT():**

Counts the number of rows that match the criteria.
`SELECT COUNT(*) AS total_books FROM books;`
This counts the total books in the table, displaying it as total_books.

**SUM():**

Adds up all values in a column.
`SELECT SUM(price) AS total_price FROM books;`
This calculates the total price of all books.

**MAX():**

Finds the maximum value in a column.
`SELECT MAX(published_date) AS latest_book FROM books;`
This retrieves the latest publication date.

**MIN():**

Finds the minimum value in a column.
`SELECT MIN(published_date) AS earliest_book FROM books;`
This retrieves the earliest publication date.

**Summary**

- **String Functions** (`CONCAT`, `GROUP_CONCAT`, `SUBSTRING`, `LENGTH`): Manipulate and transform text.
- **Aggregate Functions** (`COUNT`, `SUM`, `MAX`, `MIN)`: Perform calculations across multiple rows, providing insights into data.
  
With these functions, you can streamline your SQL queries to perform efficient data transformations and aggregations.

**Question: Using the tools_db database, what is the tool with the longest name based on character length?**

Answer: ***USB Rubber Ducky***

**Question: Using the tools_db database, what is the total sum of all tools?**

Answer: ***1444***

**Question: Using the tools_db database, what are the tool names where the amount does not end in 0, and group the tool names concatenated by " & ".**

Answer: ***Flipper Zero & iCopy-XS***

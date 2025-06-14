---
title: Username enumeration via different responses
description: PortSwigger Authentication Lab
---
This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.
## Discovery
Login request
```http
POST /login HTTP/2
Host: 0a3d007704901c3c803e538a00d60087.web-security-academy.net
Cookie: session=kqolczlHWEUGA4MXHzualXLGupjIQc36
Content-Length: 26
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a3d007704901c3c803e538a00d60087.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a3d007704901c3c803e538a00d60087.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=test&password=123
```

Display message indicating that the username is invalid
![](../../../../public/images/PS_Auth_20250613%20_175423%201.png)

## Exploit
Enumerating the username with the provided list, looking for a different return message that is not "Invalid username".

The username "Amarillo" returned "Incorrect password", indicating it is likely a valid account.
![](../../../../public/images/PS_Auth_20250613%20_175932.png)

With "Amarillo" identified as a  username, I proceeded to brute-force the password using the provided wordlist and found `pepper` as a valid password.

```
POST /login HTTP/2
Host: 0a3d007704901c3c803e538a00d60087.web-security-academy.net

username=Amarillo&password=pepper
```

```
HTTP/2 302 Found
Location: /my-account?id=amarillo
Set-Cookie: session=NbJZ5i49MxiLAq2qz9Vlbse8IHyspWcC; Secure; HttpOnly; SameSite=None
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

Credentials: `Amarillo`:`pepper`
![](../../../../public/images/PS_Auth_20250613%20_180904.png)
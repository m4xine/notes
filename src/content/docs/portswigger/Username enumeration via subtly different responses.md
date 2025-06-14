---
title: Username enumeration via subtly different responses
description: PortSwigger Authentication Lab
---
This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.
## Discovery
Login request
```http
POST /login HTTP/2
Host: 0a9800e903fad5bf814e08ca007100fc.web-security-academy.net
Cookie: session=8iiIyiSGmzge99vbHJSC6QPf460Iljnm
Content-Length: 27
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a9800e903fad5bf814e08ca007100fc.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a9800e903fad5bf814e08ca007100fc.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=john&password=test
```

Unsuccessful login returns this message:
![](../../../../public/images/PS_Auth_20250613%20_204705.png)

Enumerating usernames to notice any different in the response. User `as400` error message is slightly different compares to the others. Theres is a period missing in the message: ![](../../../../public/images/PS_Auth_20250613%20_205145%201.png)

This means there is something different about this username and it is processed differently.
## Exploit
Brute-forcing the password for user `as400`. 
Found `112233` returns a different status code 302 which means its a valid password.
![](../../../../public/images/PS_Auth_20250613%20_205546.png)

Credential: `as400`:`112233`
![](../../../../public/images/PS_Auth_20250613%20_205749.png)


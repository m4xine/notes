---
title: 2FA simple bypass
description: PortSwigger Authentication Lab
---
This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials: `wiener:peter`
- Victim's credentials `carlos:montoya`

## Discovery
To complete the authentication the user have to enter a 4-digit security code sent to the user's inbox. ![](../../../../public/images/PS_Auth_20250613%20_181958.png)

### Auth Flow
1. Login with username & password : 
```http
POST /login HTTP/2
Host: 0ac0006a04c16c738008358a00400035.web-security-academy.net
Cookie: session=YuthgJRb79tsDDjpQs45LZfT2sKu4xWm
Content-Length: 30
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0ac0006a04c16c738008358a00400035.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ac0006a04c16c738008358a00400035.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=wiener&password=peter
```
2. If valid credentials user is redirected to 
```http
GET /login2 HTTP/2
Host: 0ac0006a04c16c738008358a00400035.web-security-academy.net
Cookie: session=YuthgJRb79tsDDjpQs45LZfT2sKu4xWm
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0ac0006a04c16c738008358a00400035.web-security-academy.net
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0ac0006a04c16c738008358a00400035.web-security-academy.net/login
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

```

If the user enter the correct 2FA code it will redirect to their account page:
`https://0ac0006a04c16c738008358a00400035.web-security-academy.net/my-account?id=wiener`

Instead of submitting the 2FA code, directly accessing the user account endpoint returns a 200 OK response, indicating that the authentication flow is broken and the server fails to enforce 2FA verification.

## Exploit
Login as carlos, after the credential is successfully validated navigate to `https://0ac0006a04c16c738008358a00400035.web-security-academy.net/my-account?id=carlos`

![](../../../../public/images/PS_Auth_20250613%20_183241.png)

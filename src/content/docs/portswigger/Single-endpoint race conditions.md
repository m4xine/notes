---
title: Single-endpoint race conditions
description: PortSwigger Race Conditions Lab
---
This lab's email change feature contains a race condition that enables you to associate an arbitrary email address with your account.

Someone with the address `carlos@ginandjuice.shop` has a pending invite to be an administrator for the site, but they have not yet created an account. Therefore, any user who successfully claims this address will automatically inherit admin privileges.

To solve the lab:

1. Identify a race condition that lets you claim an arbitrary email address.
2. Change your email address to `carlos@ginandjuice.shop`.
3. Access the admin panel.
4. Delete the user `carlos`

You can log in to your own account with the following credentials: `wiener:peter`.

You also have access to an email client, where you can view all emails sent to `@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net` addresses
## Discovery
Change email request
```http
POST /my-account/change-email HTTP/2
Host: 0a7c009903ddd27080169e8a00f400d8.web-security-academy.net
Cookie: session=CoEpjPiJeTgE6e5OX7PMz5g36phqTrq7
Content-Length: 110
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a7c009903ddd27080169e8a00f400d8.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a7c009903ddd27080169e8a00f400d8.web-security-academy.net/my-account?id=wiener
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

email=test%40exploit-0ab700c703f7d2b280789d8001ee00bd.exploit-server.net&csrf=aDw2vIKP0Q1PY7ePPqTL0WNaYvSK3yit
```

Sending multiple change email request in sequence to check behaviour.
![](../../../../public/images/PS_Race_Conditions_20250612%20_220515.png)

Mailbox receives the request in order:
![](../../../../public/images/PS_Race_Conditions_20250612%20_220636.png)

Sending multiple change email request in concurrently to see how the server handle it or any unexpected behaviour.
![](../../../../public/images/PS_Race_Conditions_20250612%20_221013.png)

The server processes concurrent email update requests without isolating each operation properly. As a result, shared state is overwritten mid-request, causing confirmation emails to be sent to one address while the confirmation link references another.![](../../../../public/images/PS_Race_Conditions_20250612%20_221513.png)

## Exploit
To exploit this, the goal is to trigger a race condition where the server sends Carlos’s email update confirmation link to our inbox.

Request 1 update email with attacker email address:
![](../../../../public/images/PS_Race_Conditions_20250612%20_221833.png)

Request 2 update email with carlos email address:
![](../../../../public/images/PS_Race_Conditions_20250612%20_222013.png)
Duplicate these two requests and then "Send group (parallel)".

Carlos email change link is sent to the attacker mailbox:
![](../../../../public/images/PS_Race_Conditions_20250612%20_222312.png)

Email is changed to Carlo's and we now have access to the admin panel
![](../../../../public/images/PS_Race_Conditions_20250612%20_222429.png)

Delete Carlo's account
![](../../../../public/images/PS_Race_Conditions_20250612%20_222551.png)
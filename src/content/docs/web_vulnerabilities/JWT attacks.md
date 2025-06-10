---
title: JWT attacks
description: Poor implementation of JWT can be used to bypass authentication and access control
---
JSON Web Tokens (JWTs) are commonly used for authentication, session management, access control, and securely exchanging data between web applications. They are also widely used in API access, OAuth 2.0 flows, and Single Sign-On (SSO) implementations. However, poor implementation of JWTs can introduce serious security risks and may be exploited to compromise a web application.

Specs define JWT: [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)
## JWT Format
A JWT consists of three parts, separated by dots:
```css
HEADER.PAYLOAD.SIGNATURE
```
- **HEADER**: Define the type(`typ`) of token and the signing algorithm (`alg`) (e.g. `HS2456`)
- **PAYLOAD**: Contains claims about the user, session, or other data (e.g. `{"user": "user1", "admin": false}`). Common claims:
	- Issuer (iss)
	- Subject (sub)
	- Audience (aud)
	- Expiration time (exp)
	- Not before (nbf)
	- Issued at (iat)
	- JWT ID (jti)
- **SIGNATURE**:  A cryptographic signature that ensures the token hasn't been tampered with.
Each part is Base64URL-encoded (without padding) and concatenated with a dot:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJ1c2VyMSIsImFkbWluIjpmYWxzZX0.
X5cBA0klC0df_vxTqM-M1WOUbE8Qzj0Kh3w_N6Y7LkI
```

## JSON Web Algorithms (JWA)
JWT algorithms are defined in[JWA Specifications](https://datatracker.ietf.org/doc/html/rfc7518
Common JWT Signing Algorithms
- **Symmetric algorithms** (HMAC based using a shared secret): `HS256`, `HS384`, `HS512`
- **Asymmetric algorithms** (public/private key): `RS256` (RSA based), `ES256` (Elliptic Curve based), `PS256` (RSA based with MGF1 padding), etc.
- **None**: A non-algorithm that implies no signature (insecure and should never be used)
More algorithms at [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-3)

Signing a token:
```js
signature = ALGORITHM.Sign(header + "." + payload, key)
```
Verifying a token:
```js
ALGORITHM.Verify(signature, header + "." + payload, key)
```

## XXE Attack
- Signature not verified
- Unsigned JWT
- Weak Signing Key

## Mitigation
- Always use a library’s **verify()** method before accessing claims.
- Never trust the payload until the signature is successfully validated.
- **Explicitly disable the "none" algorithm** in your JWT library configuration.
- Do not rely on defaults, enforce algorithm allowlists like `RS256` or `HS256`.
## Exploit
### Signature not verified
**JWTs are not encrypted by default**, which means their contents can be viewed and even modified by anyone. To ensure the token hasn't been tampered with, applications must validate the signature. However, some applications skip this critical step, allowing attackers to modify the payload and exploit the system with ease.

1. Get a valid JWT token.
2. Decode the Base64URL-decode to see header and payload
3. Make changes to the payload, like changing to a different user. 
```http
{  
    "iss": "portswigger",  
    "exp": 1747553975,  
    "sub": "john"  
}
```
Change user:
```http
{  
    "iss": "portswigger",  
    "exp": 1747553975,  
    "sub": "admin"  
}
```
4. Base64URL-encode the header and payload.
5. Send with original signature, if the application does not verify the signature you'll be authenticated as `admin` user.
### Unsigned JWT
Early versions of many JWT libraries accepted `None` or `none` as a valid option, meaning the token was considered valid **without a signature at all**.
1. Use burpsuite **JSON Web Token** extensions to remove the signature. 

![JSON Web Token](/images/JWT_20250518%20_164907.png)

2. It removes the signature. The header now looks like from this: 
```http
{  
    "typ": "JWT",  
    "alg": "HS256"  
}
```
to this:
```http
{  
    "typ": "JWT",  
    "alg": "none"  
}
```

3. JWT with no signature:
```http
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0NzU1NDQ3MCwic3ViIjoid2llbmVyIn0.
```
4. Send the token if the application does not reject `"alg": "none"`, it will accept the token as valid.
### Weak signing key
HMAC-based algorithms rely on the strength of the secret key. If the key is weak or easily guessable, an attacker can brute-force it and generate their own valid tokens, effectively bypassing authentication.

Use **hashcat** to try to brute-force the secret key.
```bash
hashcat -a 0 -m 16500 eyJraWQiOiI0ODY2MTZhOC1lM2I0LTQzZWItODQ3Mi04NTc1OTgzNWJhNTkiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc0NzU1NDc1NSwic3ViIjoid2llbmVyIn0._75lGMCWEJRNqs-mH0KCZ4IDodeS3IEQFPhUZOGKDNk rockyou.txt
```

List of known JWT secrets: [wallarm/jwt_secrets](https://github.com/wallarm/jwt-secrets)

Create a new signing key with the cracked secret key.
1. Burp Suite > JWT Editor > New Symmetric Key
2. Specify secret > Generate
3. Go to JSON Web token, change the payload and sign with new key.![JWT Signing Key](/images/JWT_20250518%20_170826.png)
### Algorithm Confusion (RSA to HMAC)
TODO
### Algorithm Confusion (ECDSA to HMAC)
TODO
### `kid` Injection (Key ID Manipulation)
TODO
###  Embedded JWK (CVE-2018-0114)
TODO
### JKU / X5U Header Abuse
TODO
###  CVE-2022-21449 (Psychic Signature)
TODO
## Resources
- [The Ultimate Guide to JWT Vulnerabilities and Attacks](https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide)
- [JWT Specification](https://datatracker.ietf.org/doc/html/rfc7519)
- [JSON Web algorithms](https://datatracker.ietf.org/doc/html/rfc7518)
- [JSON Web Token (JWT) Signing Algorithms Overview](https://auth0.com/blog/json-web-token-signing-algorithms-overview/)

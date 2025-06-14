---
title: Broken Authentication
description: Poor or weak implementation of authentication mechanism
---
- [ ] Identify valid usernames
	- [ ] Registration pages
	- [ ] Password reset features
	- [ ] Verbose Errors
- [ ] Brute-force protection
	- [ ] Check account lockout
	- [ ] Check for rate limiting
	- [ ] Check for CAPTCHA
	- [ ] Check for MFA
- [ ] What is the password policy?
	- [ ] Check the strength requirements
	- [ ] Is the password stored securely?
	- [ ] the password reset token sufficiently unique?
- [ ] Is authentication happening client-side?
- [ ] Password reset logic
	- [ ] Predictable Tokens
	- [ ] Token expirations
	- [ ] Insufficient validation
- [ ] Are tokens or credentials passed via the URL?
- [ ] Are there CSRF tokens?
### Session Management
- Check if a session is created after authentication
- Is old session invalidated after re-authentication?
- Check for both idle and absolute timeouts
- Test behaviour after password change or reset
- Test security of account recovery mechanisms

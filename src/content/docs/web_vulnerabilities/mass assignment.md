---
title: Mass Assignment
description: When an application automatically binds user-supplied input to object properties or model fields without proper filtering or validation
---
Mass assignment is when an application automatically binds input fields to an internal object. The vulnerability happens when an attacker is able to assign sensitive or internal fields that were not meant to be user-controlled.

For example, suppose there's a `User` object with the fields: `name`, `email`, and `isAdmin`. A normal user should only be allowed to set `name`and `email` during sign-up. The isAdmin field should be handled internally by the application.

However, if mass assignment is not properly restricted, the application might bind all fields automatically — including `isAdmin`. This allows an attacker to set the `isAdmin` field by including it in the signup request, potentially gaining access they shouldn't have.

E.g. `POST /api/register`
```json
{
	"name": "max",
	"email": "max@gmail.com"
}
```

If vulnerable attacker can do this:
```json
{
	"name": "max",
	"email": "max@gmail.com",
	"isAdmin": true
}
```


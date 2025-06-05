---
title: OSWE Prep
description: Resources to learn before doing the OSWE course
---
Syllabus: [https://manage.offsec.com/app/uploads/2023/01/WEB-300-Syllabus-Google-Docs.pdf](https://manage.offsec.com/app/uploads/2023/01/WEB-300-Syllabus-Google-Docs.pdf)
## Tools:
- Burp Suite
- dnSpy:
    - [Codingo - Decompiling with dnSpy](https://codingo.io/reverse-engineering/ctf/2017/07/25/Decompiling-CSharp-By-Example-with-Cracknet.html)
    - [krypt0mux - Reverse Engineering .NET Applications](https://www.youtube.com/watch?v=_HvqI3Bsgfs)
- Reverse Shells
    - [Reverse Shell Cheat Sheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
    - [Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)

## Programming Concepts
|Concept|What You Should Know:|
|---|---|
|**Data Types**|• How are they declared?|
||• How can they be casted/converted to other data types?|
||• Which data types have the ability to hold multiple sets of data?|
|**Variables & Constants**|• Why do some data types need to be dynamic?|
||• Why do some data types need to remain constant?|
|**Keywords**|• Which words are reserved and why can they not be used as a variable or constant?|
|**Conditional Statements**|• How is data compared to create logic?|
||• Which operators are used to make these comparisons?|
||• How does logic branch from an if/then/else statement?|
|**Loops**|• What are loops primarily used for?|
||• How is a loop exited?|
|**Functions**|• How are functions called?|
||• How are they called from a different file in the codebase?|
||• How is data passed to a function?|
||• How is data returned from a function?|
|**Comments**|• Which characters denote the start of a comment?|

## Web App Concepts
|Concept|What You Should Know:|
|---|---|
|**Input Validation**|• How do web apps ensure user-provided data is valid?  <br>• Which types of data can be dangerous to a web app?|
|**Database Interaction**|• What kinds of databases can be used by a web app?  <br>• How do database management systems differ?  <br>• How does a web app create, retrieve, update, or delete database data?|
|**Authentication**|• How does a web app authenticate users?  <br>• What are hashes? Why is data often stored as hashes?|
## Sample Projects for Code Review
|Language|Sample Project for Code Review|
|---|---|
|**PHP**|• Beginner: [Simple PHP Website](https://github.com/banago/simple-php-website)  <br>• Advanced: [Fuel CMS](https://www.getfuelcms.com/)|
|**ASP.NET & C#**|• Beginner: [Simple Web App MVC](https://github.com/adamajammary/simple-web-app-mvc-dotnet)  <br>• Moderate: [Reddnet](https://github.com/moritz-mm/Reddnet)|
|**NodeJS**|• Beginner: [Employee Database](https://github.com/ijason/NodeJS-Sample-App)  <br>• Moderate: [JS RealWorld Example App](https://github.com/gothinkster/node-express-realworld-example-app)|
|**Java**|• Beginner: [Java Web App – Step by Step](https://github.com/in28minutes/JavaWebApplicationStepByStep)  <br>• Advanced: [GeoStore](https://github.com/geosolutions-it/geostore)|

## Vulnerabilities
|Vulnerability|Vulnerability Write-up|
|---|---|
|**Cross-Site Scripting (XSS)**|• [From Reflected XSS to Account Takeover](https://medium.com/a-bugz-life/from-reflected-xss-to-account-takeover-showing-xss-impact-9bc6dd35d4e6)  <br>• [XSS to Account Takeover](https://noobe.io/articles/2019-10/xss-to-account-takeover)  <br>• [XHR Spec](https://xhr.spec.whatwg.org/)  <br>• [AtMail Email Server Appliance 6.4 - Persistent Cross-Site Scripting](https://www.exploit-db.com/exploits/20009)  <br>• [Chaining XSS, CSRF to achieve RCE](https://rhinosecuritylabs.com/application-security/labkey-server-vulnerabilities-to-rce/)  <br>• [Code analysis to gaining RCE](https://sarthaksaini.com/2019/awae/xss-rce.html)  <br>• [Magento 2.3.1: Unauthenticated Stored XSS to RCE](https://blog.ripstech.com/2019/magento-rce-via-xss/)  <br>• [Mybb 18.20 From Stored XSS to RCE](https://medium.com/@knownsec404team/the-analysis-of-mybb-18-20-from-stored-xss-to-rce-7234d7cc0e72)|
|**Session Hijacking**|• [Hijacking Sessions using Socat](https://popped.io/hijacking-sessions-using-socat/)  <br>• [PentesterLab XSS and MySQL File](https://pentesterlab.com/exercises/xss_and_mysql_file/course)|
|**Persistent Cross-Site Scripting**|• [Acunetix on Persistent XSS](https://www.acunetix.com/blog/articles/persistent-xss/)  <br>• [PortSwigger Web Security - XSS](https://portswigger.net/web-security/cross-site-scripting)|
|**Cross-Site Request Forgery**|• [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)|
|**XSS and MySQL**|• [VulnHub Pentester Lab XSS and MySQL File](https://www.vulnhub.com/entry/pentester-lab-xss-and-mysql-file,66/)|
|**Bypassing File Upload Restrictions**|• [Exploit-DB File Upload Restrictions Bypass](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)  <br>• [Security Idiots - Shell Upload](http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html)  <br>• [OWASP Unrestricted File Upload](https://www.owasp.org/index.php/Unrestricted_File_Upload)  <br>• Popcorn machine from HackTheBox  <br>• [Vault machine from HackTheBox](https://www.youtube.com/watch?v=LfbwlPxToBc)  <br>• [[Paper] File Upload Restrictions Bypass](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)  <br>• [Shell the web - Methods of a Ninja](http://www.securityidiots.com/Web-Pentest/hacking-website-by-shell-uploading.html)  <br>• [Unrestricted File Upload](https://www.owasp.org/index.php/Unrestricted_File_Upload)  <br>• [Atlassian Crowd Pre-auth RCE](https://www.corben.io/atlassian-crowd-rce/)  <br>• [Popcorn machine from HackTheBox](https://www.youtube.com/watch?v=NMGsnPSm8iw)|
|**PHP Type Juggling**|• [PHP Magic Tricks: Type Juggling](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)  <br>• [PHP Type Juggling Explained](https://medium.com/@Q2hpY2tlblB3bnk/php-type-juggling-c34a10630b10)  <br>• [FoxGloveSecurity PHP Type Juggling](https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/)  <br>• [Netsparker PHP Type Juggling](https://www.netsparker.com/blog/web-security/php-type-juggling-vulnerabilities/)  <br>• [TurboChaos PHP Type Juggling](http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html)  <br>• [OWASP Type Juggling Authentication Bypass](https://www.netsparker.com/blog/web-security/type-juggling-authentication-bypass-cms-made-simple/)  <br>• [PHP.net Type Comparisons](https://www.php.net/manual/en/types.comparisons.php)  <br>• [Spaze Hashes](https://github.com/spaze/hashes)  <br>• [WhiteHatSec Magic Hashes](https://www.whitehatsec.com/blog/magic-hashes/)  <br>• Falafel machine from HackTheBox|
|**Deserialization**|• [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)  <br>• [BlackHat JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)  <br>• [Exploit-DB Deserialization](https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf)  <br>• [Zer0Nights Deserialization](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Aleksei%20Tiurin_Deserialization%20vulnerabilities.pdf)|
|**.NET Deserialization**|• [BlackHat .NET Serialization](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)  <br>• [ysoserial.net](https://github.com/pwntester/ysoserial.net)  <br>• [dnSpy](https://github.com/0xd4d/dnSpy)|
|**Java Deserialization**|• [Exploiting Blind Java Deserialization](https://www.n00py.io/2017/11/exploiting-blind-java-deserialization-with-burp-and-ysoserial/)  <br>• [OWASP Java Deserialization](https://www.owasp.org/images/7/71/GOD16-Deserialization.pdf)  <br>• [ysoserial](https://github.com/frohoff/ysoserial)  <br>• [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)  <br>• [Practicing Java Deserialization](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)|
|**JavaScript Injection**|• [NodeGoat Server-Side JS Injection](https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_server_side_js_injection.html)  <br>• [CapacitorSet MathJS](https://capacitorset.github.io/mathjs/)|
|**NodeJS**|• [Remote Debugging Node with VSCode](https://maikthulhu.github.io/2019-05-17-remote-debugging-node-vscode/)  <br>• [Node.js Security Course](https://github.com/ajinabraham/Node.Js-Security-Course)  <br>• [Acunetix JS Deserialization](https://www.acunetix.com/blog/web-security-zone/deserialization-vulnerabilities-attacking-deserialization-in-js/)  <br>• [YeahHub Node.js Deserialization Attack](https://www.yeahhub.com/nodejs-deserialization-attack-detailed-tutorial-2018/)  <br>• Celestial machine from HackTheBox|
|**SQL Injection**|• [PentesterLab SQLi to Shell](https://pentesterlab.com/exercises/from_sqli_to_shell/course)  <br>• [Acunetix Blind SQLi](https://www.acunetix.com/websitesecurity/blind-sql-injection/)|
|**PostgreSQL**|• [PostgreSQL SQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)  <br>• [PostgreSQL Shell](http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt)  <br>• [PostgreSQL Exploit DB](https://www.exploit-db.com/papers/13084)  <br>• [PostgreSQL String Functions](http://www.postgresqltutorial.com/postgresql-string-functions/)  <br>• [LinuxTopia PostgreSQL Guide](https://www.linuxtopia.org/online_books/database_guides/Practical_PostgreSQL_database/c7547_002.htm)  <br>• [PostgreSQL Injection Guide](https://www.infigo.hr/files/INFIGO-TD-2009-04_PostgreSQL_injection_ENG.pdf)  <br>• [Blind PostgreSQL SQL Injection](https://dotcppfile.wordpress.com/2014/07/12/blind-postgresql-sql-injection-tutorial/)|
|**Long Readings**|• [Use of Deserialization in .NET Framework](https://www.nccgroup.trust/globalassets/our-research/uk/images/whitepaper-new.pdf)  <br>• [BlackHat JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)|

## More links
- [JavaScript For Pentesters](https://www.pentesteracademy.com/course?id=11)
- [Edabit (Javascript, Java, PHP)](https://edabit.com/)
- [From SQL Injection to Shell](https://pentesterlab.com/exercises/from_sqli_to_shell/)
- [XSS and MySQL](https://www.vulnhub.com/entry/pentester-lab-xss-and-mysql-file,66/)
- [Understanding PHP Object Injection](https://securitycafe.ro/2015/01/05/understanding-php-object-injection/)
- [/dev/random: Pipe](https://www.vulnhub.com/entry/devrandom-pipe,124/)
- [Understanding Java Deserialization](https://nytrosecurity.com/2018/05/30/understanding-java-deserialization/)
- [Practicing Java Deserialization Exploits](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)
- [SQL Injection Attacks and Defense](https://www.amazon.com/Injection-Attacks-Defense-Justin-Clarke/dp/1597499633)
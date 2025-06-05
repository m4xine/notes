---
title: Flask
description: Python web framework
---
Create virtual environment

```shell
mkdir flaskproject
cd flaskproject
python3 -m venv .venv
```

Activate environment

```shell
source .venv/bin/activate   
```

Install flask

```shell
pip install flask
```

Page setup `main.py`

```python
from flask import Flask

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"
```

Run flask application

```shell
flask --app main run
```

File structure

```shell
/flaskproject
    ├── main.py               # Your Flask application code
    ├── templates
    │   └── home.html        # Your HTML template
    └── static
        ├── style.css        # Your CSS file
        └── script.js         # Your JavaScript file

```
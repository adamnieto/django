# django-xss-detector
---
Created by Adam Nieto

## Summary
Although django does an amazing job at autoescaping variables in templates, it is still possible to have an XSS attack by making silly mistakes. These mistakes can occur when one uses tag filters that intentionally turn off autoescaping. The intention of this version of django is to create a django web framework that provides warnings of possible XSS vulnerabilities by looking for tag filters that turn autoescaping off. The inspiration for this version of django was to bring attention to possible areas in the template that may be vulnerable to attack. Note that this version of django is extra cautious, however, you are given the option to suppress and silence warnings.

---
## Purpose
To check templates (html files) that contain variables that can potentially be a risk to XSS attack. If it finds potentially unescaped variables it will warn the user from the console by providing a warning with the location of the vulnerability along with the template name.

Example:

```
WARNING: Your application may be at risk to an XSS attack.
In template, "hello.html", line 50 the autoescape was off.
{% autoescape off %}
^
```
---

## django Additions
This version of django adds XSS detection capabilities to django version 1.11.9. It performs XSS vulnerability checks for common template tags that when used incorrectly can be vulnerable to attack.

Take a look at the the following files to see the new additions:

1. `django/middleware/XSSDetector.py`
2. `django/core/management/commands/runserver.py`

---
## Resolve Warnings
### Silence Warnings
Automatically warnings are printed to the console if a vulnerability is detected in any user created template. To suppress the warnings you can use the `--silence-xss-warnings` argument when running the server as depicted below: 

```
python3 manage.py runserver --silence-xss-warnings
```

### Surpress Warnings
A file called `xss_supressions.txt` is created in the same directory as `manage.py` the first time the server is run. This file can be used to tell django to ignore certain lines in templates that may be producing warnings. This is different from silencing warnings. Adding a suppression makes the XSSDetector to ignore possible vulnerabilities for the suppressed line given.

Please use the following format when adding suppressions (start on the 5th line):

```
template_name,line_num
```

Example:
```
home.html,23
```
---
## Installation
To install this package from github simply use one of the following commands:
```
pip install git+https://github.com/adamnieto/django-xss-detector
```
or 
```
pip install git+git://github.com/adamnieto/django-xss-detector
```

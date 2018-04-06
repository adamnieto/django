# django-xss-detector
---
Created by Adam Nieto

![alt text](https://github.com/adamnieto/django-xss-detector/blob/master/XSSDetector_example.png)

## Summary
Although django does an amazing job at autoescaping variables in templates, it is still possible to have an XSS attack by making silly mistakes. These mistakes can occur when one uses tag filters that intentionally turn off autoescaping. The intention of this version of django is to create a django web framework that provides warnings of possible XSS vulnerabilities by looking for tag filters that turn autoescaping off. Note that this version of django is intentionally extra cautious, however, you are given the option to suppress and silence warnings.

---
## Purpose
To check templates (html files) that contain variables that can potentially be a risk to XSS attack. 

If it finds potentially unescaped variables it will warn the user from the console by providing a warning with the location of the vulnerability along with the template name.

Example:

```
WARNING: Your application may be at risk to an XSS attack.
In template, "hello.html", line 50 the autoescape was off.
{% autoescape off %}
^
```
---

## django Additions
This version of django adds XSS detection capabilities to django version 1.11.9. It performs XSS vulnerability checks for builtin template tags that when used incorrectly can be vulnerable to attack.

Take a look at the following files to see the new additions:

1. `django/middleware/XSSDetector.py`
2. `django/core/management/commands/runserver.py`

---
## Features
### Silence Warnings
Automatically warnings are printed to the console if a vulnerability is detected in any user created template. To silence the warnings you can use the `--silence-xss-warnings` argument when running the server as depicted below: 

```
python3 manage.py runserver --silence-xss-warnings
```

### Surpress Warnings
A file called `xss_suppressions.txt` is created in the same directory as `manage.py` the first time the `runserver` command is executed. This file can be used to tell django to ignore certain lines in templates that may be producing warnings. This is different from silencing warnings. Adding a suppression makes the XSSDetector ignore possible vulnerabilities for the suppressed line given.

Please use the following format when adding suppressions (start on the 6th line):

```
<template_name>,<line_num>
```

Example:
```
home.html,23
```
### Add New Rules
A file called `xss_rules.txt` is created in the same directory as `manage.py` the first time the `runserver` command is executed. This file can be used to tell django that you want to add more rules for the xss detector to identify. For instance, if a developer created a new filter or template tag that could potentially be vulnerable to XSS attack then the developer should add this rule to `xss_rules.txt` so they or others who use this filter can be warned if used incorrectly could result in an XSS attack. 
Please use the following format when adding rules (start on the 6th line):

```
<vulnerable_filter_or_text>,<warning_message>
```

Example:
```
|dont_escape,Incorrect usage of the dont_escape filter could lead to a vulnerability.
```
---
## Installation
To install this package from GitHub simply use one of the following commands with pip:
```
pip install git+https://github.com/adamnieto/django-xss-detector
```
or 
```
pip install git+git://github.com/adamnieto/django-xss-detector
```

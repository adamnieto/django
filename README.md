# django-xss-detector

## Motive
Although Django does an amazing job at autoescaping variables in templates it is still possible to have an XSS attack by making silly mistakes. These mistakes can occur when one uses tag filters that intentionally turn off autoescaping. The intention of this version of Django is to create a Django framework that provides warnings of possible XSS vulnerabilities by looking for tag filters that turn autoescaping off. This version helps Django newcomers or people who don't read the documentation from making a silly mistake that can make their web application vulnerable. Additionally, the inspiration for this version of django was to eliminate confusion that may occur with the "safe" tag filter. This filter may confuse Django newcomers into believing that adding "|safe" to a template variable is actually asking Django to make the variable safe from XSS attacks (when it actually does the exact opposite).

## Changes
This version of Django adds XSS detection capabilities to Django version 1.11.9. It completes the XSS checks during system checks when the `runserver` command is executed with `manage.py`.

Take a look at the the following files to see the new additions and changes:

1. `django/middleware/XSSDetector.py`
2. `django/core/management/commands/runserver.py`

## XSSDetector
This class is provided with absolute paths of templates from the Django app and will check templates (html files) that contain variables that are not escaped. If it finds unescaped variables it will warn the user from the console by providing a warning with the location of the vulnerability along with the template name.

Example:

```
WARNING: Your application may be at risk to an XSS attack.
In template, "hello.html", line 50 the autoescape was off.
{% autoescape off %}
^
```

## Installation
To install this package from github simply use one of the following commands:
```
pip install git+https://github.com/adamnieto/django-xss-detector
```
or 
```
pip install git+git://github.com/adamnieto/django-xss-detector
```

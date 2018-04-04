# django-xss-detector
This version of Django adds XSS detection capabilities. It completes the XSS checks during system checks when the `runserver` command is executed on `manage.py`.

Take a look at the the following files to see the new additions and changes:

1. `django/middleware/XSSDetector.py`
2. `django/core/management/commands/runserver.py`

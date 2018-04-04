# django-xss-detector
This version of Django adds XSS detection capabilities. It completes the XSS checks during system checks when the `runserver` command is executed on `manage.py`.

Take a look at the the following files to see the new additions and changes:

1. `django/middleware/XSSDetector.py`
2. `django/core/management/commands/runserver.py`

## XSSDetector
This class is provided with absolute paths of templates from the Django app and will check templates (html files) that contain variables that are not escaped. If it finds unescaped variables it will warn the user from the console by providing a warning with the location and template name.

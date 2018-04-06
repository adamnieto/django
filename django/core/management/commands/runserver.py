from __future__ import unicode_literals

import errno
import os
import re
import socket
import sys
from datetime import datetime

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.core.servers.basehttp import (
    WSGIServer, get_internal_wsgi_application, run,
)
from django.utils import autoreload, six
from django.utils.encoding import force_text, get_system_encoding
# ==============================================================================
# Add Ins by Adam Nieto
import django.template.loader as engine_loader
import django.template.loaders.app_directories as template_dir_loader
import glob
from django.middleware.XSSDetector import XSSDetector
# ==============================================================================

naiveip_re = re.compile(r"""^(?:
(?P<addr>
    (?P<ipv4>\d{1,3}(?:\.\d{1,3}){3}) |         # IPv4 address
    (?P<ipv6>\[[a-fA-F0-9:]+\]) |               # IPv6 address
    (?P<fqdn>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*) # FQDN
):)?(?P<port>\d+)$""", re.X)


class Command(BaseCommand):
    help = "Starts a lightweight Web server for development."

    # Validation is called explicitly each time the server is reloaded.
    requires_system_checks = False
    leave_locale_alone = True

    default_port = '8000'
    protocol = 'http'
    server_cls = WSGIServer

    def add_arguments(self, parser):
        parser.add_argument(
            'addrport', nargs='?',
            help='Optional port number, or ipaddr:port'
        )
        parser.add_argument(
            '--ipv6', '-6', action='store_true', dest='use_ipv6', default=False,
            help='Tells Django to use an IPv6 address.',
        )
        parser.add_argument(
            '--nothreading', action='store_false', dest='use_threading', default=True,
            help='Tells Django to NOT use threading.',
        )
        parser.add_argument(
            '--noreload', action='store_false', dest='use_reloader', default=True,
            help='Tells Django to NOT use the auto-reloader.',
        )
        #=======================================================================
        # Added by Adam Nieto
        parser.add_argument(
            '--silence-xss-warnings', action='store_true',
            help="Silences XSS warnings that come from the XSS detector during checks.",
        )
        #=======================================================================

    def execute(self, *args, **options):
        if options['no_color']:
            # We rely on the environment because it's currently the only
            # way to reach WSGIRequestHandler. This seems an acceptable
            # compromise considering `runserver` runs indefinitely.
            os.environ[str("DJANGO_COLORS")] = str("nocolor")
        super(Command, self).execute(*args, **options)

    def get_handler(self, *args, **options):
        """
        Returns the default WSGI handler for the runner.
        """
        return get_internal_wsgi_application()

    def handle(self, *args, **options):
        from django.conf import settings

        if not settings.DEBUG and not settings.ALLOWED_HOSTS:
            raise CommandError('You must set settings.ALLOWED_HOSTS if DEBUG is False.')

        self.use_ipv6 = options['use_ipv6']
        if self.use_ipv6 and not socket.has_ipv6:
            raise CommandError('Your Python does not support IPv6.')
        self._raw_ipv6 = False
        if not options['addrport']:
            self.addr = ''
            self.port = self.default_port
        else:
            m = re.match(naiveip_re, options['addrport'])
            if m is None:
                raise CommandError('"%s" is not a valid port number '
                                   'or address:port pair.' % options['addrport'])
            self.addr, _ipv4, _ipv6, _fqdn, self.port = m.groups()
            if not self.port.isdigit():
                raise CommandError("%r is not a valid port number." % self.port)
            if self.addr:
                if _ipv6:
                    self.addr = self.addr[1:-1]
                    self.use_ipv6 = True
                    self._raw_ipv6 = True
                elif self.use_ipv6 and not _fqdn:
                    raise CommandError('"%s" is not a valid IPv6 address.' % self.addr)
        if not self.addr:
            self.addr = '::1' if self.use_ipv6 else '127.0.0.1'
            self._raw_ipv6 = self.use_ipv6
        self.run(**options)
# ==============================================================================
    # Added by Adam Nieto
    def create_suppresion_file(self,suppresion_file_path):
        self.stdout.write("No xss suppresion file found.\n")
        self.stdout.write("Created a suppresion file in manage.py directory.\n")
        file_obj = open(suppresion_file_path,"w")
        file_obj.write("This file is used to tell Django to ignore XSS warnings it picks up when the runserver command on manage.py is invoked.\n")
        file_obj.write("Format: <template_name>,<line_num>\n#Example: django.html,50\n")
        file_obj.write("Add your suppressions below:\n")
        file_obj.write("==========================================================================================\n")
        file_obj.close()

    def create_rule_file(self,rule_file_path):
        self.stdout.write("No xss rule file found.\n")
        self.stdout.write("Created a rule file in manage.py directory.\n")
        file_obj = open(rule_file_path,"w")
        file_obj.write("This file is used to tell Django to add an XSS detector rule to the checking process for new filters or text you created that may be vulnerable.\n")
        file_obj.write("Format: <vulnerable_filter_or_text>,<warning_message>\n#Example: |dont_escape,the dont_escape filter was used.\n")
        file_obj.write("Add your rules below:\n")
        file_obj.write("==========================================================================================\n")
        file_obj.close()

    def check_suppresion_file_exists(self,suppresion_file_path):
        return os.path.exists(suppresion_file_path)

    def check_rule_file_exists(self,rule_file_path):
        return os.path.exists(rule_file_path)

    def check_xss_vulnerabilities(self, xss_warnings_are_silenced,suppresion_path,rule_path):
        engine_obj = engine_loader._engine_list()[0]
        template_loader = template_dir_loader.Loader(engine_obj)
        template_directories = template_loader.get_dirs()
        user_template_directory = template_directories[0]
        template_paths = glob.glob(os.path.join(user_template_directory,"*.html"))
        xssdetector = XSSDetector(template_paths,suppresion_path,rule_path)
        xssdetector.check()
        num_errors = xssdetector.get_num_errors()
        messages = xssdetector.get_error_messages()
        if num_errors > 0:
            if not xss_warnings_are_silenced:
                self.stdout.write(str(num_errors) + " potential XSS vulnerabilities were found:\n")
                self.stdout.write(messages)
            else:
                self.stdout.write("Potential XSS vulnerabilities were found (%s silenced).\n" % str(num_errors))
        else:
            self.stdout.write("No XSS threats detected (0 silenced).")

# ==============================================================================

    def run(self, **options):
        """
        Runs the server, using the autoreloader if needed
        """
        use_reloader = options['use_reloader']

        if use_reloader:
            autoreload.main(self.inner_run, None, options)
        else:
            self.inner_run(None, **options)

    def inner_run(self, *args, **options):
        # If an exception was silenced in ManagementUtility.execute in order
        # to be raised in the child process, raise it now.
        autoreload.raise_last_exception()

        threading = options['use_threading']
        # 'shutdown_message' is a stealth option.
        shutdown_message = options.get('shutdown_message', '')
        quit_command = 'CTRL-BREAK' if sys.platform == 'win32' else 'CONTROL-C'

        self.stdout.write("Performing system checks...\n")
        #=======================================================================
        # Added by Adam Nieto
        # Gathering xss suppresion file path
        user_current_directory = os.path.dirname(os.path.abspath(sys.argv[0]))
        suppresion_file_path = os.path.join(user_current_directory,
                                             "xss_suppresions.txt")
        rule_file_path = os.path.join(user_current_directory,
                                             "xss_rules.txt")
        # Checking if xss suppresion file should be created
        if not self.check_suppresion_file_exists(suppresion_file_path):
            self.create_suppresion_file(suppresion_file_path)
        # Checking if xss rule file should be created
        if not self.check_rule_file_exists(rule_file_path):
            self.create_rule_file(rule_file_path)

        self.stdout.write("Performing xss vulnerability checks...\n\n")
        xss_warnings_are_silenced = options["silence_xss_warnings"]
        self.check_xss_vulnerabilities(xss_warnings_are_silenced,
                                       suppresion_file_path,rule_file_path)
        #=======================================================================
        self.check(display_num_errors=True)
        # Need to check migrations here, so can't use the
        # requires_migrations_check attribute.
        self.check_migrations()
        now = datetime.now().strftime('%B %d, %Y - %X')
        if six.PY2:
            now = now.decode(get_system_encoding())
        self.stdout.write(now)
        self.stdout.write((
            "Django version %(version)s, using settings %(settings)r\n"
            "Starting development server at %(protocol)s://%(addr)s:%(port)s/\n"
            "Quit the server with %(quit_command)s.\n"
        ) % {
            "version": self.get_version(),
            "settings": settings.SETTINGS_MODULE,
            "protocol": self.protocol,
            "addr": '[%s]' % self.addr if self._raw_ipv6 else self.addr,
            "port": self.port,
            "quit_command": quit_command,
        })

        try:
            handler = self.get_handler(*args, **options)
            run(self.addr, int(self.port), handler,
                ipv6=self.use_ipv6, threading=threading, server_cls=self.server_cls)
        except socket.error as e:
            # Use helpful error messages instead of ugly tracebacks.
            ERRORS = {
                errno.EACCES: "You don't have permission to access that port.",
                errno.EADDRINUSE: "That port is already in use.",
                errno.EADDRNOTAVAIL: "That IP address can't be assigned to.",
            }
            try:
                error_text = ERRORS[e.errno]
            except KeyError:
                error_text = force_text(e)
            self.stderr.write("Error: %s" % error_text)
            # Need to use an OS exit because sys.exit doesn't work in a thread
            os._exit(1)
        except KeyboardInterrupt:
            if shutdown_message:
                self.stdout.write(shutdown_message)
            sys.exit(0)


# Kept for backward compatibility
BaseRunserverCommand = Command

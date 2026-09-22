"""
WSGI config for core project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/wsgi/
"""

import os
import sys

from django.core.wsgi import get_wsgi_application
from django.core.management import call_command

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

application = get_wsgi_application()

# Safe automated database migration on startup for cloud environments (e.g. Render)
try:
    print("[DEPLOY AUTO-MIGRATE] Running database migrations on server boot...")
    call_command('migrate', interactive=False)
    print("[DEPLOY AUTO-MIGRATE] Database migrations completed successfully.")
except Exception as e:
    print(f"[DEPLOY AUTO-MIGRATE WARNING] Auto-migration skipped or encountered notice: {e}", file=sys.stderr)

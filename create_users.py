import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from api.models import Member

# Allow initial passwords to be configured via environment variable or default
initial_admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
initial_agent_password = os.getenv('AGENT_PASSWORD', 'agent123')

# Create or retrieve Admin
admin, created = Member.objects.get_or_create(
    national_id='11111111',
    defaults={
        'full_name': 'HQ Administrator',
        'phone': '0700000000',
        'is_admin': True,
        'is_staff': True,
        'is_superuser': True,
        'ward': 'Rumuruti Township'
    }
)

if created:
    admin.set_password(initial_admin_password)
    admin.ward = 'Rumuruti Township'
    admin.save()
    print("HQ Admin account created with initial password.")
else:
    # Admin account already exists: preserve the existing password (never overwrite!)
    needs_save = False
    if not (admin.is_admin and admin.is_staff and admin.is_superuser):
        admin.is_admin = True
        admin.is_staff = True
        admin.is_superuser = True
        needs_save = True
    if needs_save:
        admin.save(update_fields=['is_admin', 'is_staff', 'is_superuser'])
    print("HQ Admin account exists: preserved existing password.")

# Create or retrieve Regular Field User
user, user_created = Member.objects.get_or_create(
    national_id='22222222',
    defaults={
        'full_name': 'Field Agent Kamau',
        'phone': '0722222222',
        'is_admin': False,
        'ward': 'Ol-Moran',
        'polling_station': 'Ol Moran Primary School'
    }
)

if user_created:
    user.set_password(initial_agent_password)
    user.ward = 'Ol-Moran'
    user.polling_station = 'Ol Moran Primary School'
    user.save()
    print("Field Agent account created with initial password.")
else:
    print("Field Agent account exists: preserved existing password.")

print("USERS SYNCHRONIZATION COMPLETE")

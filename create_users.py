import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from api.models import Member

# Allow initial passwords to be configured via environment variable or default
initial_admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
initial_agent_password = os.getenv('AGENT_PASSWORD', 'agent123')

# 1. Create or retrieve Admin
admin, created = Member.objects.get_or_create(
    national_id='11111111',
    defaults={
        'full_name': 'HQ Administrator',
        'phone': '0700000000',
        'is_admin': True,
        'is_staff': True,
        'is_superuser': True,
        'ward': 'Rumuruti Township',
        'official_ward': 'Rumuruti Township',
        'campaign_role': 'county_manager',
        'source': 'field_mobilizer',
    }
)

if created:
    admin.set_password(initial_admin_password)
    admin.ward = 'Rumuruti Township'
    admin.official_ward = 'Rumuruti Township'
    admin.campaign_role = 'county_manager'
    admin.source = 'field_mobilizer'
    admin.save()
    print("HQ Admin account created.")
else:
    needs_save = False
    if not (admin.is_admin and admin.is_staff and admin.is_superuser):
        admin.is_admin = True
        admin.is_staff = True
        admin.is_superuser = True
        needs_save = True
    if needs_save:
        admin.save(update_fields=['is_admin', 'is_staff', 'is_superuser'])
    print("HQ Admin account preserved.")

# 2. System Recovered & Seed Members (Mobilizers & Social Recruits)
MEMBERS_SEED = [
    # ─── FIELD MOBILIZERS ──────────────────────────────────────────────────────────
    {
        'full_name': 'Brenda Wangechi Ndirangu',
        'phone': '+254742978982',
        'national_id': '3697095',
        'ward': 'Marmanet',
        'polling_station': 'Karaba Primary School (Station 01)',
        'source': 'field_mobilizer',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'PETER NDIRANGU KURIA',
        'phone': '+254721681383',
        'national_id': '11260660',
        'ward': 'Salama',
        'polling_station': 'Marura Primary School (Station 03)',
        'source': 'field_mobilizer',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Charles Gwandaru Ndirangu',
        'phone': '+254722888632',
        'national_id': '21986445',
        'ward': 'Tigithi',
        'polling_station': 'Riachui Primary School (Station 01)',
        'source': 'field_mobilizer',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Joyce Njeri Kaniu',
        'phone': '+254720666835',
        'national_id': '11427532',
        'ward': 'Nanyuki',
        'polling_station': 'Nanyuki Primary School (Station 04)',
        'source': 'field_mobilizer',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'MICHAEL  KANIU NDIRANGU',
        'phone': '+254758398369',
        'national_id': '39833602',
        'ward': 'Rumuruti Township',
        'polling_station': 'Mutamaiyu Primary School (Station 01)',
        'source': 'field_mobilizer',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Field Agent Kamau',
        'phone': '0722222222',
        'national_id': '22222222',
        'ward': 'Ol-Moran',
        'polling_station': 'Ol Moran Primary School',
        'source': 'field_mobilizer',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': False,
    },
    # ─── ONLINE / SOCIAL RECRUITS (WhatsApp / Public Links) ───────────────────────
    {
        'full_name': 'John Kimtai',
        'phone': '+254748084559',
        'national_id': '29402209',
        'ward': 'Marmanet',
        'polling_station': 'Thiru Primary School (Station 02)',
        'source': 'whatsapp',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Petro Ole Santa',
        'phone': '+254721748758',
        'national_id': '6586621',
        'ward': 'Mukogodo West',
        'polling_station': 'Kimanjo Primary School (Station 01)',
        'source': 'whatsapp',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'Election Volunteer',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Sayyed Salim',
        'phone': '+254113145861',
        'national_id': '36643844',
        'ward': 'Igwamiti',
        'polling_station': '91 Municipality Primary School (Station 03)',
        'source': 'whatsapp',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'Digital Champion',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Anthony Njogu',
        'phone': '+254748084550',
        'national_id': '24999198',
        'ward': 'Nanyuki',
        'polling_station': 'Nturukuma Primary School',
        'source': 'whatsapp',
        'campaign_role': 'station_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
]

for d in MEMBERS_SEED:
    mem, m_created = Member.objects.get_or_create(
        national_id=d['national_id'],
        defaults={
            'full_name': d['full_name'],
            'phone': d['phone'],
            'ward': d['ward'],
            'polling_station': d['polling_station'],
            'official_ward': d['ward'],
            'official_polling_station': d['polling_station'],
            'assigned_ward': d['ward'],
            'assigned_polling_centre': d['polling_station'],
            'source': d['source'],
            'campaign_role': d['campaign_role'],
            'volunteer_role': d['volunteer_role'],
            'is_voter_verified': d['is_voter_verified'],
            'is_admin': False,
            'is_staff': False,
            'is_active': True,
        }
    )
    if m_created and d['national_id'] == '22222222':
        mem.set_password(initial_agent_password)
        mem.save()
    elif not m_created:
        # Preserve existing record & update fields safely
        mem.full_name = d['full_name']
        mem.phone = d['phone']
        mem.ward = d['ward']
        mem.polling_station = d['polling_station']
        mem.official_ward = d['ward']
        mem.official_polling_station = d['polling_station']
        mem.source = d['source']
        mem.campaign_role = d['campaign_role']
        mem.volunteer_role = d['volunteer_role']
        mem.is_voter_verified = d['is_voter_verified']
        mem.is_active = True
        mem.save()
    print(f"Synced member: {d['full_name']} [{d['source']}]")

print("ALL MEMBERS AND ROLES SYNCHRONIZATION COMPLETE")

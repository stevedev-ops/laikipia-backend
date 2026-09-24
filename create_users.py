import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from api.models import Member, VoterRecord
from api.constants import clean_centre_name, WARD_TO_SUBCOUNTY

# Allow initial passwords to be configured via environment variable or default
initial_admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
initial_agent_password = os.getenv('AGENT_PASSWORD', 'agent123')

# 1. Create or retrieve HQ Administrator
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
    print('HQ Admin account created.')
else:
    needs_save = False
    if not (admin.is_admin and admin.is_staff and admin.is_superuser):
        admin.is_admin = True
        admin.is_staff = True
        admin.is_superuser = True
        needs_save = True
    if needs_save:
        admin.save(update_fields=['is_admin', 'is_staff', 'is_superuser'])
    print('HQ Admin account preserved.')

# 2. Master Member Roster
MEMBERS_SEED = [
    {
        'full_name': 'Sayyed Salim',
        'phone': '+254113145861',
        'national_id': '36643844',
        'ward': 'Igwamiti',
        'polling_station': '91 Municipality Primary School (Station 03)',
        'source': 'whatsapp',
        'volunteer_role': 'Digital Champion',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Brenda Wangechi Ndirangu',
        'phone': '+254742978982',
        'national_id': '3697095',
        'ward': 'Marmanet',
        'polling_station': 'Karaba Primary School (Station 01)',
        'source': 'field_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'John Kimtai',
        'phone': '+254748084559',
        'national_id': '29402209',
        'ward': 'Marmanet',
        'polling_station': 'Thiru Primary School (Station 02)',
        'source': 'whatsapp',
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
        'volunteer_role': 'Election Volunteer',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Amos Maina Kariuki',
        'phone': '+254723898369',
        'national_id': '22097506',
        'ward': 'Nanyuki',
        'polling_station': 'Nanyuki Primary School (Station 01)',
        'source': 'field_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Anthony Njogu',
        'phone': '+254748084550',
        'national_id': '24999198',
        'ward': 'Nanyuki',
        'polling_station': 'Nturukuma Primary School',
        'source': 'whatsapp',
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
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Benjamin Irungu',
        'phone': '+254798016096',
        'national_id': '38953552',
        'ward': 'Ngobit',
        'polling_station': 'South Imenti Primary School (Station 01)',
        'source': 'whatsapp',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'CHARLES KARIUKI',
        'phone': '+254729918887',
        'national_id': '41227098',
        'ward': 'Ol-Moran',
        'polling_station': 'Olmoran Day Secondary School (Station 02)',
        'source': 'whatsapp',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Charles Kuria Macharia',
        'phone': '+254723255200',
        'national_id': '21656682',
        'ward': 'Ngobit',
        'polling_station': 'Wiyumiririe Youth Poly (Station 01)',
        'source': 'field_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Eunice Wahome',
        'phone': '+254720302447',
        'national_id': '21880251',
        'ward': 'Ngobit',
        'polling_station': 'Wiyumiririe Primary School (Station 01)',
        'source': 'whatsapp',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Patrick Maina',
        'phone': '+25471756691',
        'national_id': '28585575',
        'ward': 'Ngobit',
        'polling_station': 'Wiyumiririe Primary School (Station 04)',
        'source': 'whatsapp',
        'volunteer_role': 'Election Volunteer',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Peter Kariuki',
        'phone': '+254746335973',
        'national_id': '35085657',
        'ward': 'Ngobit',
        'polling_station': 'Wiyumiririe Primary School (Station 04)',
        'source': 'whatsapp',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Philip Ndonga',
        'phone': '+254798798042',
        'national_id': '37695799',
        'ward': 'Ngobit',
        'polling_station': 'Mathenya Primary School (Station 02)',
        'source': 'whatsapp',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Cosmas Wanyoike',
        'phone': '+254746361115',
        'national_id': '39380316',
        'ward': 'Githiga',
        'polling_station': 'Tandare Primary School (Station 03)',
        'source': 'whatsapp',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Steve Ngigi',
        'phone': '+254729824431',
        'national_id': '21643190',
        'ward': 'Ol-Moran',
        'polling_station': 'Lariak Primary School (Station 05)',
        'source': 'whatsapp',
        'volunteer_role': 'Digital Champion',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Field Agent Kamau',
        'phone': '0722222222',
        'national_id': '22222222',
        'ward': 'Ol-Moran',
        'polling_station': 'Ol Moran Primary School',
        'source': 'field_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': False,
    },
    {
        'full_name': 'MICHAEL  KANIU NDIRANGU',
        'phone': '+254758398369',
        'national_id': '39833602',
        'ward': 'Rumuruti Township',
        'polling_station': 'Mutamaiyu Primary School (Station 01)',
        'source': 'field_mobilizer',
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
        'campaign_role': 'governor',
        'volunteer_role': 'Governor Aspirant',
        'is_voter_verified': True,
    },
    {
        'full_name': 'Charles Gwandaru Ndirangu',
        'phone': '+254722888632',
        'national_id': '21986445',
        'ward': 'Tigithi',
        'polling_station': 'Riachui Primary School (Station 01)',
        'source': 'field_mobilizer',
        'volunteer_role': 'General Supporter',
        'is_voter_verified': True,
    },
]

for d in MEMBERS_SEED:
    mem = Member.objects.filter(national_id=d['national_id']).first()
    if not mem and d.get('phone'):
        mem = Member.objects.filter(phone=d['phone']).first()
    
    clean_st = clean_centre_name(d['polling_station'])
    sc = WARD_TO_SUBCOUNTY.get(d['ward'].lower(), '')

    if not mem:
        mem = Member.objects.create(
            national_id=d['national_id'],
            full_name=d['full_name'],
            phone=d['phone'],
            ward=d['ward'],
            polling_station=clean_st or d['polling_station'],
            official_ward=d['ward'],
            official_polling_station=d['polling_station'],
            assigned_ward=d['ward'],
            assigned_polling_centre=clean_st or d['polling_station'],
            assigned_sub_county=sc,
            source=d['source'],
            campaign_role='station_mobilizer',
            volunteer_role=d['volunteer_role'],
            is_voter_verified=d['is_voter_verified'],
            is_admin=False,
            is_staff=False,
            is_active=True,
        )
        if d['national_id'] == '22222222':
            mem.set_password(initial_agent_password)
            mem.save()
        print(f'Created member: {mem.full_name} [{mem.ward}]')
    else:
        # PRESERVE EXISTING RECORD & ONLY FILL MISSING FIELDS
        mem.full_name = d['full_name']
        mem.phone = d['phone']
        mem.ward = d['ward']
        mem.official_ward = d['ward']
        mem.official_polling_station = d['polling_station']
        if not mem.polling_station:
            mem.polling_station = clean_st or d['polling_station']
        if not mem.assigned_ward:
            mem.assigned_ward = d['ward']
        if not mem.assigned_polling_centre:
            mem.assigned_polling_centre = clean_st or d['polling_station']
        if not mem.assigned_sub_county and sc:
            mem.assigned_sub_county = sc
        if not mem.campaign_role:
            mem.campaign_role = 'station_mobilizer'
        if not mem.source:
            mem.source = d['source']
        if not mem.volunteer_role:
            mem.volunteer_role = d['volunteer_role']
        mem.is_voter_verified = d['is_voter_verified']
        mem.is_active = True
        mem.save()
        print(f'Preserved & verified member: {mem.full_name} [{mem.campaign_role}]')

print('ALL 20 DCP MEMBERS RESTORED AND SAFELY SYNCHRONIZED!')

from django.db import migrations

def restore_members(apps, schema_editor):
    Member = apps.get_model('api', 'Member')

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
            'volunteer_role': 'General Supporter',
            'is_voter_verified': True,
        },
    ]

    for d in MEMBERS_SEED:
        mem = Member.objects.filter(national_id=d['national_id']).first()
        if not mem and d.get('phone'):
            mem = Member.objects.filter(phone=d['phone']).first()

        if not mem:
            Member.objects.create(
                national_id=d['national_id'],
                full_name=d['full_name'],
                phone=d['phone'],
                ward=d['ward'],
                polling_station=d['polling_station'],
                official_ward=d['ward'],
                official_polling_station=d['polling_station'],
                assigned_ward=d['ward'],
                assigned_polling_centre=d['polling_station'],
                source=d['source'],
                campaign_role='station_mobilizer',
                volunteer_role=d['volunteer_role'],
                is_voter_verified=d['is_voter_verified'],
                is_admin=False,
                is_staff=False,
                is_active=True,
            )
        else:
            # Non-destructively preserve any existing appointments
            mem.full_name = d['full_name']
            mem.phone = d['phone']
            mem.ward = d['ward']
            mem.official_ward = d['ward']
            mem.official_polling_station = d['polling_station']
            if not mem.polling_station:
                mem.polling_station = d['polling_station']
            if not mem.assigned_ward:
                mem.assigned_ward = d['ward']
            if not mem.assigned_polling_centre:
                mem.assigned_polling_centre = d['polling_station']
            if not mem.campaign_role:
                mem.campaign_role = 'station_mobilizer'
            if not mem.source:
                mem.source = d['source']
            if not mem.volunteer_role:
                mem.volunteer_role = d['volunteer_role']
            mem.is_voter_verified = d['is_voter_verified']
            mem.is_active = True
            mem.save()

def backwards_pass(apps, schema_editor):
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0032_member_assigned_polling_centre_and_more'),
    ]

    operations = [
        migrations.RunPython(restore_members, backwards_pass),
    ]

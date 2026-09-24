from django.db import migrations

def set_mwalimu_kuria_governor(apps, schema_editor):
    Member = apps.get_model('api', 'Member')

    # Look up Mwalimu Kuria by National ID 11260660 or phone
    kuria = Member.objects.filter(national_id='11260660').first()
    if not kuria:
        kuria = Member.objects.filter(phone__contains='721681383').first()

    if kuria:
        kuria.campaign_role = 'governor'
        kuria.is_admin = True
        kuria.is_staff = True
        kuria.is_active = True
        kuria.assigned_sub_county = None
        kuria.assigned_ward = None
        kuria.assigned_polling_centre = None
        kuria.save()
    else:
        Member.objects.create(
            national_id='11260660',
            full_name='PETER NDIRANGU KURIA',
            phone='+254721681383',
            ward='Salama',
            official_ward='Salama',
            polling_station='Marura Primary School',
            official_polling_station='Marura Primary School (Station 03)',
            campaign_role='governor',
            source='field_mobilizer',
            volunteer_role='Governor Aspirant',
            is_voter_verified=True,
            is_admin=True,
            is_staff=True,
            is_active=True,
        )

def backwards_pass(apps, schema_editor):
    pass

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0033_restore_lost_members'),
    ]

    operations = [
        migrations.RunPython(set_mwalimu_kuria_governor, backwards_pass),
    ]

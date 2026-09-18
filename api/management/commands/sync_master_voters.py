import os
import csv
import time
from django.core.management.base import BaseCommand
from django.conf import settings
from api.models import VoterRecord

class Command(BaseCommand):
    help = 'Sync master reconciled 2022 Laikipia voters into VoterRecord table'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing VoterRecord entries before import',
        )

    def handle(self, *args, **options):
        csv_path = os.path.join(settings.BASE_DIR, 'iebc_data', 'laikipia_master_voters_2022.csv')
        
        if not os.path.exists(csv_path):
            self.stdout.write(self.style.ERROR(f"Master CSV file not found at: {csv_path}"))
            return

        if options['clear']:
            self.stdout.write(self.style.WARNING("Clearing existing VoterRecord entries..."))
            VoterRecord.objects.all().delete()

        self.stdout.write(self.style.NOTICE(f"Loading master voters from {csv_path}..."))
        start_time = time.time()
        
        batch_size = 5000
        batch = []
        total_inserted = 0
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                id_num = row.get('id_number', '').strip()
                phone = row.get('phone_number', '').strip() or None
                full_name = row.get('full_name', '').strip()
                dob = row.get('dob', '').strip()
                gender = row.get('gender', '').strip()
                ward = row.get('ward', '').strip()
                station = row.get('polling_station', '').strip()

                record = VoterRecord(
                    id_number=id_num,
                    phone_number=phone,
                    full_name=full_name,
                    dob=dob,
                    gender=gender,
                    ward=ward,
                    polling_station=station
                )
                batch.append(record)
                
                if len(batch) >= batch_size:
                    VoterRecord.objects.bulk_create(batch, batch_size=batch_size, ignore_conflicts=True)
                    total_inserted += len(batch)
                    batch = []
                    self.stdout.write(f"  Inserted {total_inserted:,} records...")

            if batch:
                VoterRecord.objects.bulk_create(batch, batch_size=batch_size, ignore_conflicts=True)
                total_inserted += len(batch)

        elapsed = time.time() - start_time
        total_in_db = VoterRecord.objects.count()
        self.stdout.write(self.style.SUCCESS(
            f"Successfully synced {total_inserted:,} voter records in {elapsed:.1f}s.\n"
            f"Total VoterRecords in database: {total_in_db:,}"
        ))

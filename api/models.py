import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class MemberManager(BaseUserManager):
    def create_user(self, national_id, full_name, phone, password=None, **extra_fields):
        if not national_id:
            raise ValueError('The National ID must be set')
        user = self.model(national_id=national_id, full_name=full_name, phone=phone, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, national_id, full_name, phone, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)
        return self.create_user(national_id, full_name, phone, password, **extra_fields)

class Member(AbstractBaseUser, PermissionsMixin):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20, unique=True)
    national_id = models.CharField(max_length=20, unique=True)
    email = models.EmailField(blank=True, null=True)
    yob = models.IntegerField(null=True, blank=True)
    gender = models.CharField(max_length=10, blank=True, null=True)
    ward = models.CharField(max_length=255, blank=True, null=True)
    polling_station = models.CharField(max_length=255, blank=True, null=True)
    # Official IEBC names — auto-populated from voter register on match
    official_ward = models.CharField(max_length=255, blank=True, null=True)
    official_polling_station = models.CharField(max_length=255, blank=True, null=True)
    referred_by = models.ForeignKey(
        'self', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='recruits'
    )
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_security = models.BooleanField(default=False)  # True if they are part of the security detail
    SECURITY_RANKS = [
        ('none', 'None'),
        ('guard', 'Guard'),
        ('station_commander', 'Station Commander'),
        ('ward_commander', 'Ward Commander'),
    ]
    security_rank = models.CharField(max_length=50, choices=SECURITY_RANKS, default='none')
    is_security_only = models.BooleanField(default=False)  # If True, locked out of campaign features
    is_active = models.BooleanField(default=True)
    is_opted_out = models.BooleanField(default=False)  # Right to Erasure / Unsubscribe per Kenya DPA 2019
    opted_out_at = models.DateTimeField(null=True, blank=True)
    is_voter_verified = models.BooleanField(default=False)
    has_voted = models.BooleanField(default=False)  # Election-day GOTV strike-off
    
    # Voter Sentiment
    supporter_score = models.IntegerField(null=True, blank=True) # 1-5 scale
    top_issue = models.CharField(max_length=255, null=True, blank=True)

    # Recruitment Source & Volunteer Role
    SOURCE_CHOICES = [
        ('field_mobilizer', 'Field Mobilizer'),
        ('social_media', 'Social Media'),
        ('tiktok', 'TikTok'),
        ('whatsapp', 'WhatsApp'),
        ('facebook', 'Facebook'),
        ('x_twitter', 'X / Twitter'),
        ('website', 'Website'),
    ]
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES, default='field_mobilizer')
    VOLUNTEER_ROLES = [
        ('digital_champion', 'Digital Champion'),
        ('election_volunteer', 'Election Day Volunteer'),
        ('boda_transport', 'Boda-Boda Transport'),
        ('general_supporter', 'General Supporter'),
        ('custom', 'Other / Custom'),
    ]
    volunteer_role = models.CharField(max_length=50, choices=VOLUNTEER_ROLES, blank=True, null=True)
    custom_role = models.CharField(max_length=255, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    objects = MemberManager()

    USERNAME_FIELD = 'national_id'
    REQUIRED_FIELDS = ['full_name', 'phone']

    @property
    def referral_code(self):
        return str(self.uuid)

    def __str__(self):
        return self.full_name

class VoterRecord(models.Model):
    id_number = models.CharField(max_length=20, null=True, blank=True, db_index=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True, db_index=True)
    full_name = models.CharField(max_length=255, db_index=True)
    dob = models.CharField(max_length=100, null=True, blank=True)
    gender = models.CharField(max_length=20, null=True, blank=True)
    ward = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    polling_station = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} ({self.id_number or self.phone_number})"

class Invite(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_role = models.CharField(max_length=50, default='root')
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Invite {self.id} ({self.target_role})"


# ─── Panna Pramukh: Canvass Area Assignments ──────────────────────────────────
class CanvassAssignment(models.Model):
    """Assigns a mobilizer (member) to a specific ward/polling station to canvass."""
    mobilizer = models.ForeignKey(
        Member, on_delete=models.CASCADE, related_name='canvass_assignments'
    )
    ward = models.CharField(max_length=255)
    polling_station = models.CharField(max_length=255, blank=True, null=True)
    target_households = models.IntegerField(default=50)
    notes = models.TextField(blank=True)
    is_completed = models.BooleanField(default=False)
    assigned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.mobilizer.full_name} → {self.polling_station or self.ward}"


# ─── Boda-Boda Transport Requests ────────────────────────────────────────────
class TransportRequest(models.Model):
    """A DCP supporter who needs a ride to the polling station on election day."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('assigned', 'Assigned'),
        ('completed', 'Completed'),
    ]
    member = models.OneToOneField(
        Member, on_delete=models.CASCADE, related_name='transport_request'
    )
    pickup_location = models.CharField(max_length=255)
    ward = models.CharField(max_length=255, blank=True)
    polling_station = models.CharField(max_length=255, blank=True)
    rider_name = models.CharField(max_length=255, blank=True)
    rider_phone = models.CharField(max_length=20, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Ride: {self.member.full_name} from {self.pickup_location}"


# ─── Polling Agent Deployment ─────────────────────────────────────────────────
class PollingAgent(models.Model):
    """Maps a DCP member as a polling agent to a specific station."""
    member = models.ForeignKey(
        Member, on_delete=models.CASCADE, related_name='agent_assignments'
    )
    ward = models.CharField(max_length=255)
    polling_station = models.CharField(max_length=255)
    checked_in = models.BooleanField(default=False)
    check_in_time = models.DateTimeField(null=True, blank=True)
    breakfast_received = models.BooleanField(default=False)
    breakfast_received_at = models.DateTimeField(null=True, blank=True)
    lunch_received = models.BooleanField(default=False)
    lunch_received_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('member', 'polling_station')

    def __str__(self):
        return f"Agent {self.member.full_name} @ {self.polling_station}"


# ─── PVT: Parallel Vote Tabulation ───────────────────────────────────────────
class TallyRecord(models.Model):
    """Vote tally submitted by a field agent from their polling station (Form 34A)."""
    submitted_by = models.ForeignKey(
        Member, on_delete=models.SET_NULL, null=True, related_name='tallies'
    )
    polling_station = models.CharField(max_length=255)
    ward = models.CharField(max_length=255, blank=True)
    dcp_votes = models.IntegerField(default=0)
    uda_votes = models.IntegerField(default=0)
    other_votes = models.IntegerField(default=0)
    total_votes_cast = models.IntegerField(default=0)
    registered_voters = models.IntegerField(default=0)
    is_verified = models.BooleanField(default=False)
    form_34a_image = models.ImageField(upload_to='form_34a/', null=True, blank=True)
    notes = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('polling_station', 'submitted_by')

    def __str__(self):
        return f"Tally: {self.polling_station} — DCP {self.dcp_votes}"


# ─── Ushahidi-Style Incident Reporter ─────────────────────────────────────────
class IncidentReport(models.Model):
    """Tracks election day irregularities, bribery, or KIEMS kit failures."""
    INCIDENT_TYPES = [
        ('kiems_failure', 'KIEMS Kit Failure'),
        ('bribery', 'Voter Bribery'),
        ('violence', 'Intimidation / Violence'),
        ('late_opening', 'Late Opening of Station'),
        ('other', 'Other Irregularity'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
    ]
    reporter = models.ForeignKey(Member, on_delete=models.SET_NULL, null=True, related_name='incidents')
    incident_type = models.CharField(max_length=50, choices=INCIDENT_TYPES)
    ward = models.CharField(max_length=255)
    polling_station = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    image = models.ImageField(upload_to='incident_images/', null=True, blank=True)
    video = models.FileField(upload_to='incident_videos/', null=True, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    reported_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.get_incident_type_display()} at {self.polling_station}"


# ─── Virtual Phone Banking ────────────────────────────────────────────────────
class PhoneBankTarget(models.Model):
    """A voter designated to be called by the remote volunteer phone bank team."""
    STATUS_CHOICES = [
        ('pending', 'Pending Call'),
        ('called', 'Called'),
        ('unreachable', 'Unreachable'),
    ]
    voter_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=20)
    ward = models.CharField(max_length=255, blank=True)
    polling_station = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    assigned_to = models.ForeignKey(Member, on_delete=models.SET_NULL, null=True, blank=True, related_name='phone_bank_assignments')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Target: {self.voter_name} ({self.phone})"

class CallRecord(models.Model):
    """Logs the outcome of a phone bank call."""
    OUTCOME_CHOICES = [
        ('strong_dcp', 'Strong DCP'),
        ('leaning_dcp', 'Leaning DCP'),
        ('undecided', 'Undecided'),
        ('uda', 'Voting UDA'),
        ('not_voting', 'Not Voting'),
        ('wrong_number', 'Wrong Number / Unreachable'),
    ]
    caller = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='calls_made')
    target = models.ForeignKey(PhoneBankTarget, on_delete=models.CASCADE, related_name='call_records')
    outcome = models.CharField(max_length=20, choices=OUTCOME_CHOICES)
    notes = models.TextField(blank=True)
    called_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Call to {self.target.voter_name} - {self.get_outcome_display()}"

# ─── Events & Rally Check-ins ────────────────────────────────────────────────
class Event(models.Model):
    name = models.CharField(max_length=255)
    date = models.DateTimeField()
    location = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} on {self.date.strftime('%Y-%m-%d')}"

class EventAttendance(models.Model):
    event = models.ForeignKey(Event, on_delete=models.CASCADE, related_name='attendees')
    member = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='events_attended')
    checked_in_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('event', 'member')

    def __str__(self):
        return f"{self.member.full_name} at {self.event.name}"

# ─── Emergency Broadcast System ──────────────────────────────────────────────
class EmergencyBroadcast(models.Model):
    """Global alert created by HQ to override all mobilizer screens."""
    SEVERITY_CHOICES = [
        ('warning', 'Warning (Yellow)'),
        ('critical', 'Critical (Red)'),
    ]
    TARGET_CHOICES = [
        ('global', 'Global'),
        ('ward', 'Specific Wards'),
        ('specific_people', 'Specific People'),
    ]
    message = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='critical')
    target_type = models.CharField(max_length=20, choices=TARGET_CHOICES, default='global')
    target_wards = models.JSONField(blank=True, null=True, help_text="List of ward names")
    target_polling_stations = models.JSONField(blank=True, null=True, help_text="List of polling stations")
    target_members = models.ManyToManyField(Member, blank=True, related_name="targeted_broadcasts")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(Member, on_delete=models.SET_NULL, null=True, related_name='broadcasts_created')

    def __str__(self):
        return f"[{self.severity.upper()}] {self.message[:50]}..."

# ─── Security Enhancements (Guards / Post Commands) ──────────────────────────
class SecurityLog(models.Model):
    """Routine status checks (SitReps) and Panic Alerts from Security detail."""
    STATUS_CHOICES = [
        ('all_clear', 'All Clear - Routine'),
        ('crowd_building', 'Crowd Building'),
        ('tense', 'Tense Situation'),
        ('panic', 'PANIC / SEND BACKUP'),
    ]
    guard = models.ForeignKey(Member, on_delete=models.CASCADE, related_name='security_logs')
    ward = models.CharField(max_length=255)
    polling_station = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='all_clear')
    notes = models.TextField(blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    logged_at = models.DateTimeField(auto_now_add=True)
    
    RESOLUTION_CHOICES = [
        ('pending', 'Pending'),
        ('dispatched_police', 'Dispatched Police'),
        ('dispatched_qrt', 'Dispatched QRT'),
        ('false_alarm', 'False Alarm'),
        ('resolved_internally', 'Resolved Internally'),
    ]
    resolution_action = models.CharField(max_length=50, choices=RESOLUTION_CHOICES, default='pending')

    def __str__(self):
        return f"{self.get_status_display()} at {self.polling_station} by {self.guard.full_name}"


# ─── Governor Campaign Diary & Chama Functions ──────────────────────────────
class CampaignFunction(models.Model):
    EVENT_TYPES = [
        ('chama', 'Chama / Table Banking Meeting'),
        ('church', 'Church Service / Harambee'),
        ('funeral', 'Funeral / Burial'),
        ('youth', 'Youth / Sports Tournament'),
        ('women', 'Women Group Baraza'),
        ('market', 'Market Baraza / Townhall'),
        ('rally', 'Major Campaign Rally'),
        ('other', 'Community Function'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending Secretariat Review'),
        ('attending', 'Governor Attending in Person'),
        ('delegated', 'Sending Representative / Delegate'),
        ('declined', 'Declined / Regrets Sent'),
    ]

    CONSTITUENCY_CHOICES = [
        ('Laikipia East', 'Laikipia East'),
        ('Laikipia West', 'Laikipia West'),
        ('Laikipia North', 'Laikipia North'),
    ]

    title = models.CharField(max_length=255)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES, default='chama')
    constituency = models.CharField(max_length=100, choices=CONSTITUENCY_CHOICES, default='Laikipia West')
    ward = models.CharField(max_length=100, blank=True, null=True)
    venue = models.CharField(max_length=255)
    event_date = models.DateField()
    start_time = models.CharField(max_length=50, default='10:00 AM')
    
    # Community Contact Person
    contact_person_name = models.CharField(max_length=255)
    contact_person_phone = models.CharField(max_length=20)
    expected_attendance = models.IntegerField(default=50)
    description = models.TextField(blank=True, null=True)
    
    # Submitted by (Mobilizer or Governor)
    submitted_by = models.ForeignKey(Member, on_delete=models.SET_NULL, null=True, blank=True, related_name='functions_submitted')
    is_created_by_governor = models.BooleanField(default=False)

    # Governor RSVP & Delegation
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')
    delegate_name = models.CharField(max_length=255, blank=True, null=True)
    delegate_phone = models.CharField(max_length=20, blank=True, null=True)
    admin_notes = models.TextField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['event_date', 'start_time']

    def __str__(self):
        return f"{self.title} ({self.event_date}) - {self.get_status_display()}"

class CampaignConfig(models.Model):
    key = models.CharField(max_length=100, unique=True, db_index=True)
    value = models.TextField(blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.key}: {self.value}"



class AuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(Member, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=100, db_index=True)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    user_agent = models.CharField(max_length=500, blank=True, null=True)
    details = models.JSONField(default=dict, blank=True)
    previous_hash = models.CharField(max_length=64, blank=True, default='GENESIS_BLOCK')
    entry_hash = models.CharField(max_length=64, blank=True, db_index=True)

    class Meta:
        ordering = ['-id']

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M')}] {self.action} by {self.user.full_name if self.user else 'Anon'}"

    @classmethod
    def log(cls, action, user=None, request=None, details=None):
        import hashlib, json
        details = details or {}
        ip = "127.0.0.1"
        ua = ""
        if request:
            from api.security import get_client_ip
            ip = get_client_ip(request)
            ua = request.META.get('HTTP_USER_AGENT', '')
            if not user and getattr(request, 'user', None) and request.user.is_authenticated:
                user = request.user

        last_entry = cls.objects.order_by('-id').first()
        prev_hash = last_entry.entry_hash if last_entry and last_entry.entry_hash else "GENESIS_BLOCK"

        entry = cls.objects.create(
            action=action,
            user=user,
            ip_address=ip,
            user_agent=ua[:500] if ua else '',
            details=details,
            previous_hash=prev_hash
        )

        data_string = f"{entry.id}:{entry.timestamp.isoformat()}:{user.id if user else 'ANON'}:{action}:{json.dumps(details, sort_keys=True)}:{prev_hash}"
        entry.entry_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
        entry.save(update_fields=['entry_hash'])
        return entry

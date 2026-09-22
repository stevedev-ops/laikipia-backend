from rest_framework import serializers
from .models import Member, CampaignConfig, Invite, VoterRecord, Event, EventAttendance, EmergencyBroadcast, CampaignFunction

def mask_phone(phone_str):
    if not phone_str:
        return "••••••••"
    p = str(phone_str).strip()
    if len(p) >= 7:
        return p[:4] + ("*" * max(0, len(p) - 6)) + p[-2:]
    return "••••••••"

def mask_id(id_str):
    if not id_str:
        return "••••••••"
    nid = str(id_str).strip()
    if len(nid) >= 4:
        return ("*" * max(0, len(nid) - 2)) + nid[-2:]
    return "••••••••"

class MemberSerializer(serializers.ModelSerializer):
    referral_code = serializers.ReadOnlyField()
    recruits_count = serializers.SerializerMethodField()
    referrer_name = serializers.CharField(source='referred_by.full_name', read_only=True)
    supervisor_name = serializers.CharField(source='supervisor.full_name', read_only=True)
    is_agent = serializers.SerializerMethodField()
    agent_assignment = serializers.SerializerMethodField()

    class Meta:
        model = Member
        fields = [
            'id', 'uuid', 'full_name', 'phone', 'national_id', 'email', 'yob',
            'ward', 'polling_station',
            'official_ward', 'official_polling_station',
            'referral_code', 'referred_by', 'is_voter_verified', 'created_at',
            'recruits_count', 'referrer_name', 'is_admin', 'is_staff', 'is_security', 'security_rank', 'is_security_only',
            'is_agent', 'agent_assignment', 'is_active', 'is_opted_out', 'opted_out_at',
            'supporter_score', 'top_issue', 'source', 'volunteer_role', 'custom_role',
            'campaign_role', 'pillar_category', 'assigned_sub_county', 'assigned_ward',
            'assigned_polling_centre', 'supervisor', 'supervisor_name'
        ]

    def get_is_agent(self, obj):
        return obj.agent_assignments.exists()

    def get_agent_assignment(self, obj):
        pa = obj.agent_assignments.first()
        if not pa:
            return None
        return {
            'id': pa.id,
            'ward': pa.ward,
            'polling_station': pa.polling_station,
            'checked_in': pa.checked_in,
            'check_in_time': pa.check_in_time,
            'breakfast_received': pa.breakfast_received,
            'lunch_received': pa.lunch_received,
            'notes': pa.notes,
        }

    def get_recruits_count(self, obj):
        return obj.recruits.count()

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get('request')
        is_admin = False
        is_self = False

        if request and hasattr(request, 'user') and request.user.is_authenticated:
            is_admin = getattr(request.user, 'is_admin', False) or getattr(request.user, 'is_staff', False) or getattr(request.user, 'is_superuser', False)
            is_self = (request.user.id == instance.id)

        # Non-admins CANNOT see the real phone number or National ID of any other person (even their recruits)
        if not is_admin:
            if not is_self:
                if data.get('national_id'):
                    data['national_id'] = mask_id(data['national_id'])
                if data.get('phone'):
                    data['phone'] = mask_phone(data['phone'])
                if data.get('email'):
                    data['email'] = "••••••••"
        return data

class InviteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invite
        fields = ['id', 'target_role', 'is_used', 'created_at']

class VoterRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = VoterRecord
        fields = ['id', 'id_number', 'phone_number', 'full_name', 'ward', 'polling_station', 'dob', 'gender', 'created_at']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get('request')
        is_admin = False

        if request and hasattr(request, 'user') and request.user.is_authenticated:
            is_admin = getattr(request.user, 'is_admin', False) or getattr(request.user, 'is_staff', False) or getattr(request.user, 'is_superuser', False)

        if not is_admin:
            if data.get('phone_number'):
                data['phone_number'] = mask_phone(data['phone_number'])
            if data.get('id_number'):
                data['id_number'] = mask_id(data['id_number'])
            if data.get('dob'):
                data['dob'] = None
        return data

class EventSerializer(serializers.ModelSerializer):
    attendees_count = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = ['id', 'name', 'date', 'location', 'description', 'created_at', 'attendees_count']

    def get_attendees_count(self, obj):
        return obj.attendees.count()

class EventAttendanceSerializer(serializers.ModelSerializer):
    member_name = serializers.CharField(source='member.full_name', read_only=True)
    member_phone = serializers.CharField(source='member.phone', read_only=True)
    member_ward = serializers.CharField(source='member.ward', read_only=True)

    class Meta:
        model = EventAttendance
        fields = ['id', 'event', 'member', 'checked_in_at', 'member_name', 'member_phone', 'member_ward']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get('request')
        is_admin = False
        if request and hasattr(request, 'user') and request.user.is_authenticated:
            is_admin = getattr(request.user, 'is_admin', False) or getattr(request.user, 'is_staff', False) or getattr(request.user, 'is_superuser', False)
        
        if not is_admin:
            if data.get('member_phone'):
                data['member_phone'] = mask_phone(data['member_phone'])
        return data

class EmergencyBroadcastSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True)

    class Meta:
        model = EmergencyBroadcast
        fields = ['id', 'message', 'severity', 'target_type', 'target_wards', 'target_polling_stations', 'target_members', 'is_active', 'created_at', 'created_by', 'created_by_name']
        read_only_fields = ['created_by']


class CampaignFunctionSerializer(serializers.ModelSerializer):
    submitted_by_name = serializers.CharField(source='submitted_by.full_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)

    class Meta:
        model = CampaignFunction
        fields = [
            'id', 'title', 'event_type', 'event_type_display',
            'constituency', 'ward', 'venue', 'event_date', 'start_time',
            'contact_person_name', 'contact_person_phone', 'expected_attendance',
            'description', 'submitted_by', 'submitted_by_name', 'is_created_by_governor',
            'status', 'status_display', 'delegate_name', 'delegate_phone', 'admin_notes',
            'created_at', 'updated_at'
        ]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get('request')
        is_admin = False
        is_submitter = False

        if request and hasattr(request, 'user') and request.user.is_authenticated:
            is_admin = getattr(request.user, 'is_admin', False) or getattr(request.user, 'is_staff', False) or getattr(request.user, 'is_superuser', False)
            if instance.submitted_by_id and request.user.id == instance.submitted_by_id:
                is_submitter = True

        # If non-admin and not submitter, mask the contact person phone number
        if not is_admin and not is_submitter:
            if data.get('contact_person_phone'):
                data['contact_person_phone'] = mask_phone(data['contact_person_phone'])
        return data

class CampaignConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = CampaignConfig
        fields = ['id', 'key', 'value', 'updated_at']



# ─── 7-Tier Campaign Hierarchy Serializer ──────────────────────────────────
class CampaignPersonnelSerializer(serializers.ModelSerializer):
    supervisor_name = serializers.CharField(source='supervisor.full_name', read_only=True)
    recruits_count = serializers.SerializerMethodField()

    class Meta:
        model = Member
        fields = [
            'id', 'uuid', 'full_name', 'phone', 'national_id', 'campaign_role', 'pillar_category',
            'assigned_sub_county', 'assigned_ward', 'assigned_polling_centre',
            'ward', 'polling_station', 'is_active', 'is_admin', 'created_at',
            'supervisor', 'supervisor_name', 'recruits_count'
        ]

    def get_recruits_count(self, obj):
        return obj.recruits.count()

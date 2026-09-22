import csv
from django.http import HttpResponse
from django.utils import timezone
import json
import uuid
from rest_framework.decorators import api_view, permission_classes

from datetime import timedelta
from rest_framework import status, views, response, generics
from rest_framework.pagination import PageNumberPagination
from django.db.models import Count, Q
from .models import (
    Member, Invite, CampaignConfig, AuditLog, VoterRecord, CanvassAssignment, 
    TransportRequest, PollingAgent, TallyRecord, IncidentReport, PhoneBankTarget, 
    CallRecord, EmergencyBroadcast, SecurityLog
)
from .security import check_rate_limit, check_honeypot, get_client_ip, rate_limit
from .serializers import MemberSerializer, CampaignPersonnelSerializer, CampaignConfigSerializer, InviteSerializer, VoterRecordSerializer, EventSerializer, EmergencyBroadcastSerializer

from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser

from rest_framework.throttling import AnonRateThrottle

class LoginThrottle(AnonRateThrottle):
    scope = 'login'

def get_recursive_downline(member_id, depth_limit=10):
    """
    Returns a tuple of (all_member_ids, max_depth) for the given member's downline.
    """
    all_ids = set()
    max_d = 0
    stack = []
    
    # Get direct recruits first
    direct_recruits = Member.objects.filter(referred_by_id=member_id).values_list('id', flat=True)
    for rid in direct_recruits:
        stack.append((rid, 1))
        all_ids.add(rid)
        max_d = max(max_d, 1)

    while stack:
        mid, depth = stack.pop()
        if depth >= depth_limit:
            continue
            
        recruits = Member.objects.filter(referred_by_id=mid).values_list('id', flat=True)
        for rid in recruits:
            if rid not in all_ids:
                all_ids.add(rid)
                stack.append((rid, depth + 1))
                max_d = max(max_d, depth + 1)
                
    return list(all_ids), max_d

class MemberLoginView(views.APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]
    def post(self, request):
        # Sliding-window rate limit
        allowed, remaining, retry_after = check_rate_limit(request, 'login', max_requests=5, window_seconds=300)
        if not allowed:
            AuditLog.log('LOGIN_RATE_LIMITED', request=request)
            return response.Response({
                "error": "rate_limit_exceeded",
                "message": f"Too many failed login attempts. Please wait {retry_after} seconds before trying again.",
                "retry_after": retry_after
            }, status=status.HTTP_429_TOO_MANY_REQUESTS, headers={"Retry-After": str(retry_after)})

        data = request.data
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        first_name = (data.get('firstName') or data.get('first_name') or '').strip()
        national_id = (data.get('nationalId') or data.get('national_id') or '').strip()

        if not first_name or not national_id:
            return response.Response(
                {"error": "First name and National ID are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        member = Member.objects.filter(
            national_id=national_id,
            full_name__istartswith=first_name
        ).first()

        if not member:
            AuditLog.log('LOGIN_FAILED', request=request, details={'national_id': national_id, 'first_name': first_name})
            return response.Response(
                {"error": "No member found with that First Name and ID combination."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not member.is_active:
            return response.Response(
                {"error": "ACCESS DENIED: Your account has been permanently deactivated by HQ."},
                status=status.HTTP_404_NOT_FOUND
            )

        # All active registered members can log in

        token, _ = Token.objects.get_or_create(user=member)
        AuditLog.log('LOGIN_SUCCESS', user=member, request=request)
        return response.Response({
            "token": token.key,
            "member": MemberSerializer(member, context={'request': request}).data
        })

class MemberRegisterView(views.APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # 1. Anti-Bot Honeypot Trap
        if check_honeypot(request):
            AuditLog.log('BOT_TRAPPED', request=request, details={'fields': list((request.data or {}).keys())})
            # Silently accept to mislead automated bot scrapers
            return response.Response({
                "success": True,
                "message": "Registration received and queued for review."
            }, status=status.HTTP_200_OK)

        # 2. Rate Limit (15 per minute per IP)
        allowed, remaining, retry_after = check_rate_limit(request, 'register', max_requests=15, window_seconds=60)
        if not allowed:
            return response.Response({
                "error": "rate_limit_exceeded",
                "message": f"Registration request limit reached. Please wait {retry_after} seconds before trying again.",
                "retry_after": retry_after
            }, status=status.HTTP_429_TOO_MANY_REQUESTS, headers={"Retry-After": str(retry_after)})

        data = request.data.copy()
        referrer_raw = data.get('referred_by')
        invite_token = data.get('invite_token')

        # Resolve UUID or legacy ID to internal Foreign Key
        referrer_id = None
        if referrer_raw:
            ref_member = None
            try:
                uuid_obj = uuid.UUID(str(referrer_raw))
                ref_member = Member.objects.filter(uuid=uuid_obj).first()
            except (ValueError, AttributeError):
                pass
            if not ref_member and str(referrer_raw).isdigit():
                ref_member = Member.objects.filter(pk=int(referrer_raw)).first()
            if ref_member:
                referrer_id = ref_member.id
        # If social source and no explicit referrer, keep referred_by as None
        raw_source = str(data.get('source', 'field_mobilizer')).strip().lower()
        if raw_source in ['x', 'twitter', 'x_twitter']:
            source_val = 'x_twitter'
        elif raw_source in ['wa', 'whatsapp']:
            source_val = 'whatsapp'
        elif raw_source in ['tt', 'tiktok']:
            source_val = 'tiktok'
        elif raw_source in ['fb', 'facebook']:
            source_val = 'facebook'
        elif raw_source in ['web', 'website']:
            source_val = 'website'
        elif raw_source in ['social', 'social_media']:
            source_val = 'social_media'
        else:
            source_val = raw_source or 'field_mobilizer'

        data['source'] = source_val
        if source_val != 'field_mobilizer' and not referrer_raw:
            referrer_id = None
        data['referred_by'] = referrer_id
        
        # SECURITY FIX: Force is_admin to False for all public registrations
        data['is_admin'] = False
        data['is_staff'] = False
        data['is_superuser'] = False

        # 1. Quota Check
        if referrer_id and not invite_token:
            try:
                referrer = Member.objects.get(id=referrer_id)
                quota = 10 if referrer.referred_by is None else 5
                current_count = referrer.recruits.count()
                if current_count >= quota:
                    return response.Response(
                        {"error": f"Recruiter has reached their quota of {quota} members."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except Member.DoesNotExist:
                return response.Response({"error": "Invalid referrer."}, status=status.HTTP_400_BAD_REQUEST)

        # 2. Duplicate Check with rich response for lockout & mobilizer claim
        existing_member = Member.objects.filter(Q(phone=data.get('phone')) | Q(national_id=data.get('national_id'))).first()
        if existing_member:
            return response.Response({
                "error": "already_registered",
                "message": "Phone Number or National ID already registered in DCP Laikipia.",
                "member_name": existing_member.full_name,
                "has_referrer": existing_member.referred_by is not None,
                "referrer_name": existing_member.referred_by.full_name if existing_member.referred_by else None,
                "ward": existing_member.ward,
                "polling_station": existing_member.polling_station,
                "source": getattr(existing_member, 'source', 'field_mobilizer')
            }, status=status.HTTP_409_CONFLICT)

        # 3. Check Voter Register with enhanced matching FIRST
        national_id = data.get('national_id', '')
        phone = data.get('phone', '')
        full_name = data.get('full_name', '')
        matched_record = None

        # Direct match first
        direct = VoterRecord.objects.filter(
            Q(id_number=national_id) | Q(phone_number=phone)
        ).first()
        
        if direct:
            matched_record = direct

        if not matched_record and national_id:
            # Try masked ID matching (checking first and last digits)
            id_len = len(national_id)
            if id_len >= 5:
                id_pattern = f"{national_id[0]}{'*' * (id_len - 2)}{national_id[-1]}"
                name_parts = [p for p in full_name.upper().split(' ') if len(p) > 2]
                potential_matches = list(VoterRecord.objects.filter(id_number=id_pattern))

                # Pass 1: 2+ name parts
                for record in potential_matches:
                    record_name_upper = record.full_name.upper()
                    if sum(1 for part in name_parts if part in record_name_upper) >= 2:
                        matched_record = record
                        break

                # Pass 2: 1 name part fallback
                if not matched_record:
                    for record in potential_matches:
                        record_name_upper = record.full_name.upper()
                        if sum(1 for part in name_parts if part in record_name_upper) >= 1:
                            matched_record = record
                            break

        is_security_deployment = data.get('is_security_only', False)
        # Any supporter can register whether matched in voter roll or not

        # 4. Invite Token Check
        if invite_token:
            try:
                invite = Invite.objects.get(id=invite_token)
                if invite.is_used:
                    return response.Response({"error": "Invite already used."}, status=status.HTTP_400_BAD_REQUEST)
                invite.is_used = True
                invite.save()
            except (Invite.DoesNotExist, ValueError):
                return response.Response({"error": "Invalid invite code."}, status=status.HTTP_400_BAD_REQUEST)

        # 5. Create Member
        serializer = MemberSerializer(data=data)
        if serializer.is_valid():
            member = serializer.save()
            
            if not is_security_deployment and matched_record:
                member.is_voter_verified = True
                member.official_ward = matched_record.ward or ''
                member.official_polling_station = matched_record.polling_station or ''
                if matched_record.gender:
                    member.gender = matched_record.gender
                member.save()

                matched_record.id_number = member.national_id
                matched_record.phone_number = member.phone
                matched_record.save(update_fields=['id_number', 'phone_number'])
            else:
                member.is_voter_verified = False
                member.save()

            token, _ = Token.objects.get_or_create(user=member)
            return response.Response({
                "token": token.key,
                "member": serializer.data
            }, status=status.HTTP_201_CREATED)
            
        # If we failed to save, un-use the invite
        if invite_token:
            Invite.objects.filter(id=invite_token).update(is_used=False)
            
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MemberMeView(views.APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return response.Response(MemberSerializer(request.user, context={'request': request}).data)

class MemberPublicView(views.APIView):
    permission_classes = [AllowAny]
    def get(self, request, identifier=None, pk=None, **kwargs):
        target = identifier or pk or kwargs.get('identifier') or kwargs.get('pk')
        member = None
        if target:
            try:
                uuid_obj = uuid.UUID(str(target))
                member = Member.objects.filter(uuid=uuid_obj).first()
            except (ValueError, AttributeError):
                pass
            if not member and str(target).isdigit():
                member = Member.objects.filter(pk=int(target)).first()

        if not member:
            return response.Response({"error": "Member not found"}, status=status.HTTP_404_NOT_FOUND)

        return response.Response({
            "id": str(member.uuid),
            "full_name": member.full_name,
            "ward": member.ward,
            "polling_station": member.polling_station,
            "recruits_count": member.recruits.count(),
            "referral_code": str(member.uuid)
        })

class MemberInsightsView(views.APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        if not request.user.is_admin and request.user.id != int(pk):
            return response.Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        try:
            member = Member.objects.get(pk=pk)
        except Member.DoesNotExist:
            return response.Response({"error": "Member not found"}, status=status.HTTP_404_NOT_FOUND)

        # Lineage (Walking up)
        lineage = []
        curr = member
        while curr:
            lineage.insert(0, MemberSerializer(curr, context={'request': request}).data)
            curr = curr.referred_by
            if len(lineage) > 10: break # Safety break

        # Network Size & Depth (Recursive)
        network_ids, network_depth = get_recursive_downline(member.id)
        
        return response.Response({
            "member_id": member.id,
            "tier": len(lineage),
            "network_size": len(network_ids),
            "network_depth": network_depth,
            "direct_invites": member.recruits.count(),
            "lineage": lineage,
            "direct_inviter": lineage[-2] if len(lineage) > 1 else None,
            "top_mobilizer": lineage[0] if lineage else None
        })

class MemberListView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = Member.objects.all().order_by('-id')
    serializer_class = MemberSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        referred_by = self.request.query_params.get('referred_by')
        if referred_by:
            if referred_by == 'null':
                # Root mobilizers MUST be field mobilizers, NEVER online/social media signups
                queryset = queryset.filter(referred_by__isnull=True, source='field_mobilizer')
            else:
                queryset = queryset.filter(referred_by=referred_by)

        is_digital = self.request.query_params.get('is_digital')
        if is_digital == 'true':
            queryset = queryset.exclude(source='field_mobilizer')
        elif is_digital == 'false':
            queryset = queryset.filter(source='field_mobilizer')

        ward = self.request.query_params.get('ward')
        if ward and ward.strip() and ward.strip().lower() != 'all':
            queryset = queryset.filter(Q(ward__iexact=ward.strip()) | Q(official_ward__iexact=ward.strip()))

        source = self.request.query_params.get('source')
        if source and source.strip() and source.strip().lower() != 'all':
            s_val = source.strip().lower()
            if s_val in ['x', 'twitter', 'x_twitter']:
                queryset = queryset.filter(Q(source='x_twitter') | Q(source='x') | Q(source='twitter'))
            elif s_val in ['social', 'social_media', 'social_link', 'web', 'website']:
                queryset = queryset.filter(Q(source='social_media') | Q(source='social') | Q(source='website') | Q(source='web'))
            elif s_val in ['wa', 'whatsapp']:
                queryset = queryset.filter(Q(source='whatsapp') | Q(source='wa'))
            elif s_val in ['tt', 'tiktok']:
                queryset = queryset.filter(Q(source='tiktok') | Q(source='tt'))
            elif s_val in ['fb', 'facebook']:
                queryset = queryset.filter(Q(source='facebook') | Q(source='fb'))
            else:
                queryset = queryset.filter(source__iexact=s_val)

        # ALWAYS filter out admins and staff from the public member lists
        queryset = queryset.filter(is_admin=False, is_staff=False)

        if not self.request.user.is_admin:
            # Regular users can only see their direct recruits
            queryset = queryset.filter(referred_by=self.request.user)
        
        search = self.request.query_params.get('search')
        if search:
            search = search.strip()
            if search.isdigit():
                queryset = queryset.filter(Q(national_id__icontains=search))
            else:
                name_parts = [p for p in search.split(' ') if p]
                for part in name_parts:
                    queryset = queryset.filter(
                        Q(full_name__icontains=part) | Q(national_id__icontains=part)
                    )
        
        voter_status = self.request.query_params.get('voter_status')
        if voter_status == 'verified':
            queryset = queryset.filter(is_voter_verified=True)
        elif voter_status == 'unverified':
            queryset = queryset.filter(is_voter_verified=False)
            
        sort = self.request.query_params.get('sort')
        if sort == 'voter_status':
            queryset = queryset.order_by('-is_voter_verified', '-id')
        elif sort == 'voter_status_asc':
            queryset = queryset.order_by('is_voter_verified', '-id')
            
        return queryset
class MemberExportCsvView(views.APIView):
    """
    Exports a clean CSV file with Name, Phone, Ward, Station, Source, Volunteer Role
    specifically formatted for calling or bulk SMS broadcasting.
    Supports filtering by ward, source, voter status, search, and referred_by.
    """
    permission_classes = [IsAdminUser]

    def get(self, request):
        allowed, remaining, retry_after = check_rate_limit(request, 'export_csv', max_requests=25, window_seconds=3600, extra_key=str(request.user.id))
        if not allowed:
            return response.Response({
                "error": "rate_limit_exceeded",
                "message": f"CSV export rate limit reached. Please wait {retry_after} seconds before requesting another export.",
                "retry_after": retry_after
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        ward = request.query_params.get('ward', '').strip()
        source = request.query_params.get('source', '').strip()
        voter_status = request.query_params.get('voter_status', '').strip()
        search = request.query_params.get('search', '').strip()
        referred_by = request.query_params.get('referred_by', '').strip()
        is_digital = request.query_params.get('is_digital', '').strip()

        qs = Member.objects.filter(is_admin=False, is_staff=False).select_related('referred_by')

        if is_digital == 'true':
            qs = qs.exclude(source='field_mobilizer')
        elif is_digital == 'false':
            qs = qs.filter(source='field_mobilizer')

        if referred_by == 'null':
            qs = qs.filter(referred_by__isnull=True, source='field_mobilizer')
        elif referred_by.isdigit():
            qs = qs.filter(referred_by_id=int(referred_by))

        if ward and ward.lower() != 'all':
            qs = qs.filter(Q(ward__iexact=ward) | Q(official_ward__iexact=ward))

        if source and source.lower() != 'all':
            s_val = source.lower()
            if s_val in ['x', 'twitter', 'x_twitter']:
                qs = qs.filter(Q(source='x_twitter') | Q(source='x') | Q(source='twitter'))
            elif s_val in ['social', 'social_media', 'social_link', 'web', 'website']:
                qs = qs.filter(Q(source='social_media') | Q(source='social') | Q(source='website') | Q(source='web'))
            elif s_val in ['wa', 'whatsapp']:
                qs = qs.filter(Q(source='whatsapp') | Q(source='wa'))
            elif s_val in ['tt', 'tiktok']:
                qs = qs.filter(Q(source='tiktok') | Q(source='tt'))
            elif s_val in ['fb', 'facebook']:
                qs = qs.filter(Q(source='facebook') | Q(source='fb'))
            else:
                qs = qs.filter(source__iexact=s_val)

        if search:
            if search.isdigit():
                qs = qs.filter(Q(national_id__icontains=search) | Q(phone__icontains=search))
            else:
                for part in [p for p in search.split(' ') if p]:
                    qs = qs.filter(
                        Q(full_name__icontains=part) | Q(national_id__icontains=part) | Q(phone__icontains=part)
                    )

        if voter_status == 'verified':
            qs = qs.filter(is_voter_verified=True)
        elif voter_status == 'unverified':
            qs = qs.filter(is_voter_verified=False)

        # Kenya DPA Opt-Out filter (defaults to True: strictly excludes supporters who requested STOP / erasure)
        exclude_opted_out = request.query_params.get('exclude_opted_out', 'true').strip().lower() != 'false'
        if exclude_opted_out:
            qs = qs.filter(is_opted_out=False)

        response_file = HttpResponse(content_type='text/csv; charset=utf-8')
        ward_label = ward.replace(' ', '_').lower() if ward and ward.lower() != 'all' else 'all_wards'
        source_label = f"_{source.lower()}" if source and source.lower() != 'all' else ("_all_channels" if is_digital == 'true' else "")
        filename = f"dcp_members_call_sms{source_label}_{ward_label}_{timezone.now().strftime('%Y%m%d_%H%M')}.csv"
        response_file['Content-Disposition'] = f'attachment; filename="{filename}"'
        response_file['Access-Control-Expose-Headers'] = 'Content-Disposition'

        writer = csv.writer(response_file)
        writer.writerow([
            'Full Name',
            'Phone (Call / SMS)',
            'Ward',
            'Polling Station / Center',
            'Recruitment Source',
            'Volunteer Role',
            'Custom Skills / Notes',
            'Assigned Mobilizer',
            'Verified 2022 Voter',
            'DPA Consent / Opt-Out Status',
            'National ID',
            'Registration Date'
        ])

        rows_count = 0
        for m in qs.order_by('ward', 'full_name'):
            rows_count += 1
            writer.writerow([
                m.full_name,
                m.phone,
                m.official_ward or m.ward or '',
                m.official_polling_station or m.polling_station or '',
                m.source or 'field_mobilizer',
                (m.volunteer_role or 'general_supporter').replace('_', ' ').title(),
                m.custom_role or '',
                m.referred_by.full_name if m.referred_by else 'Root / Direct',
                'Yes' if m.is_voter_verified else 'No',
                'Opted Out (DPA Restricted)' if m.is_opted_out else 'Active Consent',
                m.national_id or '',
                m.created_at.strftime('%Y-%m-%d %H:%M') if m.created_at else ''
            ])

        AuditLog.log('CSV_EXPORT', user=request.user, request=request, details={
            'ward': ward or 'all',
            'source': source or 'all',
            'is_digital': is_digital,
            'rows_exported': rows_count,
            'filename': filename
        })

        return response_file

class MemberDetailView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, pk):
        try:
            member = Member.objects.get(pk=pk)
            return response.Response(MemberSerializer(member, context={'request': request}).data)
        except Member.DoesNotExist:
            return response.Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, pk):
        """Only allows updating referred_by (for Promote to Root feature)."""
        try:
            member = Member.objects.get(pk=pk)
        except Member.DoesNotExist:
            return response.Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        allowed_fields = {'referred_by'}
        data = {k: v for k, v in request.data.items() if k in allowed_fields}

        if 'referred_by' in data:
            val = data['referred_by']
            if val is None or val == 'null' or val == '':
                member.referred_by = None
            else:
                try:
                    member.referred_by = Member.objects.get(pk=val)
                except Member.DoesNotExist:
                    return response.Response({"error": "Referrer not found"}, status=status.HTTP_400_BAD_REQUEST)

        member.save()
        return response.Response(MemberSerializer(member, context={'request': request}).data)

class VoterRecordPagination(PageNumberPagination):
    page_size = 50

class VoterRecordListView(generics.ListAPIView):
    permission_classes = [IsAdminUser]
    queryset = VoterRecord.objects.all().order_by('full_name')
    serializer_class = VoterRecordSerializer
    pagination_class = VoterRecordPagination

    def get_queryset(self):
        queryset = super().get_queryset()
        search = self.request.query_params.get('search')
        if search:
            search = search.strip()
            if search.isdigit():
                queryset = queryset.filter(
                    Q(id_number__icontains=search) | 
                    Q(phone_number__icontains=search)
                )
            else:
                name_parts = [p for p in search.split(' ') if p]
                for part in name_parts:
                    queryset = queryset.filter(
                        Q(full_name__icontains=part) | 
                        Q(id_number__icontains=part) | 
                        Q(phone_number__icontains=part) |
                        Q(ward__icontains=part)
                    )
        
        ward = self.request.query_params.get('ward')
        if ward:
            queryset = queryset.filter(ward__icontains=ward)
            
        return queryset

class ReportStatsView(views.APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        if not request.user.is_admin:
            # Force scoping to mobilizer's own tree
            member_id = request.user.id
        else:
            member_id = request.query_params.get('member_id')
        mode = request.query_params.get('mode', 'all')  # all | verified | unverified

        base_qs = Member.objects.filter(is_admin=False, is_staff=False)
        if member_id:
            downline_ids, _ = get_recursive_downline(member_id)
            # Include direct recruits AND their downline
            base_qs = base_qs.filter(id__in=downline_ids)
        elif not request.user.is_admin:
            downline_ids, _ = get_recursive_downline(request.user.id)
            base_qs = base_qs.filter(id__in=downline_ids)

        if mode == 'verified':
            queryset = base_qs.filter(is_voter_verified=True)
            ward_field = 'official_ward'
            station_field = 'official_polling_station'
        elif mode == 'unverified':
            queryset = base_qs.filter(is_voter_verified=False)
            ward_field = 'ward'
            station_field = 'polling_station'
        else:  # all
            queryset = base_qs
            ward_field = 'ward'
            station_field = 'polling_station'

        ward_summary = queryset.values(ward_field).annotate(count=Count('id')).order_by('-count')
        polling_summary = queryset.values(station_field, ward_field).annotate(count=Count('id')).order_by('-count')

        ward_res = [{"ward": item[ward_field] or "Unknown", "count": item['count']} for item in ward_summary]
        polling_res = [
            {
                "station": item[station_field] or "Unknown",
                "ward": item[ward_field] or "Unknown",
                "count": item['count']
            }
            for item in polling_summary
        ]

        return response.Response({
            "ward_summary": ward_res,
            "polling_summary": polling_res,
            "total": queryset.count(),
            "mode": mode,
        })

class SystemStatsView(views.APIView):
    permission_classes = [IsAdminUser]
    def get(self, request):
        total = Member.objects.filter(is_admin=False, is_staff=False).count()
        roots = Member.objects.filter(referred_by__isnull=True, is_admin=False, is_staff=False).count()
        verified = Member.objects.filter(is_voter_verified=True, is_admin=False, is_staff=False).count()
        unverified = total - verified
        
        return response.Response({
            "total_registered": total,
            "total_roots": roots,
            "verified_voters": verified,
            "unverified_new": unverified,
        })

class InviteCreateView(generics.CreateAPIView):
    permission_classes = [IsAdminUser]
    queryset = Invite.objects.all()
    serializer_class = InviteSerializer

class InviteDetailView(generics.RetrieveAPIView):
    permission_classes = [AllowAny]
    queryset = Invite.objects.all()
    serializer_class = InviteSerializer
    lookup_field = 'id'

class VoterLookupView(views.APIView):
    """
    Lookup voter in official IEBC register for self-enrollment and mobilizers.
    Protected against mass scraping via sliding-window rate limiting,
    minimum query lengths, and serializer masking for public requests.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        query = request.query_params.get('q', '').strip()
        if not query:
            return response.Response([])

        is_auth = bool(request.user and request.user.is_authenticated)

        # 1. Sliding-window rate limiting (strict for public self-enrollment, relaxed for mobilizers)
        if not is_auth:
            allowed, remaining, retry_after = check_rate_limit(
                request, 'voter_lookup_public', max_requests=8, window_seconds=60
            )
            if not allowed:
                return response.Response({
                    "error": "rate_limit_exceeded",
                    "message": f"Too many searches. Please wait {retry_after} seconds before trying again.",
                    "retry_after": retry_after
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        else:
            allowed, remaining, retry_after = check_rate_limit(
                request, 'voter_lookup_auth', max_requests=60, window_seconds=60
            )
            if not allowed:
                return response.Response({
                    "error": "rate_limit_exceeded",
                    "message": "Search limit reached. Please slow down."
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        # 2. Query validation to prevent broad harvesting by bots
        if not is_auth:
            # If numeric (National ID or Phone search), require at least 5 digits to block prefix dumping
            if query.isdigit() and len(query) < 5:
                return response.Response([])
            # If name search, require at least 3 characters
            if not query.isdigit() and len(query) < 3:
                return response.Response([])

        # Handle numeric queries (ID/Phone)
        if query.isdigit() and len(query) >= 3:
            queryset = VoterRecord.objects.filter(
                Q(id_number__icontains=query) | Q(phone_number__icontains=query)
            )[:15]
            return response.Response(VoterRecordSerializer(queryset, many=True, context={'request': request}).data)

        # Name-based search (match all name parts of length >= 2)
        name_parts = [p for p in query.upper().split(' ') if len(p) >= 2]
        if not name_parts:
            return response.Response([])
        
        queryset = VoterRecord.objects.all()
        for part in name_parts:
            queryset = queryset.filter(
                Q(full_name__icontains=part) | 
                Q(id_number__icontains=part) | 
                Q(phone_number__icontains=part)
            )
        
        queryset = queryset[:15]

        serializer = VoterRecordSerializer(queryset, many=True, context={'request': request})
        return response.Response(serializer.data)


# ─── Polling Station Coverage ────────────────────────────────────────────────
class PollingCoverageView(views.APIView):
    """
    Returns DCP member count per ward and polling station,
    mapped against the known 142-station Laikipia register.
    Accessible to all authenticated members.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        base = Member.objects.filter(is_admin=False, is_staff=False)

        # Ward-level summary
        ward_summary = (
            base.values('ward')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        # Polling station breakdown (both self-reported and IEBC-verified)
        station_all = (
            base.values('polling_station', 'ward')
            .annotate(count=Count('id'))
            .order_by('-count')
        )
        station_verified = (
            base.filter(is_voter_verified=True)
            .values('official_polling_station', 'official_ward')
            .annotate(count=Count('id'))
            .order_by('-count')
        )

        return response.Response({
            'total': base.count(),
            'verified': base.filter(is_voter_verified=True).count(),
            'ward_summary': [
                {'ward': r['ward'] or 'Unknown', 'count': r['count']}
                for r in ward_summary
            ],
            'station_all': [
                {
                    'station': r['polling_station'] or 'Unknown',
                    'ward': r['ward'] or 'Unknown',
                    'count': r['count'],
                }
                for r in station_all
            ],
            'station_verified': [
                {
                    'station': r['official_polling_station'] or 'Unknown',
                    'ward': r['official_ward'] or 'Unknown',
                    'count': r['count'],
                }
                for r in station_verified
            ],
        })


# ─── Recruiter Leaderboard ───────────────────────────────────────────────────
class LeaderboardView(views.APIView):
    """
    Returns top 20 mobilizers by direct recruits and ward-level totals.
    Accessible to all authenticated members.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Top mobilizers (direct invites, excluding admins/staff)
        from datetime import timedelta
        now = timezone.now()
        seven_days_ago = now - timedelta(days=7)

        top_members = (
            Member.objects
            .filter(is_admin=False, is_staff=False)
            .annotate(
                recruits_total=Count('recruits'),
                recent_recruits_count=Count('recruits', filter=Q(recruits__created_at__gte=seven_days_ago))
            )
            .order_by('-recruits_total')[:20]
        )

        # Ward totals for ward leaderboard
        ward_totals = (
            Member.objects
            .filter(is_admin=False, is_staff=False)
            .values('ward')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )

        return response.Response({
            'top_mobilizers': [
                {
                    'rank': idx + 1,
                    'id': m.id,
                    'full_name': m.full_name,
                    'is_active': m.is_active,
                    'ward': m.ward or 'Unknown',
                    'polling_station': m.polling_station or 'Unknown',
                    'direct_recruits': m.recruits_total,
                    'is_root': m.referred_by_id is None,
                }
                for idx, m in enumerate(top_members)
            ],
            'ward_totals': [
                {'ward': r['ward'] or 'Unknown', 'count': r['count']}
                for r in ward_totals
            ],
        })


# ─── GOTV Election Day Strike-off ────────────────────────────────────────────
class GotvListView(views.APIView):
    """
    Admin-only: Returns DCP members at a given polling station
    for the election-day strike-off tool.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        station = request.query_params.get('station', '').strip()
        ward    = request.query_params.get('ward', '').strip()

        qs = Member.objects.filter(is_admin=False, is_staff=False)
        if station:
            qs = qs.filter(
                Q(polling_station__icontains=station) |
                Q(official_polling_station__icontains=station)
            )
        if ward:
            qs = qs.filter(
                Q(ward__icontains=ward) |
                Q(official_ward__icontains=ward)
            )

        return response.Response([
            {
                'id': m.id,
                'full_name': m.full_name,
                    'is_active': m.is_active,
                'ward': m.official_ward or m.ward or 'Unknown',
                'polling_station': m.official_polling_station or m.polling_station or 'Unknown',
                'has_voted': m.has_voted,
                'is_voter_verified': m.is_voter_verified,
            }
            for m in qs.order_by('full_name')
        ])


class GotvMarkVotedView(views.APIView):
    """
    Authenticated agents mark a DCP supporter as voted.
    PATCH /api/gotv/<pk>/voted
    """
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            member = Member.objects.get(pk=pk, is_admin=False, is_staff=False)
        except Member.DoesNotExist:
            return response.Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

        member.has_voted = not member.has_voted   # Toggle
        member.save(update_fields=['has_voted'])
        return response.Response({
            'id': member.id,
            'full_name': member.full_name,
            'has_voted': member.has_voted,
        })


import datetime

# ─── Panna Pramukh: Canvass Assignments ──────────────────────────────────────
class CanvassListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = CanvassAssignment.objects.select_related('mobilizer').all()
        member_id = request.query_params.get('member')
        if member_id:
            qs = qs.filter(mobilizer_id=member_id)
        if not request.user.is_admin:
            qs = qs.filter(mobilizer=request.user)
        return response.Response([
            {
                'id': a.id,
                'mobilizer_id': a.mobilizer_id,
                'mobilizer_name': a.mobilizer.full_name,
                'ward': a.ward,
                'polling_station': a.polling_station or '',
                'target_households': a.target_households,
                'notes': a.notes,
                'is_completed': a.is_completed,
                'assigned_at': a.assigned_at,
            }
            for a in qs.order_by('-assigned_at')
        ])

    def post(self, request):
        d = request.data
        try:
            mob = Member.objects.get(pk=d['mobilizer_id'])
        except Member.DoesNotExist:
            return response.Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)
        a = CanvassAssignment.objects.create(
            mobilizer=mob,
            ward=d.get('ward', ''),
            polling_station=d.get('polling_station', ''),
            target_households=int(d.get('target_households', 50)),
            notes=d.get('notes', ''),
        )
        return response.Response({'id': a.id, 'message': 'Assignment created'}, status=status.HTTP_201_CREATED)


class CanvassDetailView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            a = CanvassAssignment.objects.get(pk=pk)
        except CanvassAssignment.DoesNotExist:
            return response.Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        a.is_completed = not a.is_completed
        a.save(update_fields=['is_completed'])
        return response.Response({'id': a.id, 'is_completed': a.is_completed})

    def delete(self, request, pk):
        try:
            CanvassAssignment.objects.get(pk=pk).delete()
        except CanvassAssignment.DoesNotExist:
            pass
        return response.Response(status=status.HTTP_204_NO_CONTENT)


# ─── Boda-Boda Transport ─────────────────────────────────────────────────────
class TransportListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ward = request.query_params.get('ward', '')
        qs = TransportRequest.objects.select_related('member').all()
        if ward:
            qs = qs.filter(ward__icontains=ward)
        if not request.user.is_admin:
            qs = qs.filter(member=request.user)
        return response.Response([
            {
                'id': t.id,
                'member_id': t.member_id,
                'member_name': t.member.full_name,
                'phone': t.member.phone,
                'pickup_location': t.pickup_location,
                'ward': t.ward,
                'polling_station': t.polling_station,
                'rider_name': t.rider_name,
                'rider_phone': t.rider_phone,
                'status': t.status,
                'created_at': t.created_at,
            }
            for t in qs.order_by('ward', 'polling_station')
        ])

    def post(self, request):
        member = request.user
        if not member.is_admin and not member.agent_assignments.exists():
            return response.Response(
                {"error": "ACCESS DENIED: Form 34A PVT tally upload is strictly restricted to accredited Polling Agents."},
                status=status.HTTP_403_FORBIDDEN
            )
        d = request.data
        tr, created = TransportRequest.objects.get_or_create(
            member=member,
            defaults={
                'pickup_location': d.get('pickup_location', ''),
                'ward': d.get('ward', member.ward or ''),
                'polling_station': d.get('polling_station', member.polling_station or ''),
            }
        )
        return response.Response(
            {'id': tr.id, 'created': created},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )


class TransportUpdateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            t = TransportRequest.objects.get(pk=pk)
        except TransportRequest.DoesNotExist:
            return response.Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        t.status = request.data.get('status', t.status)
        t.rider_name = request.data.get('rider_name', t.rider_name)
        t.rider_phone = request.data.get('rider_phone', t.rider_phone)
        t.save(update_fields=['status', 'rider_name', 'rider_phone'])
        return response.Response({'id': t.id, 'status': t.status, 'rider_name': t.rider_name, 'rider_phone': t.rider_phone})


# ─── Polling Agent Deployment ─────────────────────────────────────────────────
class AgentListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = PollingAgent.objects.select_related('member').all()
        if not request.user.is_admin:
            qs = qs.filter(member=request.user)
        return response.Response([
            {
                'id': a.id,
                'member_id': a.member_id,
                'member_name': a.member.full_name,
                'phone': a.member.phone,
                'ward': a.ward,
                'polling_station': a.polling_station,
                'checked_in': a.checked_in,
                'check_in_time': a.check_in_time,
                'breakfast_received': a.breakfast_received,
                'breakfast_received_at': a.breakfast_received_at,
                'lunch_received': a.lunch_received,
                'lunch_received_at': a.lunch_received_at,
                'notes': a.notes,
            }
            for a in qs.order_by('ward', 'polling_station')
        ])

    def post(self, request):
        d = request.data
        try:
            member = Member.objects.get(pk=d['member_id'])
        except Member.DoesNotExist:
            return response.Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)
        agent, created = PollingAgent.objects.get_or_create(
            member=member,
            polling_station=d.get('polling_station', ''),
            defaults={
                'ward': d.get('ward', ''),
                'notes': d.get('notes', ''),
            }
        )
        return response.Response(
            {'id': agent.id, 'created': created},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )


class AgentCheckInView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            agent = PollingAgent.objects.get(pk=pk)
        except PollingAgent.DoesNotExist:
            return response.Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action', 'checkin')
        now = timezone.now()

        if action == 'breakfast':
            agent.breakfast_received = not agent.breakfast_received
            agent.breakfast_received_at = now if agent.breakfast_received else None
            agent.save(update_fields=['breakfast_received', 'breakfast_received_at'])
        elif action == 'lunch':
            agent.lunch_received = not agent.lunch_received
            agent.lunch_received_at = now if agent.lunch_received else None
            agent.save(update_fields=['lunch_received', 'lunch_received_at'])
        else:
            # Default station checkin
            agent.checked_in = not agent.checked_in
            agent.check_in_time = now if agent.checked_in else None
            agent.save(update_fields=['checked_in', 'check_in_time'])

        return response.Response({
            'id': agent.id,
            'checked_in': agent.checked_in,
            'check_in_time': agent.check_in_time,
            'breakfast_received': agent.breakfast_received,
            'breakfast_received_at': agent.breakfast_received_at,
            'lunch_received': agent.lunch_received,
            'lunch_received_at': agent.lunch_received_at,
        })

    def post(self, request, pk):
        # Support POST method as well
        return self.patch(request, pk)


# ─── PVT: Tally Records ───────────────────────────────────────────────────────
class TallyListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = TallyRecord.objects.select_related('submitted_by').all()
        ward = request.query_params.get('ward')
        if ward:
            qs = qs.filter(ward__icontains=ward)
            
        if not request.user.is_admin:
            qs = qs.filter(submitted_by=request.user)

        # Aggregate totals
        total_dcp = sum(t.dcp_votes for t in qs)
        total_uda = sum(t.uda_votes for t in qs)
        total_other = sum(t.other_votes for t in qs)
        total_cast = sum(t.total_votes_cast for t in qs)

        return response.Response({
            'summary': {
                'stations_reported': qs.count(),
                'dcp_total': total_dcp,
                'uda_total': total_uda,
                'other_total': total_other,
                'total_cast': total_cast,
                'dcp_pct': round((total_dcp / total_cast * 100), 1) if total_cast else 0,
            },
            'records': [
                {
                    'id': t.id,
                    'polling_station': t.polling_station,
                    'ward': t.ward,
                    'dcp_votes': t.dcp_votes,
                    'uda_votes': t.uda_votes,
                    'other_votes': t.other_votes,
                    'total_votes_cast': t.total_votes_cast,
                    'registered_voters': t.registered_voters,
                    'submitted_by': t.submitted_by.full_name if t.submitted_by else 'Unknown',
                    'is_verified': t.is_verified,
                    'form_34a_image': request.build_absolute_uri(t.form_34a_image.url) if t.form_34a_image else None,
                    'submitted_at': t.submitted_at,
                    'notes': t.notes,
                }
                for t in qs.order_by('ward', 'polling_station')
            ]
        })

    def post(self, request):
        member = request.user
        if not member.is_admin and not member.agent_assignments.exists():
            return response.Response(
                {"error": "ACCESS DENIED: Form 34A PVT tally upload is strictly restricted to accredited Polling Agents."},
                status=status.HTTP_403_FORBIDDEN
            )
        d = request.data
        tally, created = TallyRecord.objects.update_or_create(
            polling_station=d.get('polling_station', ''),
            submitted_by=member,
            defaults={
                'ward': d.get('ward', member.official_ward or member.ward or ''),
                'dcp_votes': int(d.get('dcp_votes', 0)),
                'uda_votes': int(d.get('uda_votes', 0)),
                'other_votes': int(d.get('other_votes', 0)),
                'total_votes_cast': int(d.get('total_votes_cast', 0)),
                'registered_voters': int(d.get('registered_voters', 0)),
                'notes': d.get('notes', ''),
            }
        )

        if 'form_34a_image' in request.FILES:
            tally.form_34a_image = request.FILES['form_34a_image']
            tally.save()
            
        return response.Response(
            {'id': tally.id, 'created': created},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )


# ─── SMS Export (ward/station filtered phone list) ────────────────────────────
class SmsExportView(views.APIView):
    """
    Returns phone numbers + names for bulk SMS filtered by ward/station.
    The caller uses this list to send via Africa's Talking, Safaricom Bulk SMS, etc.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ward = request.query_params.get('ward', '')
        station = request.query_params.get('station', '')
        exclude_opted_out = request.query_params.get('exclude_opted_out', 'true').lower() in ('true', '1')

        qs = Member.objects.filter(is_admin=False, is_staff=False)
        if ward:
            qs = qs.filter(Q(ward__icontains=ward) | Q(official_ward__icontains=ward))
        if station:
            qs = qs.filter(
                Q(polling_station__icontains=station) |
                Q(official_polling_station__icontains=station)
            )
        
        total_in_scope = qs.count()
        opted_out_count = qs.filter(is_opted_out=True).count()
        if exclude_opted_out:
            qs = qs.filter(is_opted_out=False)

        recipients = [
            {
                'name': m.full_name,
                'phone': m.phone,
                'ward': m.official_ward or m.ward,
                'station': m.official_polling_station or m.polling_station,
                'is_opted_out': m.is_opted_out,
            }
            for m in qs.order_by('ward', 'full_name')
            if m.phone
        ]
        return response.Response({
            'count': len(recipients),
            'total_in_scope': total_in_scope,
            'opted_out_excluded': opted_out_count if exclude_opted_out else 0,
            'recipients': recipients,
        })


# ─── Relational Contact Matcher ───────────────────────────────────────────────
class ContactMatcherView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '').strip()
        if not query or len(query) < 3:
            return response.Response([])
        
        # Search voter register for matching names
        voters = VoterRecord.objects.filter(full_name__icontains=query)[:20]
        
        # Check which of these are already DCP members
        results = []
        for v in voters:
            is_member = Member.objects.filter(national_id=v.id_number).exists() if v.id_number else False
            results.append({
                'id': v.id,
                'full_name': v.full_name,
                'id_number': v.id_number,
                'ward': v.ward,
                'polling_station': v.polling_station,
                'is_member': is_member
            })
        return response.Response(results)


# ─── Ushahidi-Style Incident Reporter ─────────────────────────────────────────
class IncidentListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = IncidentReport.objects.select_related('reporter').all().order_by('-reported_at')
        if not request.user.is_admin:
            qs = qs.filter(reporter=request.user)
        return response.Response([
            {
                'id': i.id,
                'reporter_name': i.reporter.full_name if i.reporter else 'Anonymous',
                'incident_type': i.incident_type,
                'ward': i.ward,
                'polling_station': i.polling_station,
                'description': i.description,
                'status': i.status,
                'reported_at': i.reported_at,
                'latitude': i.latitude,
                'longitude': i.longitude,
                'image': request.build_absolute_uri(i.image.url) if i.image else None,
                'video': request.build_absolute_uri(i.video.url) if i.video else None,
            }
            for i in qs
        ])

    def post(self, request):
        d = request.data
        incident = IncidentReport.objects.create(
            reporter=request.user,
            incident_type=d.get('incident_type', 'other'),
            ward=d.get('ward', request.user.ward or ''),
            polling_station=d.get('polling_station', request.user.polling_station or ''),
            description=d.get('description', ''),
            latitude=d.get('latitude'),
            longitude=d.get('longitude'),
        )
        
        if 'image' in request.FILES:
            incident.image = request.FILES['image']
        if 'video' in request.FILES:
            incident.video = request.FILES['video']
            
        if 'image' in request.FILES or 'video' in request.FILES:
            incident.save()
            
        return response.Response({'id': incident.id}, status=status.HTTP_201_CREATED)

class IncidentDetailView(views.APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            incident = IncidentReport.objects.get(pk=pk)
        except IncidentReport.DoesNotExist:
            return response.Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        incident.status = request.data.get('status', incident.status)
        incident.save(update_fields=['status'])
        return response.Response({'id': incident.id, 'status': incident.status})


# ─── Virtual Phone Banking ────────────────────────────────────────────────────
class PhoneBankQueueView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Assign 1 pending target to this caller (or fetch one they already have pending)
        target = PhoneBankTarget.objects.filter(status='pending', assigned_to=request.user).first()
        if not target:
            # Grab a new unassigned one
            target = PhoneBankTarget.objects.filter(status='pending', assigned_to__isnull=True).first()
            if target:
                target.assigned_to = request.user
                target.save(update_fields=['assigned_to'])
        
        if not target:
            return response.Response({'target': None})
            
        return response.Response({
            'target': {
                'id': target.id,
                'voter_name': target.voter_name,
                'phone': target.phone,
                'ward': target.ward,
                'polling_station': target.polling_station,
            }
        })

class CallRecordCreateView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        d = request.data
        try:
            target = PhoneBankTarget.objects.get(pk=d['target_id'])
        except PhoneBankTarget.DoesNotExist:
            return response.Response({'error': 'Target not found'}, status=status.HTTP_404_NOT_FOUND)
            
        outcome = d.get('outcome')
        CallRecord.objects.create(
            caller=request.user,
            target=target,
            outcome=outcome,
            notes=d.get('notes', '')
        )
        
        # Update target status
        if outcome == 'wrong_number':
            target.status = 'unreachable'
        else:
            target.status = 'called'
        target.save(update_fields=['status'])
        
        return response.Response({'success': True}, status=status.HTTP_201_CREATED)

# ─── Events & Rally Check-ins ────────────────────────────────────────────────
from .models import Event, EventAttendance
from .serializers import EventSerializer, EventAttendanceSerializer

class EventListView(generics.ListCreateAPIView):
    permission_classes = [IsAdminUser]
    queryset = Event.objects.all().order_by('-date')
    serializer_class = EventSerializer

class EventDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAdminUser]
    queryset = Event.objects.all()
    serializer_class = EventSerializer

class EventAttendanceView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, event_id):
        attendances = EventAttendance.objects.filter(event_id=event_id).select_related('member')
        serializer = EventAttendanceSerializer(attendances, many=True)
        return response.Response(serializer.data)

    def post(self, request, event_id):
        member_id = request.data.get('member_id')
        if not member_id:
            return response.Response({"error": "member_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            event = Event.objects.get(id=event_id)
            member = Member.objects.get(id=member_id)
        except (Event.DoesNotExist, Member.DoesNotExist):
            return response.Response({"error": "Event or Member not found"}, status=status.HTTP_404_NOT_FOUND)

        attendance, created = EventAttendance.objects.get_or_create(event=event, member=member)
        if not created:
            return response.Response({"error": "Already checked in"}, status=status.HTTP_400_BAD_REQUEST)

        EventAttendance.objects.create(event=event, member=request.user)
        return response.Response({"status": "Checked in"}, status=status.HTTP_201_CREATED)

class EmergencyBroadcastView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get the active broadcast for this specific mobilizer."""
        broadcasts = EmergencyBroadcast.objects.filter(is_active=True).order_by('-created_at')
        
        applicable_broadcast = None
        for b in broadcasts:
            if b.target_type == 'global':
                applicable_broadcast = b
                break
            elif b.target_type == 'ward' and request.user.ward in (b.target_wards or []):
                if not b.target_polling_stations or request.user.polling_station in b.target_polling_stations:
                    applicable_broadcast = b
                    break
            elif b.target_type == 'specific_people' and b.target_members.filter(id=request.user.id).exists():
                applicable_broadcast = b
                break
                
        if applicable_broadcast:
            return response.Response(EmergencyBroadcastSerializer(applicable_broadcast).data)
        return response.Response({"status": "No active broadcasts"}, status=status.HTTP_204_NO_CONTENT)

    def post(self, request):
        """Admin creates a new targeted broadcast."""
        if not request.user.is_admin:
            return response.Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
            
        message = request.data.get('message')
        severity = request.data.get('severity', 'critical')
        target_type = request.data.get('target_type', 'global')
        target_wards = request.data.get('target_wards', [])
        target_polling_stations = request.data.get('target_polling_stations', [])
        target_member_ids = request.data.get('target_member_ids', [])
        
        if not message:
            return response.Response({"error": "Message required"}, status=status.HTTP_400_BAD_REQUEST)
            
        EmergencyBroadcast.objects.filter(is_active=True).update(is_active=False)
        
        broadcast = EmergencyBroadcast.objects.create(
            message=message,
            severity=severity,
            target_type=target_type,
            target_wards=target_wards,
            target_polling_stations=target_polling_stations,
            created_by=request.user,
            is_active=True
        )
        
        if target_type == 'specific_people' and target_member_ids:
            members = Member.objects.filter(id__in=target_member_ids)
            broadcast.target_members.set(members)
            
        return response.Response(EmergencyBroadcastSerializer(broadcast).data, status=status.HTTP_201_CREATED)

    def delete(self, request):
        """Admin clears the active broadcast."""
        if not request.user.is_admin:
            return response.Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
            
        EmergencyBroadcast.objects.filter(is_active=True).update(is_active=False)
        return response.Response({"status": "Broadcast cleared"}, status=status.HTTP_200_OK)

LAIKIPIA_WEST_STATIONS = {
    "Ol-Moran": [
        "Ol Moran Primary School",
        "Ol Moran Secondary School",
        "Sipili Primary School",
        "Sipili Secondary School",
        "Tumaini Primary School",
        "Dimcom Primary School",
        "Mugei Primary School",
        "Larisoro Primary School"
    ],
    "Rumuruti Township": [
        "Rumuruti Primary School",
        "Rumuruti Stadium / Social Hall",
        "Rumuruti Secondary School",
        "Kandutura Primary School",
        "Mutamaiyu Primary School",
        "Lorien Primary School",
        "African Independent Church Centre",
        "Rumuruti Sub-County HQ"
    ],
    "Githiga": [
        "Githiga Primary School",
        "Matuiku Primary School",
        "Maina Primary School",
        "Kinamba Primary School",
        "Kinamba Secondary School",
        "Mahianyu Primary School",
        "Tandare Primary School",
        "Wangwaci Primary School"
    ],
    "Marmanet": [
        "Marmanet Primary School",
        "Marmanet Secondary School",
        "Siron Primary School",
        "Gatundia Primary School",
        "Melwa Primary School",
        "Kianjogu Primary School",
        "Maili Tisa Primary School",
        "Muhotetu Primary School"
    ],
    "Salama": [
        "Salama Primary School",
        "Pesi Primary School",
        "Muruku Primary School",
        "Muruku Secondary School",
        "Kiamariki Primary School",
        "Sirima Primary School",
        "Ndurumo Secondary School",
        "Thome Primary School"
    ],
    "Sosian": [
        "Sosian Primary School",
        "Ewaso Primary School",
        "Naibor Primary School",
        "Kimanjo Primary School",
        "Kimanjo Secondary School",
        "Il Polei Primary School",
        "Doldol Primary School",
        "Mogogendo Primary School"
    ]
}

@api_view(['GET'])
@permission_classes([AllowAny])
def get_wards_and_stations(request):
    """Returns a dictionary mapping all Laikipia Wards to their unique Polling Stations directly from the official voter register."""
    mapping = {}
    wards_data = VoterRecord.objects.values('ward', 'polling_station').distinct().order_by('ward', 'polling_station')
    for entry in wards_data:
        ward = entry.get('ward')
        station = entry.get('polling_station')
        if not ward:
            continue
            
        if ward not in mapping:
            mapping[ward] = []
            
        if station and station not in mapping[ward]:
            mapping[ward].append(station)
            
    if not mapping:
        mapping = {k: list(v) for k, v in LAIKIPIA_WEST_STATIONS.items()}

    sorted_mapping = {w: sorted(s) for w, s in sorted(mapping.items())}
    return response.Response(sorted_mapping)



class MemberToggleOptOutView(views.APIView):
    """
    Toggles supporter opt-out status pursuant to Kenya Data Protection Act 2019 Section 40 (Right to Erasure / Unsubscribe).
    Excludes the supporter from bulk SMS and automated outreach lists.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            member = Member.objects.get(pk=pk)
            # Admin, staff, or the user themselves can toggle opt-out status
            if not (request.user.is_admin or request.user.is_staff or request.user.id == member.id):
                return response.Response({"error": "Unauthorized to modify opt-out status."}, status=status.HTTP_403_FORBIDDEN)

            member.is_opted_out = not member.is_opted_out
            member.opted_out_at = timezone.now() if member.is_opted_out else None
            member.save(update_fields=['is_opted_out', 'opted_out_at'])

            action = 'MEMBER_OPTED_OUT' if member.is_opted_out else 'MEMBER_OPTED_IN'
            AuditLog.log(action, user=request.user, request=request, details={
                'member_id': member.id,
                'phone': member.phone,
                'is_opted_out': member.is_opted_out
            })

            return response.Response({
                "message": f"{member.full_name} is now {'OPTED OUT (STOP)' if member.is_opted_out else 'OPTED IN'}.",
                "is_opted_out": member.is_opted_out,
                "opted_out_at": member.opted_out_at
            })
        except Member.DoesNotExist:
            return response.Response({"error": "Member not found."}, status=status.HTTP_404_NOT_FOUND)

class MemberToggleActiveView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        if not request.user.is_admin:
            return response.Response({"error": "Only admins can deactivate members."}, status=status.HTTP_403_FORBIDDEN)
            
        try:
            member = Member.objects.get(pk=pk)
            if member.id == request.user.id:
                return response.Response({"error": "You cannot deactivate yourself."}, status=status.HTTP_400_BAD_REQUEST)
                
            member.is_active = not member.is_active
            member.save()
            return response.Response({"message": "Status updated.", "is_active": member.is_active})
        except Member.DoesNotExist:
            return response.Response({"error": "Member not found."}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, pk):
        if not request.user.is_admin:
            return response.Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
            
        try:
            member = Member.objects.get(pk=pk)
        except Member.DoesNotExist:
            return response.Response({"error": "Member not found."}, status=status.HTTP_404_NOT_FOUND)
            
        d = request.data
        update_fields = []
        if 'security_rank' in d:
            member.security_rank = d['security_rank']
            update_fields.append('security_rank')
        if 'is_security_only' in d:
            member.is_security_only = d['is_security_only']
            update_fields.append('is_security_only')
        if 'ward' in d:
            member.ward = d['ward']
            update_fields.append('ward')
        if 'polling_station' in d:
            member.polling_station = d['polling_station']
            update_fields.append('polling_station')
            
        if update_fields:
            member.save(update_fields=update_fields)
            
        return response.Response({
            'security_rank': member.security_rank,
            'is_security_only': member.is_security_only
        })


class WardHealthInsightsView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        now = timezone.now()
        forty_eight_hours_ago = now - timedelta(hours=48)
        ninety_six_hours_ago = now - timedelta(hours=96)

        # Count recruits in current 48h
        current_period = Member.objects.filter(
            is_admin=False, is_staff=False,
            created_at__gte=forty_eight_hours_ago
        ).values('ward').annotate(count=Count('id'))
        
        current_dict = {item['ward']: item['count'] for item in current_period if item['ward']}

        # Count recruits in previous 48h
        previous_period = Member.objects.filter(
            is_admin=False, is_staff=False,
            created_at__gte=ninety_six_hours_ago,
            created_at__lt=forty_eight_hours_ago
        ).values('ward').annotate(count=Count('id'))

        previous_dict = {item['ward']: item['count'] for item in previous_period if item['ward']}

        insights = []
        for ward, current_count in current_dict.items():
            prev_count = previous_dict.get(ward, 0)
            
            # We only care if previous count was meaningful enough to form a trend
            if prev_count >= 5:
                drop_ratio = (prev_count - current_count) / prev_count
                
                # If velocity dropped by more than 20%
                if drop_ratio > 0.20:
                    percent_drop = int(drop_ratio * 100)
                    insights.append({
                        "ward": ward,
                        "type": "warning",
                        "message": f"Warning: {ward} mobilization velocity has slowed down by {percent_drop}% in the last 48 hours. Current 48h: {current_count} recruits (down from {prev_count}). Recommend deploying additional root mobilizers."
                    })
                elif drop_ratio < -0.20:
                    # Growth
                    percent_growth = int(abs(drop_ratio) * 100)
                    insights.append({
                        "ward": ward,
                        "type": "success",
                        "message": f"Positive Trend: {ward} mobilization is accelerating! Up {percent_growth}% in the last 48 hours ({current_count} recruits vs {prev_count})."
                    })

        # Sort insights (warnings first)
        insights.sort(key=lambda x: 0 if x['type'] == 'warning' else 1)

        return response.Response({"insights": insights})


class FraudDetectionView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        now = timezone.now()
        forty_eight_hours_ago = now - timedelta(hours=48)
        
        recent_recruits = Member.objects.filter(
            created_at__gte=forty_eight_hours_ago,
            referred_by__isnull=False
        ).select_related('referred_by').order_by('referred_by', 'created_at')

        alerts = []
        last_member = None
        
        for member in recent_recruits:
            if last_member and last_member.referred_by_id == member.referred_by_id:
                time_diff = (member.created_at - last_member.created_at).total_seconds()
                
                # Check 1: Speed anomaly (less than 30 seconds apart)
                if time_diff < 30:
                    alerts.append({
                        "type": "speed_anomaly",
                        "severity": "high",
                        "mobilizer_name": member.referred_by.full_name,
                        "mobilizer_id": member.referred_by_id,
                        "message": f"Registered {member.full_name} and {last_member.full_name} only {int(time_diff)} seconds apart.",
                        "timestamp": member.created_at
                    })
                
                # Check 2: Sequential ID anomaly (e.g. 1234567, 1234568)
                try:
                    if abs(int(member.national_id) - int(last_member.national_id)) == 1:
                        alerts.append({
                            "type": "sequential_id",
                            "severity": "critical",
                            "mobilizer_name": member.referred_by.full_name,
                            "mobilizer_id": member.referred_by_id,
                            "message": f"Registered sequential IDs: {last_member.national_id} and {member.national_id}.",
                            "timestamp": member.created_at
                        })
                except ValueError:
                    pass

            last_member = member

        return response.Response({"alerts": alerts})


class SaturationPredictionView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        # Total registered from official IEBC data
        official_totals = VoterRecord.objects.values('polling_station').annotate(total_voters=Count('id'))
        official_dict = {item['polling_station']: item['total_voters'] for item in official_totals if item['polling_station']}

        # Our recruits
        recruit_totals = Member.objects.values('polling_station').annotate(total_recruits=Count('id'))
        
        stations = []
        for r in recruit_totals:
            ps = r['polling_station']
            if not ps: continue
            
            recruits = r['total_recruits']
            total = official_dict.get(ps, 0)
            
            if total > 0:
                saturation = (recruits / total) * 100
                stations.append({
                    "polling_station": ps,
                    "recruits": recruits,
                    "total_registered": total,
                    "saturation_percent": round(saturation, 1)
                })

        stations.sort(key=lambda x: x['saturation_percent'], reverse=True)
        
        secured = [s for s in stations if s['saturation_percent'] >= 50][:5]
        at_risk = [s for s in stations[::-1] if s['saturation_percent'] < 50][:5]

        return response.Response({
            "secured": secured,
            "at_risk": at_risk
        })


class TargetMatchingView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            member = Member.objects.get(pk=pk)
        except Member.DoesNotExist:
            return response.Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        if not member.full_name or not member.polling_station:
            return response.Response({"targets": []})

        # Get last name
        name_parts = member.full_name.strip().split()
        if not name_parts:
            return response.Response({"targets": []})
        
        last_name = name_parts[-1]
        if len(last_name) < 3: # Ignore tiny names to prevent massive false positives
            return response.Response({"targets": []})

        # Get existing member IDs in this station to exclude
        existing_member_ids = Member.objects.filter(polling_station=member.polling_station).values_list('national_id', flat=True)

        # Search VoterRecord
        targets = VoterRecord.objects.filter(
            full_name__icontains=last_name,
            polling_station=member.polling_station
        ).exclude(id_number__in=existing_member_ids)[:10]

        target_data = [{"full_name": t.full_name, "id_number": t.id_number} for t in targets]

        return response.Response({"targets": target_data})


class DemographicInsightsView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        import datetime
        from django.db.models import Count, Q
        
        current_year = datetime.datetime.now().year
        
        base_qs = Member.objects.filter(is_admin=False, is_staff=False)
        total = base_qs.count()
        if total == 0:
            return response.Response({
                "gender": {"male": 0, "female": 0, "unknown": 0},
                "age_buckets": {"youth": 0, "adult": 0, "elder": 0, "unknown": 0},
                "insights": ["No demographic data available yet."]
            })

        # Gender breakdown
        male_count = base_qs.filter(gender__iexact='M').count()
        female_count = base_qs.filter(gender__iexact='F').count()
        unknown_gender = total - (male_count + female_count)

        # Age breakdown
        # Youths: 18-35 (current_year - 35 <= yob <= current_year - 18)
        # Adults: 36-50
        # Elders: 50+
        youths = base_qs.filter(yob__gte=current_year - 35).count()
        adults = base_qs.filter(yob__lt=current_year - 35, yob__gte=current_year - 50).count()
        elders = base_qs.filter(yob__lt=current_year - 50).count()
        unknown_age = total - (youths + adults + elders)

        # AI Insights Generation
        insights = []
        
        # Gender insights
        if female_count > 0 and (female_count / total) < 0.3:
            insights.append("Warning: Women make up less than 30% of your recruits. Consider deploying more female mobilizers.")
        elif female_count > 0 and (female_count / total) > 0.5:
            insights.append("Success: Strong female turnout! Women make up the majority of your enrolled members.")
            
        # Age insights
        if youths > 0 and (youths / total) < 0.2:
            insights.append("Warning: Low youth enrollment. Youths (18-35) make up less than 20% of your base. Target younger demographics.")
        elif youths > 0 and (youths / total) > 0.6:
            insights.append("Insight: Excellent youth mobilization! Over 60% of your base is under 35.")
            
        if not insights:
            insights.append("Insight: Your demographic distribution is currently balanced.")

        # Optional: Station/Ward specific anomaly (Mock AI generation based on top ward)
        top_ward = base_qs.values('ward').annotate(c=Count('id')).order_by('-c').first()
        if top_ward and top_ward['ward']:
            w_name = top_ward['ward']
            w_youths = base_qs.filter(ward=w_name, yob__gte=current_year - 35).count()
            if w_youths > 0 and top_ward['c'] > 0:
                y_pct = (w_youths / top_ward['c']) * 100
                insights.append(f"AI Alert: {y_pct:.0f}% of your recruits in {w_name} Ward are Youths.")

        return response.Response({
            "gender": {
                "male": male_count,
                "female": female_count,
                "unknown": unknown_gender
            },
            "age_buckets": {
                "youth": youths,
                "adult": adults,
                "elder": elders,
                "unknown": unknown_age
            },
            "insights": insights
        })


# ─── Security Enhancements (Guards / Post Commands) ──────────────────────────
class SecurityLogListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_admin:
            return response.Response({"detail": "Admin security access required."}, status=status.HTTP_403_FORBIDDEN)
        qs = SecurityLog.objects.select_related('guard').all().order_by('-logged_at')
        user = request.user
        if not user.is_admin:
            if user.security_rank == 'ward_commander':
                qs = qs.filter(ward=user.ward)
            elif user.security_rank == 'station_commander':
                qs = qs.filter(polling_station=user.polling_station)
            else:
                qs = qs.filter(guard=user)
            
        return response.Response([
            {
                'id': log.id,
                'guard_name': log.guard.full_name,
                'guard_phone': log.guard.phone,
                'ward': log.ward,
                'polling_station': log.polling_station,
                'status': log.status,
                'notes': log.notes,
                'logged_at': log.logged_at,
                'latitude': log.latitude,
                'longitude': log.longitude,
                'resolution_action': log.resolution_action,
            }
            for log in qs[:100]  # Return last 100 logs
        ])

    def post(self, request):
        if not request.user.is_security and not request.user.is_admin:
            return response.Response({"error": "Forbidden. Security personnel only."}, status=status.HTTP_403_FORBIDDEN)
            
        d = request.data
        log = SecurityLog.objects.create(
            guard=request.user,
            ward=d.get('ward', request.user.ward or ''),
            polling_station=d.get('polling_station', request.user.polling_station or ''),
            status=d.get('status', 'all_clear'),
            notes=d.get('notes', ''),
            latitude=d.get('latitude'),
            longitude=d.get('longitude'),
        )
        return response.Response({'id': log.id, 'status': log.status}, status=status.HTTP_201_CREATED)

class SecurityLogDetailView(views.APIView):
    permission_classes = [IsAdminUser]

    def patch(self, request, pk):
        try:
            log = SecurityLog.objects.get(pk=pk)
        except SecurityLog.DoesNotExist:
            return response.Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
            
        log.resolution_action = request.data.get('resolution_action', log.resolution_action)
        log.save(update_fields=['resolution_action'])
        return response.Response({'id': log.id, 'resolution_action': log.resolution_action})

class SecurityPersonnelListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.is_admin:
            qs = Member.objects.filter(security_rank__in=['ward_commander', 'station_commander', 'guard'])
        elif user.security_rank == 'ward_commander':
            # See station commanders and guards in their ward
            qs = Member.objects.filter(ward=user.ward, security_rank__in=['station_commander', 'guard'])
        elif user.security_rank == 'station_commander':
            # See guards in their station
            qs = Member.objects.filter(polling_station=user.polling_station, security_rank='guard')
        else:
            return response.Response([])

        return response.Response([
            {
                'id': m.id,
                'full_name': m.full_name,
                'phone': m.phone,
                'security_rank': m.security_rank,
                'polling_station': m.polling_station,
                'ward': m.ward
            }
            for m in qs
        ])

class SecurityMIAView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        thirty_mins_ago = timezone.now() - timedelta(minutes=30)
        
        # Get all security personnel
        security_members = Member.objects.exclude(security_rank='none')
        
        mia_list = []
        for m in security_members:
            # Check if they have any logs in the last 30 mins
            has_recent_log = SecurityLog.objects.filter(guard=m, logged_at__gte=thirty_mins_ago).exists()
            if not has_recent_log:
                mia_list.append({
                    'id': m.id,
                    'full_name': m.full_name,
                    'phone': m.phone,
                    'ward': m.ward,
                    'polling_station': m.polling_station,
                    'security_rank': m.security_rank
                })
                
        return response.Response(mia_list)


# ─── Governor Campaign Diary & Chama Functions ──────────────────────────────
from .models import CampaignFunction
from .serializers import CampaignFunctionSerializer

class CampaignFunctionListView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = CampaignFunction.objects.all().select_related('submitted_by')

        # Privacy Scoping: Mobilizers only see functions they personally submitted OR official Governor rallies
        if not request.user.is_admin:
            qs = qs.filter(Q(submitted_by=request.user) | Q(is_created_by_governor=True))

        constituency = request.query_params.get('constituency')
        if constituency and constituency != 'all':
            qs = qs.filter(constituency__iexact=constituency)

        ward = request.query_params.get('ward')
        if ward and ward != 'all':
            qs = qs.filter(ward__iexact=ward)

        status_filter = request.query_params.get('status')
        if status_filter and status_filter != 'all':
            qs = qs.filter(status=status_filter)

        event_type = request.query_params.get('type')
        if event_type and event_type != 'all':
            qs = qs.filter(event_type=event_type)

        # Access rule:
        # Admins/Secretariat: see everything
        # Regular Mobilizers: see confirmed/delegated events + all events they submitted themselves
        if not request.user.is_admin:
            qs = qs.filter(Q(status__in=['attending', 'delegated']) | Q(submitted_by=request.user))

        serializer = CampaignFunctionSerializer(qs, many=True, context={'request': request})
        return response.Response(serializer.data)

    def post(self, request):
        data = request.data.copy()
        is_admin = request.user.is_admin or request.user.is_staff or request.user.is_superuser

        if is_admin:
            data['is_created_by_governor'] = True
            if 'status' not in data:
                data['status'] = 'attending'
        else:
            data['is_created_by_governor'] = False
            data['status'] = 'pending'

        serializer = CampaignFunctionSerializer(data=data, context={'request': request})
        if serializer.is_valid():
            function_obj = serializer.save(submitted_by=request.user)
            return response.Response(
                CampaignFunctionSerializer(function_obj, context={'request': request}).data,
                status=status.HTTP_201_CREATED
            )
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CampaignFunctionDetailView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            func = CampaignFunction.objects.select_related('submitted_by').get(pk=pk)
        except CampaignFunction.DoesNotExist:
            return response.Response({'error': 'Function not found'}, status=status.HTTP_404_NOT_FOUND)

        if not request.user.is_admin and func.status not in ['attending', 'delegated'] and func.submitted_by_id != request.user.id:
            return response.Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        serializer = CampaignFunctionSerializer(func, context={'request': request})
        return response.Response(serializer.data)

    def patch(self, request, pk):
        try:
            func = CampaignFunction.objects.get(pk=pk)
        except CampaignFunction.DoesNotExist:
            return response.Response({'error': 'Function not found'}, status=status.HTTP_404_NOT_FOUND)

        is_admin = request.user.is_admin or request.user.is_staff or request.user.is_superuser
        is_submitter = (func.submitted_by_id == request.user.id)

        if not is_admin and not is_submitter:
            return response.Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        data = request.data.copy()
        # Non-admins cannot change status or delegate
        if not is_admin:
            data.pop('status', None)
            data.pop('delegate_name', None)
            data.pop('delegate_phone', None)
            data.pop('admin_notes', None)

        serializer = CampaignFunctionSerializer(func, data=data, partial=True, context={'request': request})
        if serializer.is_valid():
            updated = serializer.save()
            return response.Response(CampaignFunctionSerializer(updated, context={'request': request}).data)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        if not request.user.is_admin:
            return response.Response({'error': 'Admin privileges required'}, status=status.HTTP_403_FORBIDDEN)
        try:
            func = CampaignFunction.objects.get(pk=pk)
            func.delete()
            return response.Response({'message': 'Function deleted successfully'})
        except CampaignFunction.DoesNotExist:
            return response.Response({'error': 'Function not found'}, status=status.HTTP_404_NOT_FOUND)

# ─── Campaign Config & Social Media Recruitment ──────────────────────────────
class CampaignConfigView(views.APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        configs = CampaignConfig.objects.all()
        data = {c.key: c.value for c in configs}
        if 'whatsapp_community_link' not in data or not data['whatsapp_community_link']:
            data['whatsapp_community_link'] = 'https://chat.whatsapp.com/sample-laikipia'
        return response.Response(data)

    def post(self, request):
        if not request.user.is_authenticated or not (request.user.is_admin or request.user.is_staff):
            return response.Response({"error": "Admin credentials required"}, status=status.HTTP_403_FORBIDDEN)
        key = request.data.get('key')
        value = request.data.get('value', '')
        if not key:
            return response.Response({"error": "Key is required"}, status=status.HTTP_400_BAD_REQUEST)
        config, _ = CampaignConfig.objects.update_or_create(key=key, defaults={'value': value})
        return response.Response({"success": True, "key": config.key, "value": config.value})

class MemberCheckStatusView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        national_id = str(request.data.get('national_id', '')).strip()
        phone = str(request.data.get('phone', '')).strip()
        if not national_id and not phone:
            return response.Response({"error": "National ID or Phone required"}, status=status.HTTP_400_BAD_REQUEST)

        query = Q()
        if national_id:
            query |= Q(national_id=national_id)
        if phone:
            query |= Q(phone=phone)

        existing = Member.objects.filter(query).first()
        if not existing:
            return response.Response({"status": "not_registered", "message": "No existing registration found."})

        if existing.referred_by is not None:
            return response.Response({
                "status": "locked",
                "message": f"Already registered under Mobilizer {existing.referred_by.full_name}.",
                "member_name": existing.full_name,
                "referrer_name": existing.referred_by.full_name,
                "ward": existing.ward
            })
        else:
            return response.Response({
                "status": "can_claim",
                "message": "Found Online / Unassigned Recruit!",
                "member_id": existing.id,
                "member_name": existing.full_name,
                "ward": existing.ward,
                "polling_station": existing.polling_station,
                "source": getattr(existing, 'source', 'social_media')
            })

class MemberClaimSocialView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        allowed, remaining, retry_after = check_rate_limit(request, 'claim_social', max_requests=15, window_seconds=60, extra_key=str(request.user.id))
        if not allowed:
            return response.Response({
                "error": "rate_limit_exceeded",
                "message": f"Too many adoption attempts. Please wait {retry_after} seconds before trying again.",
                "retry_after": retry_after
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        mobilizer = request.user
        national_id = str(request.data.get('national_id', '')).strip()
        phone = str(request.data.get('phone', '')).strip()
        if not national_id or not phone:
            return response.Response({"error": "Both National ID and Phone number are required to verify the recruit in-person."}, status=status.HTTP_400_BAD_REQUEST)

        # Match exact ID and Phone
        recruit = Member.objects.filter(national_id=national_id, phone=phone).first()
        if not recruit:
            return response.Response({"error": "No matching member found with that National ID and Phone."}, status=status.HTTP_404_NOT_FOUND)

        if recruit.id == mobilizer.id:
            return response.Response({"error": "You cannot adopt yourself."}, status=status.HTTP_400_BAD_REQUEST)

        if recruit.referred_by is not None:
            return response.Response({
                "error": f"This member is already registered under Mobilizer {recruit.referred_by.full_name} and cannot be reassigned."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check mobilizer quota
        quota = 10 if mobilizer.referred_by is None else 5
        current_count = mobilizer.recruits.count()
        if current_count >= quota:
            return response.Response({"error": f"You have reached your quota limit of {quota} recruits."}, status=status.HTTP_400_BAD_REQUEST)

        # Assign recruit to this mobilizer
        recruit.referred_by = mobilizer
        recruit.save(update_fields=['referred_by'])
        AuditLog.log('RECRUIT_ADOPTED', user=mobilizer, request=request, details={
            'recruit_id': recruit.id,
            'recruit_name': recruit.full_name,
            'ward': recruit.ward
        })

        return response.Response({
            "success": True,
            "message": f"Successfully adopted {recruit.full_name} to your team!",
            "recruit": MemberSerializer(recruit, context={'request': request}).data
        })



class AdminChangePasswordView(views.APIView):
    """
    Allows authenticated admin/staff users to securely update their account password.
    POST /api/admin/change-password
    """
    permission_classes = [IsAdminUser]

    def post(self, request):
        user = request.user
        data = request.data or {}
        
        current_password = str(data.get('current_password') or '').strip()
        new_password = str(data.get('new_password') or '').strip()
        confirm_password = str(data.get('confirm_password') or '').strip()

        if not new_password or len(new_password) < 6:
            return response.Response(
                {"error": "New password must be at least 6 characters long."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if new_password != confirm_password:
            return response.Response(
                {"error": "New password and confirmation do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify current password if user has one
        if user.has_usable_password() and current_password:
            if not user.check_password(current_password):
                AuditLog.log('PASSWORD_CHANGE_FAILED', user=user, request=request, details={'reason': 'incorrect_current_password'})
                return response.Response(
                    {"error": "Current password is incorrect."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        elif user.has_usable_password() and not current_password:
            return response.Response(
                {"error": "Current password is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(new_password)
        user.save()

        AuditLog.log('PASSWORD_CHANGED_SUCCESS', user=user, request=request)

        return response.Response({
            "status": "success",
            "message": "Password updated successfully."
        }, status=status.HTTP_200_OK)


# ─── 7-Tier Campaign Hierarchy & Command Views ─────────────────────────────────

class CampaignHierarchyStatsView(views.APIView):
    """High-level role counts, quotas, and health breakdown across the campaign."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        counts = {
            'governor': Member.objects.filter(campaign_role='governor', is_active=True).count(),
            'county_manager': Member.objects.filter(campaign_role='county_manager', is_active=True).count(),
            'sub_county_coordinator': Member.objects.filter(campaign_role='sub_county_coordinator', is_active=True).count(),
            'ward_coordinator': Member.objects.filter(campaign_role='ward_coordinator', is_active=True).count(),
            'polling_centre_coordinator': Member.objects.filter(campaign_role='polling_centre_coordinator', is_active=True).count(),
            'pillar': Member.objects.filter(campaign_role='pillar', is_active=True).count(),
            'station_mobilizer': Member.objects.filter(campaign_role='station_mobilizer', is_active=True).count(),
            'total_personnel': Member.objects.filter(is_active=True).count(),
        }
        pillar_counts = {
            'youth': Member.objects.filter(campaign_role='pillar', pillar_category='youth', is_active=True).count(),
            'women': Member.objects.filter(campaign_role='pillar', pillar_category='women', is_active=True).count(),
            'elders_business': Member.objects.filter(campaign_role='pillar', pillar_category='elders_business', is_active=True).count(),
            'special_interest': Member.objects.filter(campaign_role='pillar', pillar_category='special_interest', is_active=True).count(),
        }

        # Calculate polling station coverage quota
        # Distinct polling stations in DB
        stations = VoterRecord.objects.exclude(polling_station__isnull=True).exclude(polling_station='').values_list('polling_station', flat=True).distinct()
        total_stations = len(stations) or 1

        # Stations with at least 1 coordinator
        station_with_coord = Member.objects.filter(campaign_role='polling_centre_coordinator', is_active=True).values_list('assigned_polling_centre', flat=True).distinct().count()
        # Stations with 3 pillars filled
        # Stations with 25 mobilizers filled

        return response.Response({
            'role_counts': counts,
            'pillar_counts': pillar_counts,
            'total_stations': total_stations,
            'stations_with_coordinator': station_with_coord,
            'targets_per_station': {
                'pillars_target': 3,
                'mobilizers_target': 25,
                'coordinators_target': 1,
            }
        })


class CampaignHierarchyTreeView(views.APIView):
    """
    Returns the hierarchy tree structured by Ward -> Polling Centre -> [Coordinator, 3 Pillars, 25 Mobilizers].
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ward_filter = request.query_params.get('ward', '').strip()
        search_query = request.query_params.get('search', '').strip()

        # Collect all active personnel
        qs = Member.objects.filter(is_active=True)
        if ward_filter:
            qs = qs.filter(Q(assigned_ward=ward_filter) | Q(ward=ward_filter))
        if search_query:
            qs = qs.filter(Q(full_name__icontains=search_query) | Q(phone__icontains=search_query) | Q(national_id__icontains=search_query))

        # Distinct Wards
        wards_data = []
        ward_names = VoterRecord.objects.exclude(ward__isnull=True).exclude(ward='').values_list('ward', flat=True).distinct().order_by('ward')
        if not ward_names.exists():
            ward_names = Member.objects.exclude(ward__isnull=True).exclude(ward='').values_list('ward', flat=True).distinct().order_by('ward')

        if ward_filter:
            ward_names = [w for w in ward_names if w.lower() == ward_filter.lower()]
            if not ward_names:
                ward_names = [ward_filter]

        for w_name in ward_names:
            ward_coord = Member.objects.filter(
                campaign_role='ward_coordinator',
                assigned_ward__iexact=w_name,
                is_active=True
            ).first()

            # Find polling stations in this ward
            stations_in_ward = VoterRecord.objects.filter(ward__iexact=w_name).exclude(polling_station__isnull=True).exclude(polling_station='').values_list('polling_station', flat=True).distinct().order_by('polling_station')
            if not stations_in_ward.exists():
                stations_in_ward = Member.objects.filter(ward__iexact=w_name).exclude(polling_station__isnull=True).exclude(polling_station='').values_list('polling_station', flat=True).distinct().order_by('polling_station')

            stations_data = []
            for s_name in stations_in_ward:
                centre_coord = Member.objects.filter(
                    campaign_role='polling_centre_coordinator',
                    assigned_polling_centre__iexact=s_name,
                    is_active=True
                ).first()

                pillars = Member.objects.filter(
                    campaign_role='pillar',
                    assigned_polling_centre__iexact=s_name,
                    is_active=True
                ).order_by('created_at')[:3]

                mobilizers = Member.objects.filter(
                    Q(campaign_role='station_mobilizer') | Q(campaign_role=''),
                    Q(assigned_polling_centre__iexact=s_name) | Q(polling_station__iexact=s_name),
                    is_active=True
                ).order_by('-created_at')[:25]

                stations_data.append({
                    'polling_station': s_name,
                    'ward': w_name,
                    'coordinator': CampaignPersonnelSerializer(centre_coord).data if centre_coord else None,
                    'pillars': CampaignPersonnelSerializer(pillars, many=True).data,
                    'pillars_count': pillars.count(),
                    'pillars_target': 3,
                    'mobilizers': CampaignPersonnelSerializer(mobilizers, many=True).data,
                    'mobilizers_count': mobilizers.count(),
                    'mobilizers_target': 25,
                    'is_quota_filled': (pillars.count() >= 3 and mobilizers.count() >= 25),
                })

            wards_data.append({
                'ward': w_name,
                'coordinator': CampaignPersonnelSerializer(ward_coord).data if ward_coord else None,
                'polling_stations': stations_data,
                'total_stations': len(stations_data),
            })

        # Top leadership
        governors = Member.objects.filter(campaign_role='governor', is_active=True)
        managers = Member.objects.filter(campaign_role='county_manager', is_active=True)
        sub_county_coords = Member.objects.filter(campaign_role='sub_county_coordinator', is_active=True)

        return response.Response({
            'leadership': {
                'governors': CampaignPersonnelSerializer(governors, many=True).data,
                'county_managers': CampaignPersonnelSerializer(managers, many=True).data,
                'sub_county_coordinators': CampaignPersonnelSerializer(sub_county_coords, many=True).data,
            },
            'wards': wards_data
        })


class CampaignDirectoryView(views.APIView):
    """
    Searchable phonebook & directory for leadership to contact anyone down the chain.
    Provides direct phone numbers for Calling (tel:) and WhatsApp messaging.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        role = request.query_params.get('role', '').strip()
        ward = request.query_params.get('ward', '').strip()
        station = request.query_params.get('station', '').strip()
        category = request.query_params.get('pillar_category', '').strip()
        q = request.query_params.get('search', '').strip()

        members = Member.objects.filter(is_active=True)

        if role:
            members = members.filter(campaign_role=role)
        if ward:
            members = members.filter(Q(assigned_ward__iexact=ward) | Q(ward__iexact=ward))
        if station:
            members = members.filter(Q(assigned_polling_centre__iexact=station) | Q(polling_station__iexact=station))
        if category:
            members = members.filter(pillar_category=category)
        if q:
            members = members.filter(
                Q(full_name__icontains=q) | Q(phone__icontains=q) | Q(national_id__icontains=q)
            )

        # Pagination or top 100
        members = members.order_by('-created_at')[:150]
        serializer = CampaignPersonnelSerializer(members, many=True)
        return response.Response(serializer.data)


class CampaignMyTeamView(views.APIView):
    """
    Returns the direct team that the authenticated member directly manages.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        role = getattr(user, 'campaign_role', 'station_mobilizer')
        is_admin_user = getattr(user, 'is_admin', False) or getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False)

        subordinates = []
        team_title = "My Direct Team"
        can_appoint = False
        allowed_roles_to_appoint = []

        if is_admin_user or role in ['governor', 'county_manager']:
            team_title = "County Campaign Command"
            can_appoint = True
            allowed_roles_to_appoint = [
                'county_manager', 'sub_county_coordinator', 'ward_coordinator',
                'polling_centre_coordinator', 'pillar', 'station_mobilizer'
            ]
            subordinates = Member.objects.filter(
                Q(supervisor=user) | Q(campaign_role__in=['sub_county_coordinator', 'ward_coordinator']),
                is_active=True
            ).order_by('campaign_role', 'full_name')

        elif role == 'sub_county_coordinator':
            team_title = f"Sub-County Team: {user.assigned_sub_county or 'Assigned Sub-County'}"
            can_appoint = True
            allowed_roles_to_appoint = ['ward_coordinator', 'polling_centre_coordinator']
            sub_county = user.assigned_sub_county or ''
            subordinates = Member.objects.filter(
                Q(supervisor=user) | (Q(assigned_sub_county=sub_county) & Q(campaign_role='ward_coordinator')),
                is_active=True
            ).order_by('full_name')

        elif role == 'ward_coordinator':
            ward = user.assigned_ward or user.ward or ''
            team_title = f"Ward Team: {ward or 'Assigned Ward'}"
            can_appoint = True
            allowed_roles_to_appoint = ['polling_centre_coordinator', 'pillar', 'station_mobilizer']
            subordinates = Member.objects.filter(
                Q(supervisor=user) | (Q(assigned_ward__iexact=ward) & Q(campaign_role='polling_centre_coordinator')),
                is_active=True
            ).order_by('assigned_polling_centre', 'full_name')

        elif role == 'polling_centre_coordinator':
            station = user.assigned_polling_centre or user.polling_station or ''
            team_title = f"Polling Centre Team: {station}"
            can_appoint = True
            allowed_roles_to_appoint = ['pillar', 'station_mobilizer']
            subordinates = Member.objects.filter(
                Q(supervisor=user) | (Q(assigned_polling_centre__iexact=station) & Q(campaign_role__in=['pillar', 'station_mobilizer'])),
                is_active=True
            ).order_by('campaign_role', 'full_name')

        elif role == 'pillar':
            station = user.assigned_polling_centre or user.polling_station or ''
            team_title = f"{user.get_pillar_category_display() if hasattr(user, 'get_pillar_category_display') else 'Pillar'} - Station Mobilizers"
            can_appoint = False
            subordinates = Member.objects.filter(
                Q(assigned_polling_centre__iexact=station) & Q(campaign_role='station_mobilizer'),
                is_active=True
            ).order_by('full_name')

        else:
            # Station mobilizers see their recruits downline
            team_title = "Voter Recruits & Downline"
            can_appoint = False
            subordinates = user.recruits.filter(is_active=True).order_by('-created_at')[:50]

        return response.Response({
            'user_role': role,
            'team_title': team_title,
            'can_appoint': can_appoint,
            'allowed_roles_to_appoint': allowed_roles_to_appoint,
            'team_count': subordinates.count() if hasattr(subordinates, 'count') else len(subordinates),
            'members': CampaignPersonnelSerializer(subordinates, many=True).data
        })


class CampaignAssignRoleView(views.APIView):
    """
    Appoint, promote, or assign a member to a specific campaign tier.
    Enforces strict cascading management authority and quotas:
      - Governor / County Manager: County-wide authority
      - Sub-County Coordinator: Only within assigned sub-county (appoints Ward Coordinators)
      - Ward Coordinator: Only within assigned ward (appoints Polling Centre Coordinators)
      - Polling Centre Coordinator: Only at assigned station (appoints 3 Pillars & 25 Mobilizers)
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        caller = request.user
        caller_role = getattr(caller, 'campaign_role', 'station_mobilizer')
        is_caller_admin = getattr(caller, 'is_admin', False) or getattr(caller, 'is_staff', False) or getattr(caller, 'is_superuser', False)

        data = request.data
        member_id = data.get('member_id')
        new_role = data.get('campaign_role')
        sub_county = data.get('assigned_sub_county', '').strip()
        ward = data.get('assigned_ward', '').strip()
        station = data.get('assigned_polling_centre', '').strip()
        pillar_category = data.get('pillar_category', 'none').strip()

        if not member_id or not new_role:
            return response.Response(
                {"error": "member_id and campaign_role are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        valid_roles = [r[0] for r in Member.CAMPAIGN_ROLES]
        if new_role not in valid_roles:
            return response.Response(
                {"error": f"Invalid campaign_role. Must be one of: {valid_roles}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        member = Member.objects.filter(id=member_id).first()
        if not member:
            return response.Response(
                {"error": "Member not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # ─── Strict Cascading Authority Enforcement ────────────────────────────
        if not is_caller_admin and caller_role not in ['governor', 'county_manager']:
            if caller_role == 'sub_county_coordinator':
                caller_sc = (caller.assigned_sub_county or '').strip()
                if new_role not in ['ward_coordinator', 'polling_centre_coordinator']:
                    return response.Response(
                        {"error": "Sub-County Coordinators can only appoint Ward Coordinators or Polling Centre Coordinators."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                if sub_county and caller_sc and sub_county.lower() != caller_sc.lower():
                    return response.Response(
                        {"error": f"Access Denied: You can only appoint leaders within your assigned Sub-County ({caller_sc})."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                sub_county = caller_sc # Auto-lock to caller's jurisdiction

            elif caller_role == 'ward_coordinator':
                caller_ward = (caller.assigned_ward or caller.ward or '').strip()
                if new_role not in ['polling_centre_coordinator', 'pillar', 'station_mobilizer']:
                    return response.Response(
                        {"error": "Ward Coordinators can only appoint Polling Centre Coordinators, Pillars, or Mobilizers."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                if ward and caller_ward and ward.lower() != caller_ward.lower():
                    return response.Response(
                        {"error": f"Access Denied: You can only appoint coordinators within your assigned Ward ({caller_ward})."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                ward = caller_ward # Auto-lock to caller's ward

            elif caller_role == 'polling_centre_coordinator':
                caller_station = (caller.assigned_polling_centre or caller.polling_station or '').strip()
                caller_ward = (caller.assigned_ward or caller.ward or '').strip()
                if new_role not in ['pillar', 'station_mobilizer']:
                    return response.Response(
                        {"error": "Polling Centre Coordinators can only appoint their 3 Pillars or 25 Mobilizers."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                if station and caller_station and station.lower() != caller_station.lower():
                    return response.Response(
                        {"error": f"Access Denied: You can only appoint personnel for your assigned Polling Centre ({caller_station})."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                station = caller_station # Auto-lock to caller's station
                if not ward:
                    ward = caller_ward

            else:
                return response.Response(
                    {"error": "You do not have appointment permissions in the campaign hierarchy."},
                    status=status.HTTP_403_FORBIDDEN
                )

        # Quota Validation Checks
        if new_role == 'pillar':
            if not station:
                return response.Response(
                    {"error": "Assigned Polling Centre is required for a Campaign Pillar."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if pillar_category not in ['youth', 'women', 'elders_business', 'special_interest']:
                return response.Response(
                    {"error": "A valid pillar category (youth, women, elders_business, special_interest) is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # Check maximum 3 pillars for this station
            current_pillars = Member.objects.filter(
                campaign_role='pillar',
                assigned_polling_centre__iexact=station,
                is_active=True
            ).exclude(id=member.id)
            if current_pillars.count() >= 3:
                return response.Response(
                    {
                        "error": f"Quota Exceeded: Polling Station '{station}' already has 3 assigned Pillars ({', '.join(current_pillars.values_list('full_name', flat=True))})."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

        if new_role == 'station_mobilizer':
            if station:
                current_mobs = Member.objects.filter(
                    campaign_role='station_mobilizer',
                    assigned_polling_centre__iexact=station,
                    is_active=True
                ).exclude(id=member.id)
                if current_mobs.count() >= 25:
                    return response.Response(
                        {
                            "warning": "quota_full",
                            "error": f"Station '{station}' has reached its target of 25 mobilizers ({current_mobs.count()} registered). Reassign or transfer existing mobilizer."
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

        # Update member
        member.campaign_role = new_role
        if sub_county:
            member.assigned_sub_county = sub_county
        if ward:
            member.assigned_ward = ward
        if station:
            member.assigned_polling_centre = station
        if pillar_category:
            member.pillar_category = pillar_category

        # Set supervisor to caller if not set
        if not member.supervisor and request.user.id != member.id:
            member.supervisor = request.user

        # If appointed as Governor or County Manager, set is_admin=True
        if new_role in ['governor', 'county_manager']:
            member.is_admin = True
            member.is_staff = True

        member.save()

        AuditLog.log(
            'ROLE_ASSIGNED',
            user=request.user,
            request=request,
            details={
                'target_member_id': member.id,
                'target_name': member.full_name,
                'assigned_role': new_role,
                'station': station,
                'ward': ward,
                'pillar_category': pillar_category
            }
        )

        return response.Response({
            "status": "success",
            "message": f"Successfully assigned {member.full_name} as {member.get_campaign_role_display()}.",
            "member": CampaignPersonnelSerializer(member).data
        })


class ConvertToMobilizerView(views.APIView):
    """
    Converts one or multiple social / online recruits into Polling Station Mobilizers.
    Sets source='field_mobilizer', campaign_role='station_mobilizer', and ensures they have mobilizer privileges.
    """
    permission_classes = [IsAdminUser]

    def post(self, request):
        member_ids = request.data.get('member_ids', [])
        single_id = request.data.get('member_id')
        
        if single_id:
            member_ids.append(single_id)

        if not member_ids:
            return response.Response(
                {"error": "At least one member_id or member_ids array is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        members = Member.objects.filter(id__in=member_ids, is_active=True)
        count = 0
        names = []

        for m in members:
            m.source = 'field_mobilizer'
            m.campaign_role = 'station_mobilizer'
            if not m.assigned_ward and m.ward:
                m.assigned_ward = m.ward
            if not m.assigned_polling_centre and m.polling_station:
                m.assigned_polling_centre = m.polling_station
            m.save()
            count += 1
            names.append(m.full_name)

        AuditLog.log(
            'CONVERT_TO_MOBILIZER',
            user=request.user,
            request=request,
            details={
                'member_ids': member_ids,
                'converted_count': count,
                'names': names
            }
        )

        return response.Response({
            "status": "success",
            "converted_count": count,
            "message": f"Successfully moved {count} recruit(s) to Mobilizer status.",
            "names": names
        })

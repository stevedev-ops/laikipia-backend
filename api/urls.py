from django.urls import path
from . import views

urlpatterns = [
    path('functions', views.CampaignFunctionListView.as_view(), name='function-list'),
    path('functions/<int:pk>', views.CampaignFunctionDetailView.as_view(), name='function-detail'),
    path('members/<int:pk>/toggle-active/', views.MemberToggleActiveView.as_view(), name='toggle-member-active'),
    path('members/<int:pk>/toggle-opt-out/', views.MemberToggleOptOutView.as_view(), name='toggle-member-opt-out'),
    path('login', views.MemberLoginView.as_view(), name='login'),
    path('register', views.MemberRegisterView.as_view(), name='register'),
    path('config', views.CampaignConfigView.as_view(), name='campaign-config'),
    path('members/claim-social', views.MemberClaimSocialView.as_view(), name='claim-social'),
    path('members/check-status', views.MemberCheckStatusView.as_view(), name='check-member-status'),

    path('members/me', views.MemberMeView.as_view(), name='member-me'),
    path('members/<str:identifier>/public', views.MemberPublicView.as_view(), name='member-public'),
    path('members/<int:pk>/insights', views.MemberInsightsView.as_view(), name='insights'),

    path('members/export-csv', views.MemberExportCsvView.as_view(), name='members-export-csv'),
    path('members', views.MemberListView.as_view(), name='member-list'),
    path('members/<int:pk>', views.MemberDetailView.as_view(), name='member-detail'),
    path('stats', views.SystemStatsView.as_view(), name='stats'),
    path('stats/reports', views.ReportStatsView.as_view(), name='report-stats'),
    path('stats/ward-health', views.WardHealthInsightsView.as_view(), name='ward-health'),
    path('stats/demographics', views.DemographicInsightsView.as_view(), name='demographics'),

    path('stats/fraud-alerts', views.FraudDetectionView.as_view(), name='fraud-alerts'),
    path('stats/saturation', views.SaturationPredictionView.as_view(), name='saturation'),
    path('members/<int:pk>/targets', views.TargetMatchingView.as_view(), name='targets'),

    path('invites', views.InviteCreateView.as_view(), name='invite-create'),
    path('invites/<uuid:id>', views.InviteDetailView.as_view(), name='invite-detail'),
    path('voter-records', views.VoterRecordListView.as_view(), name='voter-records'),
    path('voter-lookup', views.VoterLookupView.as_view(), name='voter-lookup'),
    path('polling-coverage', views.PollingCoverageView.as_view(), name='polling-coverage'),
    path('leaderboard', views.LeaderboardView.as_view(), name='leaderboard'),
    path('gotv', views.GotvListView.as_view(), name='gotv-list'),
    path('gotv/<int:pk>/voted', views.GotvMarkVotedView.as_view(), name='gotv-mark-voted'),
    # Panna Pramukh
    path('canvass', views.CanvassListView.as_view(), name='canvass-list'),
    path('canvass/<int:pk>', views.CanvassDetailView.as_view(), name='canvass-detail'),
    # Boda-boda Transport
    path('transport', views.TransportListView.as_view(), name='transport-list'),
    path('transport/<int:pk>', views.TransportUpdateView.as_view(), name='transport-update'),
    # Polling Agents
    path('agents', views.AgentListView.as_view(), name='agent-list'),
    path('agents/<int:pk>/checkin', views.AgentCheckInView.as_view(), name='agent-checkin'),
    # PVT Tallies
    path('tally', views.TallyListView.as_view(), name='tally-list'),
    # SMS Export
    path('sms-export', views.SmsExportView.as_view(), name='sms-export'),
    # Relational Contact Matcher
    path('contact-matcher', views.ContactMatcherView.as_view(), name='contact-matcher'),
    # Ushahidi-Style Incidents
    path('incidents', views.IncidentListView.as_view(), name='incident-list'),
    path('incidents/<int:pk>', views.IncidentDetailView.as_view(), name='incident-detail'),
    # Virtual Phone Banking
    path('phone-bank/queue', views.PhoneBankQueueView.as_view(), name='phonebank-queue'),
    path('phone-bank/call', views.CallRecordCreateView.as_view(), name='phonebank-call'),
    # Events & Rally Check-ins
    path('events', views.EventListView.as_view(), name='event-list'),
    path('events/<int:pk>', views.EventDetailView.as_view(), name='event-detail'),
    path('events/<int:event_id>/attendance', views.EventAttendanceView.as_view(), name='event-attendance'),
    # Emergency Broadcast
    path('broadcasts', views.EmergencyBroadcastView.as_view(), name='emergency-broadcasts'),
    path('wards-and-stations', views.get_wards_and_stations, name='wards-and-stations'),
    # Security Logs
    path('security-logs', views.SecurityLogListView.as_view(), name='security-logs-list'),
    path('security-logs/<int:pk>', views.SecurityLogDetailView.as_view(), name='security-logs-detail'),
    path('security-personnel', views.SecurityPersonnelListView.as_view(), name='security-personnel-list'),
    path('security-mia', views.SecurityMIAView.as_view(), name='security-mia'),
]

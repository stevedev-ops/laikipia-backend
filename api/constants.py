"""
Centralized Campaign Geographic & Role Constants for DCP Laikipia
"""

CONSTITUENCIES = {
    "Laikipia West": ["Githiga", "Igwamiti", "Marmanet", "Ol-Moran", "Rumuruti Township", "Salama"],
    "Laikipia East": ["Nanyuki", "Thingithu", "Tigithi", "Ngobit", "Umande"],
    "Laikipia North": ["Mugogodo East", "Mugogodo West", "Segera", "Sosian"],
}

SUBCOUNTY_TO_WARDS = CONSTITUENCIES

ALL_LAIKIPIA_WARDS = [ward for wards in CONSTITUENCIES.values() for ward in wards]

WARD_TO_SUBCOUNTY = {
    'nanyuki': 'Laikipia East',
    'thingithu': 'Laikipia East',
    'ngobit': 'Laikipia East',
    'tigithi': 'Laikipia East',
    'umande': 'Laikipia East',
    'ol moran': 'Laikipia West',
    'ol-moran': 'Laikipia West',
    'rumuruti township': 'Laikipia West',
    'rumuruti': 'Laikipia West',
    'githiga': 'Laikipia West',
    'marmanet': 'Laikipia West',
    'igwamiti': 'Laikipia West',
    'salama': 'Laikipia West',
    'mugogodo east': 'Laikipia North',
    'mugogodo west': 'Laikipia North',
    'mukogodo east': 'Laikipia North',
    'mukogodo west': 'Laikipia North',
    'segera': 'Laikipia North',
    'sosian': 'Laikipia North'
}

CAMPAIGN_ROLES = [
    ('governor', 'Governor Aspirant'),
    ('county_manager', 'County Campaigns Manager'),
    ('sub_county_coordinator', 'Sub-County Coordinator'),
    ('ward_coordinator', 'Ward Coordinator'),
    ('polling_centre_coordinator', 'Polling Centre Coordinator'),
    ('pillar', 'Campaign Pillar'),
    ('station_mobilizer', 'Polling Station Mobilizer'),
]

PILLAR_CATEGORIES = [
    ('youth', 'Youth Pillar'),
    ('women', 'Women Pillar'),
    ('elders_business', 'Elders & Business Pillar'),
    ('special_interest', 'Special Interest Pillar'),
]

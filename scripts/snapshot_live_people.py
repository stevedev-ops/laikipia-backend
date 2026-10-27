import os
import sys
import re
import csv
import json
import gzip
import shutil
import sqlite3
import tarfile
import datetime
import urllib.request
import urllib.error
from pathlib import Path

BASE_API_URL = os.environ.get("LIVE_API_URL", "https://laikipia-backend.onrender.com/api")
ADMIN_FIRST_NAME = os.environ.get("ADMIN_FIRST_NAME", "HQ")
ADMIN_NATIONAL_ID = os.environ.get("ADMIN_NATIONAL_ID", "11111111")

def api_request(path: str, token: str = None, method: str = "GET", data: dict = None):
    url = f"{BASE_API_URL.rstrip('/')}/{path.lstrip('/')}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Token {token}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        content_type = resp.headers.get("Content-Type", "")
        payload = resp.read()
        if "json" in content_type:
            return json.loads(payload.decode("utf-8"))
        return payload.decode("utf-8", errors="replace")

def get_auth_token():
    print(f"[*] Authenticating against live production ({BASE_API_URL})...")
    login_data = {
        "firstName": ADMIN_FIRST_NAME,
        "nationalId": ADMIN_NATIONAL_ID
    }
    res = api_request("login", method="POST", data=login_data)
    token = res.get("token")
    if not token:
        raise RuntimeError(f"Authentication failed: {res}")
    member = res.get("member", {})
    print(f"[+] Authenticated as {member.get('full_name')} (ID: {member.get('national_id')}, Role: {member.get('campaign_role')})")
    return token

def fetch_all_people(token: str):
    print("[*] Fetching complete directory roster from live system...")
    directory = api_request("hierarchy/directory", token=token)
    print(f"[+] Directory records retrieved: {len(directory)}")
    directory.sort(key=lambda x: x.get("id", 0))

    all_detailed_people = []
    print("[*] Fetching comprehensive member profiles for each person...")
    for item in directory:
        mid = item["id"]
        try:
            detail = api_request(f"members/{mid}", token=token)
            all_detailed_people.append(detail)
            sys.stdout.write(f"\r  -> Retrieved profile {len(all_detailed_people)}/{len(directory)} (ID {mid}: {detail.get('full_name')})")
            sys.stdout.flush()
        except Exception as e:
            print(f"\n[!] Warning: Error fetching detail for ID {mid}: {e}")
            all_detailed_people.append(item)
    print("\n[+] Successfully captured all individual member profiles.")
    return all_detailed_people

def fetch_campaign_functions(token: str):
    print("[*] Fetching live campaign functions and community contacts...")
    try:
        funcs = api_request("functions", token=token)
        print(f"[+] Campaign functions retrieved: {len(funcs)}")
        return funcs
    except Exception as e:
        print(f"[!] Warning: Could not fetch campaign functions: {e}")
        return []

def fetch_coverage_stats(token: str):
    print("[*] Fetching live ward coverage statistics...")
    try:
        stats = api_request("stats/reports", token=token)
        return stats
    except Exception as e:
        print(f"[!] Warning: Could not fetch stats/reports: {e}")
        return {}

def fetch_hierarchy_tree(token: str):
    print("[*] Fetching live 7-tier campaign hierarchy tree...")
    try:
        tree = api_request("hierarchy/tree", token=token)
        print(f"[+] Hierarchy tree retrieved ({len(tree.get('wards', []))} wards mapped)")
        return tree
    except Exception as e:
        print(f"[!] Warning: Could not fetch hierarchy/tree: {e}")
        return {}

def fetch_hierarchy_stats(token: str):
    print("[*] Fetching live hierarchy command stats and quotas...")
    try:
        stats = api_request("hierarchy/stats", token=token)
        print(f"[+] Hierarchy command stats retrieved")
        return stats
    except Exception as e:
        print(f"[!] Warning: Could not fetch hierarchy/stats: {e}")
        return {}

def format_kenyan_phone_for_csv(phone_str: str) -> str:
    if not phone_str:
        return ""
    phone_clean = str(phone_str).strip()
    digits = re.sub(r'\D', '', phone_clean)
    if digits.startswith('254') and len(digits) == 12:
        digits = '0' + digits[3:]
    elif len(digits) == 9 and digits.startswith(('7', '1')):
        digits = '0' + digits
    if len(digits) == 10 and digits.startswith(('07', '01')):
        return f"{digits[:4]} {digits[4:7]} {digits[7:]}"
    return phone_clean

def generate_csv(people: list, out_path: Path):
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID",
            "Full Name",
            "Phone (Call / WhatsApp)",
            "National ID",
            "Email",
            "Campaign Role",
            "Pillar Category",
            "Assigned Sub-County",
            "Assigned Ward",
            "Assigned Polling Centre",
            "Registered Ward",
            "Registered Polling Station",
            "Official IEBC Ward",
            "Official IEBC Polling Station",
            "Recruitment Source",
            "Volunteer Role",
            "Custom Role / Skills",
            "Supervisor / Mobilizer ID",
            "Supervisor / Mobilizer Name",
            "Recruits Count",
            "Verified 2022 Voter",
            "DPA Opt-Out Status",
            "Registration Date",
            "Active Status",
            "Admin / Staff Status",
            "Security Rank",
            "Referral Code (UUID)"
        ])
        sorted_people = sorted(people, key=lambda x: (
            x.get("campaign_role") != "governor",
            x.get("campaign_role") != "county_manager",
            x.get("ward") or "",
            x.get("full_name") or ""
        ))
        for p in sorted_people:
            phone_val = format_kenyan_phone_for_csv(p.get("phone"))
            phone_cell = f'="{phone_val}"' if phone_val else ""
            id_cell = f'="{p.get("national_id")}"' if p.get("national_id") else ""
            writer.writerow([
                p.get("id"),
                p.get("full_name"),
                phone_cell,
                id_cell,
                p.get("email") or "",
                p.get("campaign_role") or "",
                p.get("pillar_category") or "",
                p.get("assigned_sub_county") or "",
                p.get("assigned_ward") or "",
                p.get("assigned_polling_centre") or "",
                p.get("ward") or "",
                p.get("polling_station") or "",
                p.get("official_ward") or "",
                p.get("official_polling_station") or "",
                p.get("source") or "",
                p.get("volunteer_role") or "",
                p.get("custom_role") or "",
                p.get("supervisor") or p.get("referred_by") or "",
                p.get("supervisor_name") or p.get("referrer_name") or "",
                p.get("recruits_count", 0),
                "Yes" if p.get("is_voter_verified") else "No",
                "Opted Out" if p.get("is_opted_out") else "Active Consent",
                p.get("created_at") or "",
                "Active" if p.get("is_active", True) else "Deactivated",
                "Yes" if (p.get("is_admin") or p.get("is_staff")) else "No",
                p.get("security_rank") or "none",
                p.get("uuid") or ""
            ])

def generate_functions_csv(funcs: list, out_path: Path):
    with open(out_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID",
            "Event Title",
            "Event Type",
            "Event Date",
            "Start Time",
            "Constituency",
            "Ward",
            "Venue",
            "Contact Person Name",
            "Contact Person Phone",
            "Expected Attendance",
            "Status",
            "Delegate Name",
            "Delegate Phone",
            "Submitted By",
            "Admin Notes",
            "Created At"
        ])
        for fn in funcs:
            phone_val = format_kenyan_phone_for_csv(fn.get("contact_person_phone"))
            phone_cell = f'="{phone_val}"' if phone_val else ""
            del_phone = format_kenyan_phone_for_csv(fn.get("delegate_phone"))
            del_cell = f'="{del_phone}"' if del_phone else ""
            writer.writerow([
                fn.get("id"),
                fn.get("title"),
                fn.get("event_type_display") or fn.get("event_type"),
                fn.get("event_date"),
                fn.get("start_time"),
                fn.get("constituency"),
                fn.get("ward"),
                fn.get("venue"),
                fn.get("contact_person_name"),
                phone_cell,
                fn.get("expected_attendance"),
                fn.get("status_display") or fn.get("status"),
                fn.get("delegate_name") or "",
                del_cell,
                fn.get("submitted_by_name") or "",
                fn.get("admin_notes") or "",
                fn.get("created_at") or ""
            ])

def generate_django_fixtures(people: list, out_path: Path):
    fixture_items = []
    for p in people:
        fields = {
            "password": "!",
            "last_login": None,
            "is_superuser": bool(p.get("is_admin") or p.get("is_staff")),
            "uuid": p.get("uuid"),
            "full_name": p.get("full_name"),
            "phone": p.get("phone"),
            "national_id": p.get("national_id"),
            "email": p.get("email"),
            "yob": p.get("yob"),
            "gender": p.get("gender"),
            "ward": p.get("ward"),
            "polling_station": p.get("polling_station"),
            "official_ward": p.get("official_ward"),
            "official_polling_station": p.get("official_polling_station"),
            "referred_by": p.get("referred_by"),
            "is_admin": bool(p.get("is_admin")),
            "is_staff": bool(p.get("is_staff")),
            "is_security": bool(p.get("is_security")),
            "security_rank": p.get("security_rank", "none"),
            "is_security_only": bool(p.get("is_security_only")),
            "is_active": bool(p.get("is_active", True)),
            "is_opted_out": bool(p.get("is_opted_out", False)),
            "opted_out_at": p.get("opted_out_at"),
            "is_voter_verified": bool(p.get("is_voter_verified", False)),
            "has_voted": bool(p.get("has_voted", False)),
            "supporter_score": p.get("supporter_score"),
            "top_issue": p.get("top_issue"),
            "campaign_role": p.get("campaign_role", "station_mobilizer"),
            "pillar_category": p.get("pillar_category", "none"),
            "assigned_sub_county": p.get("assigned_sub_county"),
            "assigned_ward": p.get("assigned_ward"),
            "assigned_polling_centre": p.get("assigned_polling_centre"),
            "supervisor": p.get("supervisor"),
            "source": p.get("source", "field_mobilizer"),
            "volunteer_role": p.get("volunteer_role"),
            "custom_role": p.get("custom_role"),
            "created_at": p.get("created_at"),
            "groups": [],
            "user_permissions": []
        }
        fixture_items.append({
            "model": "api.member",
            "pk": p.get("id"),
            "fields": fields
        })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(fixture_items, f, indent=2, ensure_ascii=False)

def sync_local_sqlite(people: list, db_path: Path):
    if not db_path.exists():
        print(f"[*] Local sqlite DB not found at {db_path}, skipping local sync.")
        return
    print(f"[*] Syncing {len(people)} live members into local SQLite: {db_path}")
    bak_path = db_path.with_suffix(".sqlite3.pre_live_sync.bak")
    if not bak_path.exists():
        shutil.copy2(db_path, bak_path)
        print(f"[+] Backed up original local database to {bak_path.name}")

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(api_member)")
    cols = [row[1] for row in cur.fetchall()]

    synced = 0
    for p in people:
        pid = p.get("id")
        nat_id = p.get("national_id") or ""
        row = None
        if nat_id:
            cur.execute("SELECT id FROM api_member WHERE national_id = ?", (nat_id,))
            row = cur.fetchone()
        if not row:
            cur.execute("SELECT id FROM api_member WHERE id = ?", (pid,))
            row = cur.fetchone()

        field_data = {
            "id": pid,
            "uuid": p.get("uuid"),
            "full_name": p.get("full_name") or "",
            "phone": p.get("phone") or "",
            "national_id": p.get("national_id") or "",
            "email": p.get("email"),
            "yob": p.get("yob"),
            "gender": p.get("gender"),
            "ward": p.get("ward"),
            "polling_station": p.get("polling_station"),
            "official_ward": p.get("official_ward"),
            "official_polling_station": p.get("official_polling_station"),
            "referred_by_id": p.get("referred_by"),
            "is_admin": 1 if p.get("is_admin") else 0,
            "is_staff": 1 if p.get("is_staff") else 0,
            "is_superuser": 1 if (p.get("is_admin") or p.get("is_staff")) else 0,
            "is_security": 1 if p.get("is_security") else 0,
            "security_rank": p.get("security_rank", "none"),
            "is_security_only": 1 if p.get("is_security_only") else 0,
            "is_active": 1 if p.get("is_active", True) else 0,
            "is_opted_out": 1 if p.get("is_opted_out") else 0,
            "opted_out_at": p.get("opted_out_at"),
            "is_voter_verified": 1 if p.get("is_voter_verified") else 0,
            "has_voted": 1 if p.get("has_voted") else 0,
            "supporter_score": p.get("supporter_score"),
            "top_issue": p.get("top_issue"),
            "campaign_role": p.get("campaign_role", "station_mobilizer"),
            "pillar_category": p.get("pillar_category", "none"),
            "assigned_sub_county": p.get("assigned_sub_county"),
            "assigned_ward": p.get("assigned_ward"),
            "assigned_polling_centre": p.get("assigned_polling_centre"),
            "supervisor_id": p.get("supervisor"),
            "source": p.get("source", "field_mobilizer"),
            "volunteer_role": p.get("volunteer_role"),
            "custom_role": p.get("custom_role"),
            "created_at": p.get("created_at") or datetime.datetime.now().isoformat(),
            "password": "!"
        }

        valid_cols = [c for c in cols if c in field_data]
        if row:
            match_id = row[0]
            set_clause = ", ".join([f"{c} = ?" for c in valid_cols if c != "id"])
            vals = [field_data[c] for c in valid_cols if c != "id"] + [match_id]
            cur.execute(f"UPDATE api_member SET {set_clause} WHERE id = ?", vals)
        else:
            col_names = ", ".join(valid_cols)
            placeholders = ", ".join(["?"] * len(valid_cols))
            vals = [field_data[c] for c in valid_cols]
            cur.execute(f"INSERT INTO api_member ({col_names}) VALUES ({placeholders})", vals)
        synced += 1

    conn.commit()
    conn.close()
    print(f"[+] Synchronized {synced} member records into local SQLite database.")

def main():
    print("=" * 70)
    print("   DCP LAIKIPIA - LIVE PEOPLE AND CAMPAIGN DATA SNAPSHOT ENGINE")
    print("=" * 70)

    token = get_auth_token()
    people = fetch_all_people(token)
    funcs = fetch_campaign_functions(token)
    stats = fetch_coverage_stats(token)
    tree = fetch_hierarchy_tree(token)
    hier_stats = fetch_hierarchy_stats(token)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    workspace_backup_dir = Path("/home/steve/projects/laikipia/backups")
    workspace_backup_dir.mkdir(parents=True, exist_ok=True)

    laptop_backup_dir = Path("/mnt/c/Users/Admin/laikipia_backups")
    laptop_backup_dir.mkdir(parents=True, exist_ok=True)

    destinations = [workspace_backup_dir, laptop_backup_dir]

    print(f"\n[*] Generating snapshots and export files (Timestamp: {timestamp})...")

    created_files = []
    for d in destinations:
        json_file = d / f"laikipia_people_live_snapshot_{timestamp}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump({
                "snapshot_timestamp": datetime.datetime.now().isoformat(),
                "total_people": len(people),
                "source": BASE_API_URL,
                "people": people
            }, f, indent=2, ensure_ascii=False)
        created_files.append(json_file)

        latest_json = d / "laikipia_people_live_snapshot_latest.json"
        shutil.copy2(json_file, latest_json)

        csv_file = d / f"laikipia_people_live_snapshot_{timestamp}.csv"
        generate_csv(people, csv_file)
        created_files.append(csv_file)

        latest_csv = d / "laikipia_people_live_snapshot_latest.csv"
        shutil.copy2(csv_file, latest_csv)

        fixture_file = d / f"laikipia_members_django_fixture_{timestamp}.json"
        generate_django_fixtures(people, fixture_file)
        created_files.append(fixture_file)

        if funcs:
            fn_json = d / f"laikipia_campaign_functions_{timestamp}.json"
            with open(fn_json, "w", encoding="utf-8") as f:
                json.dump(funcs, f, indent=2, ensure_ascii=False)
            created_files.append(fn_json)

            fn_csv = d / f"laikipia_campaign_functions_{timestamp}.csv"
            generate_functions_csv(funcs, fn_csv)
            created_files.append(fn_csv)

        if stats:
            stats_file = d / f"laikipia_ward_coverage_summary_{timestamp}.json"
            with open(stats_file, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            created_files.append(stats_file)

        if tree:
            tree_file = d / f"laikipia_hierarchy_tree_{timestamp}.json"
            with open(tree_file, "w", encoding="utf-8") as f:
                json.dump(tree, f, indent=2, ensure_ascii=False)
            created_files.append(tree_file)

            latest_tree = d / "laikipia_hierarchy_tree_latest.json"
            shutil.copy2(tree_file, latest_tree)

        if hier_stats:
            hstats_file = d / f"laikipia_hierarchy_stats_{timestamp}.json"
            with open(hstats_file, "w", encoding="utf-8") as f:
                json.dump(hier_stats, f, indent=2, ensure_ascii=False)
            created_files.append(hstats_file)

        tar_gz_file = d / f"laikipia_people_live_snapshot_{timestamp}.tar.gz"
        with tarfile.open(tar_gz_file, "w:gz") as tar:
            tar.add(json_file, arcname=json_file.name)
            tar.add(csv_file, arcname=csv_file.name)
            tar.add(fixture_file, arcname=fixture_file.name)
            if funcs:
                tar.add(fn_json, arcname=fn_json.name)
                tar.add(fn_csv, arcname=fn_csv.name)
            if stats:
                tar.add(stats_file, arcname=stats_file.name)
            if tree:
                tar.add(tree_file, arcname=tree_file.name)
            if hier_stats:
                tar.add(hstats_file, arcname=hstats_file.name)
        created_files.append(tar_gz_file)

    backend_dir = Path("/home/steve/projects/laikipia/ol-kalou-backend")
    sync_local_sqlite(people, backend_dir / "db.sqlite3")

    admin_count = sum(1 for p in people if p.get('is_admin') or p.get('is_staff'))
    mobilizer_count = len(people) - admin_count

    print("\n" + "=" * 70)
    print("                      BACKUP COMPLETED")
    print("=" * 70)
    print(f"Total People Captured: {len(people)}")
    print(f"Leadership / Staff:    {admin_count}")
    print(f"Mobilizers / Members:  {mobilizer_count}")
    print(f"Community Functions:   {len(funcs)}")
    print(f"\nFiles generated in:")
    print(f"  - Laptop Storage:    C:\\Users\\Admin\\laikipia_backups\\")
    print(f"  - Workspace Storage: /home/steve/projects/laikipia/backups/")
    for f in created_files[:7]:
        print(f"   * {f.name} ({f.stat().st_size:,} bytes)")
    print("=" * 70)

if __name__ == "__main__":
    main()

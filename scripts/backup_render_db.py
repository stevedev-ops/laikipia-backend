#!/usr/bin/env python3
"""
Automated Database Backup Engine for DCP Laikipia Campaign
Downloads live snapshots from Render PostgreSQL directly to local laptop storage.
Saves timestamped compressed archives and auto-prunes backups older than 30 days.
"""

import os
import sys
import time
import gzip
import shutil
import subprocess
import datetime
from pathlib import Path

# Fix Windows terminal UTF-8 encoding
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def get_backup_dir() -> Path:
    """Resolves cross-platform local backup directory on laptop."""
    if sys.platform == 'win32':
        b_dir = Path(os.environ.get("USERPROFILE", r"C:\Users\Admin")) / "laikipia_backups"
    else:
        # WSL or Linux
        if os.path.exists('/mnt/c/Users/Admin'):
            b_dir = Path('/mnt/c/Users/Admin/laikipia_backups')
        else:
            b_dir = Path.home() / 'laikipia_backups'
    b_dir.mkdir(parents=True, exist_ok=True)
    return b_dir

def load_db_url():
    """Finds Database URL from environment, .env file, or config."""
    # 1. Check direct environment variable
    url = os.environ.get("RENDER_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if url and "postgres" in url:
        return url

    # 2. Check .env file in ol-kalou-backend
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("RENDER_DATABASE_URL=") or line.startswith("DATABASE_URL="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if "postgres" in val:
                        return val

    # 3. Check backup_config.json in script dir
    cfg_file = Path(__file__).resolve().parent / "backup_config.json"
    if cfg_file.exists():
        import json
        with open(cfg_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("database_url")

    # 4. Fallback to local database snapshot if no postgres configured
    return "sqlite"

def prune_old_backups(directory: Path, max_age_days: int = 30):
    """Deletes backups older than max_age_days to keep laptop disk clean."""
    if not directory.exists():
        return
    now = time.time()
    cutoff = now - (max_age_days * 86400)
    for item in directory.glob("laikipia_backup_*.*"):
        try:
            if item.stat().st_mtime < cutoff:
                item.unlink()
                print(f"[CLEANUP] Pruned old archive: {item.name}")
        except Exception:
            pass

def perform_backup():
    print("=" * 65)
    print("  DCP LAIKIPIA - AUTOMATED DATABASE BACKUP TO LAPTOP")
    print("=" * 65)
    
    target_dir = get_backup_dir()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    db_url = load_db_url()

    print(f"Destination: {target_dir}")
    print(f"Timestamp:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if db_url == "sqlite":
        print("Mode:        Local Database Snapshot")
    print("Connecting and capturing snapshot...")

    # Step 1: Capture live people & campaign roster from live API
    try:
        backend_dir = str(Path(__file__).resolve().parent.parent)
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        from scripts.snapshot_live_people import main as snapshot_people
        snapshot_people()
    except Exception as e:
        print(f"[NOTICE] Live people API snapshot: {e}")

    sql_file = target_dir / f"laikipia_backup_{timestamp}.sql"
    gz_file = target_dir / f"laikipia_backup_{timestamp}.sql.gz"

    pg_dump_bin = shutil.which("pg_dump")

    # Method 1: Direct pg_dump if PostgreSQL URL and pg_dump are present
    if pg_dump_bin and db_url != "sqlite":
        try:
            cmd = [
                pg_dump_bin,
                "--dbname", db_url,
                "--no-owner",
                "--no-acl",
                "--clean",
                "--if-exists",
                "-f", str(sql_file)
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0 and sql_file.exists() and sql_file.stat().st_size > 0:
                with open(sql_file, "rb") as f_in:
                    with gzip.open(gz_file, "wb", compresslevel=9) as f_out:
                        shutil.copyfileobj(f_in, f_out)
                sql_file.unlink()
                size_mb = gz_file.stat().st_size / (1024 * 1024)
                print(f"[SUCCESS] Backup successful via pg_dump!")
                print(f"[SAVED]   {gz_file.name} ({size_mb:.2f} MB)")
                prune_old_backups(target_dir, max_age_days=30)
                return True
        except Exception as e:
            print(f"[NOTICE] pg_dump: {e}, falling back to Django data dump...")

    # Method 2: Python / Django Dumpdata Fallback (Works everywhere on Windows & WSL)
    try:
        if db_url != "sqlite":
            os.environ["DATABASE_URL"] = db_url
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
        
        backend_dir = str(Path(__file__).resolve().parent.parent)
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)

        import django
        django.setup()
        from django.core.management import call_command

        json_gz_file = target_dir / f"laikipia_backup_{timestamp}.json.gz"
        raw_json_file = target_dir / f"laikipia_backup_{timestamp}.json"

        with open(raw_json_file, "w", encoding="utf-8") as f:
            call_command("dumpdata", exclude=["contenttypes", "auth.permission"], stdout=f, indent=2)

        with open(raw_json_file, "rb") as f_in:
            with gzip.open(json_gz_file, "wb", compresslevel=9) as f_out:
                shutil.copyfileobj(f_in, f_out)

        raw_json_file.unlink()
        size_mb = json_gz_file.stat().st_size / (1024 * 1024)
        print(f"[SUCCESS] Database backup completed successfully!")
        print(f"[SAVED]   {json_gz_file.name} ({size_mb:.2f} MB)")
        prune_old_backups(target_dir, max_age_days=30)
        return True

    except Exception as err:
        print(f"[ERROR] Backup failed: {err}")
        return False

if __name__ == "__main__":
    success = perform_backup()
    if not success:
        sys.exit(1)

@echo off
title DCP Laikipia - Live Database Backup
color 0A
echo ====================================================================
echo      DCP LAIKIPIA - LIVE DATABASE BACKUP TO LAPTOP
echo ====================================================================
echo.
wsl -d Ubuntu-24.04 bash -c "cd /home/steve/projects/laikipia/ol-kalou-backend; python3 scripts/backup_render_db.py"

echo.
echo ====================================================================
echo  Backups stored in: %USERPROFILE%\laikipia_backups\
echo ====================================================================
echo.
pause

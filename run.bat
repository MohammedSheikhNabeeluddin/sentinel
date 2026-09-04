@echo off
echo Starting AICTE Cyber Risk Platform + Strix...
cd /d D:\hackathon\cyber-risk-platform
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
pause

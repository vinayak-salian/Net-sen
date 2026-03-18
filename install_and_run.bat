
@echo off
echo [*] Initializing NetSentinel Core Installation...
echo [*] Installing required dependencies...

pip install -r requirements.txt

echo [*] Launching NetSentinel Agent with Administrator Privileges...
python agent.py

pause

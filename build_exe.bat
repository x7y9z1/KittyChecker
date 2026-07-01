@echo off
pip install pyinstaller
pyinstaller --onefile --console --name KittyChecker --icon image.ico --noconfirm --clean --hidden-import ctypes.wintypes --hidden-import winreg --hidden-import glob kitty_checker.py
del KittyChecker.spec
rmdir /s /q build
echo Done. Check dist\KittyChecker.exe
pause

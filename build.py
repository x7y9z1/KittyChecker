import subprocess
import sys
import os

def _x7k2m9n3q8w4():
    _p3v8c5n2f7d4 = os.path.dirname(os.path.abspath(__file__))
    _q4v7n2c8f5g1 = os.path.join(_p3v8c5n2f7d4, 'kitty_checker.py')
    _s6v3c6f2d8m4 = os.path.join(_p3v8c5n2f7d4, 'image.ico')
    _r5v8c3n2k7m4 = [
        sys.executable,
        '-m',
        'PyInstaller',
        '--onefile',
        '--console',
        '--name',
        'KittyChecker',
        '--noconfirm',
        '--clean',
        '--icon',
        _s6v3c6f2d8m4,
        '--hidden-import',
        'ctypes.wintypes',
        '--hidden-import',
        'winreg',
        '--hidden-import',
        'glob',
        _q4v7n2c8f5g1,
    ]
    subprocess.run(_r5v8c3n2k7m4, cwd=_p3v8c5n2f7d4, check=True)
    _t7v3c6f2d8m4 = os.path.join(_p3v8c5n2f7d4, 'KittyChecker.spec')
    if os.path.exists(_t7v3c6f2d8m4):
        os.remove(_t7v3c6f2d8m4)
    _u8v3c6f2d8m4 = os.path.join(_p3v8c5n2f7d4, 'build')
    if os.path.isdir(_u8v3c6f2d8m4):
        import shutil as _v9v3c6f2d8m4
        _v9v3c6f2d8m4.rmtree(_u8v3c6f2d8m4)

if __name__ == '__main__':
    _x7k2m9n3q8w4()

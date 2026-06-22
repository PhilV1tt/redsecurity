# PyInstaller spec for the native BeSecured app.
#
#   pyinstaller packaging/BeSecured.spec
#
# Output: dist/BeSecured.app on macOS, dist/BeSecured/BeSecured.exe on Windows.
# PyInstaller does not cross-compile: build the .app on macOS and the .exe on
# Windows.
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve().parent
STATIC = ROOT / "besecured" / "ui" / "static"

if sys.platform == "darwin":
    icon = str(ROOT / "packaging" / "BeSecured.icns")
elif sys.platform == "win32":
    icon = str(ROOT / "packaging" / "BeSecured.ico")
else:
    icon = None

a = Analysis(
    [str(ROOT / "besecured" / "app.py")],
    pathex=[str(ROOT)],
    datas=[(str(STATIC), "besecured/ui/static")],
    hiddenimports=collect_submodules("webview"),
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="BeSecured",
    console=False,
    icon=icon,
)
coll = COLLECT(exe, a.binaries, a.datas, name="BeSecured")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="BeSecured.app",
        icon=icon,
        bundle_identifier="com.besecured.app",
        info_plist={
            "CFBundleShortVersionString": "0.1.0",
            "NSHighResolutionCapable": True,
        },
    )

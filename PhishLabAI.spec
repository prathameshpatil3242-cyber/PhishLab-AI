# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for PhishLab AI desktop app (Windows).
# Build with:  pyinstaller --clean PhishLabAI.spec

import os

block_cipher = None
ROOT = os.path.abspath(SPECPATH)

a = Analysis(
    ["desktop.py"],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, "templates"), "templates"),
        (os.path.join(ROOT, "static"), "static"),
        (os.path.join(ROOT, "models"), "models"),
        (os.path.join(ROOT, "data"), "data"),
        (os.path.join(ROOT, "phishlab"), "phishlab"),
    ],
    hiddenimports=[
        "phishlab",
        "phishlab.analyzer",
        "phishlab.awareness_data",
        "phishlab.metrics",
        "phishlab.storage",
        "phishlab.train_model",
        "phishlab.url_analyzer",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "tkinter"],
    noarchive=False,
    optimize=0,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="PhishLabAI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # windowed app — no console flash
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,              # drop an .ico path here if you have one
)

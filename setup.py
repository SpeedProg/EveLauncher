from distutils.core import setup

import py2exe

setup(
    name='Python Launcher for EvE',
    description="Commandline Launcher for Eve",
    version="0.0.14",
    windows=['PveLauncher.py'],
    console=[{'script': 'PveConsole.py'}],
    options={'py2exe': {
        'packages': ['dbm'],
        'includes': 'eve, utils, gui',
        'dist_dir': 'PveLauncher',
        'bundle_files': 3,
        'optimize': 2
    }}
)
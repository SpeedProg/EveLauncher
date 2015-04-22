from distutils.core import setup
import py2exe

setup(
    name='Python Launcher for EvE',
    description="Commandline Launcher for Eve",
    version="0.0.7",
    windows=['PveLauncher.py'],
    console=[{'script': 'PveConsole.py'}],
    options={'py2exe': {
        'packages': ['dbm'],
        'includes': 'eve, utils, gui',
    }}
)
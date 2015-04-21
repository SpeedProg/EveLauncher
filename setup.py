from distutils.core import setup

setup(
    name='Python Launcher for EvE',
    description="Commandline Launcher for Eve",
    version="0.0.3",
    windows=['PveLauncher.py'],
    console=[{'script': 'PveConsole.py'}],
    options={'py2exe': {
        'packages': ['dbm'],
        'includes': 'eve, utils, gui',
    }}
)
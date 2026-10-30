"""Local runtime identity for installation and launch troubleshooting."""
from __future__ import annotations
from pathlib import Path
import sys
from . import __version__

BUILD = '6.0.1-delivery-fix'


def runtime_info(db_path=None):
    result = {'application':'ThreatWatch Global','version':__version__, 'build':BUILD,
              'source_dir':str(Path(__file__).resolve().parent.parent),
              'python_executable':sys.executable, 'risk_scale':'0–100'}
    if db_path is not None:
        result['database_path']=str(Path(db_path).expanduser().resolve())
    return result

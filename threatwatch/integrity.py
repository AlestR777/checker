"""Detect incomplete or mixed release extraction without inspecting user data.

The SHA-256 manifest detects packaging errors; it is not a publisher signature.
Mutable watchlists, the database, .env and bytecode are deliberately excluded.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from .config import ROOT

MANIFEST_NAME='RELEASE_MANIFEST.json'
RELEASE_FILES=frozenset({'START_THREATWATCH.bat','start_windows.bat','start_linux_mac.sh',
                       'install_windows.bat','collect_once_windows.bat','watch_6h_windows.bat','setup.sh'})


def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate manifest key')
        result[key]=value
    return result


def _allowed(name):
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_./-]+',name):return False
    parts=PurePosixPath(name)
    if parts.is_absolute() or parts.as_posix()!=name or any(p.startswith('.') for p in parts.parts):return False
    return name in RELEASE_FILES or (len(parts.parts)>=2 and parts.parts[0]=='threatwatch'
                                    and parts.suffix=='.py' and '__pycache__' not in parts.parts)


def verify_installation(root=ROOT):
    base=Path(root).expanduser().resolve()
    manifest=base/MANIFEST_NAME
    if not manifest.exists() and not manifest.is_symlink():
        return {'status':'unchecked','checked_files':0,'reason':'Developer checkout without release manifest'}
    try:
        if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size>1_000_000:
            raise ValueError('Manifest must be a regular local JSON file')
        payload=json.loads(manifest.read_text(encoding='utf-8'),object_pairs_hook=_unique_object)
        if not isinstance(payload,dict) or type(payload.get('schema_version')) is not int or payload['schema_version']!=1:
            raise ValueError('Unsupported release manifest schema')
        files=payload.get('files')
        if not isinstance(files,dict) or not files or len(files)>2000:raise ValueError('Invalid release file list')
        for name,digest in files.items():
            if not _allowed(name) or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):
                raise ValueError(f'Invalid manifest entry: {name}')
        package=base/'threatwatch'
        if package.is_symlink():raise ValueError('Package must not be a symbolic link')
        actual={name for name in RELEASE_FILES if (base/name).exists() or (base/name).is_symlink()}
        if package.is_dir():
            for path in package.rglob('*'):
                if path.is_symlink():raise ValueError('Package files and directories must not be symbolic links')
                if path.is_file() and path.suffix=='.py' and '__pycache__' not in path.parts:
                    actual.add(path.relative_to(base).as_posix())
        issues=[f'unlisted source file: {name}' for name in sorted(actual-files.keys())]
        for name,digest in files.items():
            path=base.joinpath(*PurePosixPath(name).parts)
            if path.is_symlink():raise ValueError(f'Symbolic link is not a release file: {name}')
            if not path.is_file():issues.append(f'missing file: {name}');continue
            if not path.resolve().is_relative_to(base):raise ValueError(f'Path escapes installation: {name}')
            if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:issues.append(f'changed file: {name}')
        if issues:raise ValueError('; '.join(issues[:12]))
        return {'status':'verified','checked_files':len(files),'manifest_path':str(manifest)}
    except (OSError,ValueError,TypeError,RecursionError) as exc:
        raise RuntimeError(f'Release integrity check failed: {exc}. Extract the complete ZIP into a new folder; keep your database separately.') from exc

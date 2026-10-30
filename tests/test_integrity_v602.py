import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from threatwatch.integrity import verify_installation,MANIFEST_NAME


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        (self.root/'threatwatch').mkdir()
        self.sources={'threatwatch/__init__.py':b'__version__="6.0.2"\n',
                      'threatwatch/dashboard.py':b'print("new")\n','START_THREATWATCH.bat':b'@echo off\r\n'}
        for name,data in self.sources.items():(self.root/name).write_bytes(data)

    def manifest(self,files=None):
        files=files or {name:hashlib.sha256(data).hexdigest() for name,data in self.sources.items()}
        (self.root/MANIFEST_NAME).write_text(json.dumps({'schema_version':1,'files':files}))

    def test_development_and_intact_release(self):
        self.assertEqual(verify_installation(self.root)['status'],'unchecked')
        self.manifest();result=verify_installation(self.root)
        self.assertEqual((result['status'],result['checked_files']),('verified',3))

    def test_old_same_size_module_is_detected(self):
        self.manifest();(self.root/'threatwatch/dashboard.py').write_bytes(b'print("old")\n')
        with self.assertRaisesRegex(RuntimeError,'changed file: threatwatch/dashboard.py'):verify_installation(self.root)

    def test_missing_and_extra_files_detected(self):
        self.manifest();(self.root/'threatwatch/dashboard.py').unlink()
        (self.root/'threatwatch/obsolete.py').write_text('old')
        with self.assertRaisesRegex(RuntimeError,'unlisted source file'):verify_installation(self.root)
        (self.root/'threatwatch/obsolete.py').unlink()
        with self.assertRaisesRegex(RuntimeError,'missing file'):verify_installation(self.root)

    def test_private_data_and_mutable_config_not_read(self):
        self.manifest()
        for name in ('.env','data/threatwatch.db','organizations.json','sources.json','threatwatch/__pycache__/x.pyc'):
            path=self.root/name;path.parent.mkdir(exist_ok=True,parents=True);path.write_text('private or user editable')
        original=Path.open
        def guarded(path,*a,**kw):
            if path.name in {'.env','threatwatch.db','organizations.json','sources.json','x.pyc'}:self.fail('Read private/user configuration')
            return original(path,*a,**kw)
        with patch.object(Path,'open',guarded):self.assertEqual(verify_installation(self.root)['status'],'verified')

    def test_invalid_paths_cannot_read_user_data(self):
        for name in ('../x.py','/tmp/x.py','C:/x.py','threatwatch/../x.py','.env','data/threatwatch.db','threatwatch//x.py','threatwatch\\x.py','threatwatch/__pycache__/x.py'):
            with self.subTest(path=name):
                self.manifest({name:'a'*64})
                with self.assertRaises(RuntimeError):verify_installation(self.root)

    def test_duplicate_keys_and_invalid_schema_rejected(self):
        for body in ('bad','{"schema_version":true,"files":{}}','{"schema_version":1,"files":{"a":"b","a":"c"}}'):
            (self.root/MANIFEST_NAME).write_text(body)
            with self.assertRaises(RuntimeError):verify_installation(self.root)

    def test_symbolic_source_rejected(self):
        self.manifest();source=self.root/'threatwatch/dashboard.py';source.unlink()
        source.symlink_to(self.root/'START_THREATWATCH.bat')
        with self.assertRaisesRegex(RuntimeError,'symbolic links'):verify_installation(self.root)


if __name__=='__main__':unittest.main()

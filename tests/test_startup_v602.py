"""Startup must reject another server instead of opening its old interface."""
import contextlib
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

from threatwatch import __version__
from threatwatch.dashboard import serve,make_handler,bind_dashboard
from threatwatch.startup import ExclusiveLocalHTTPServer,verify_server
from threatwatch.store import connect


class StartupTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.db=Path(temp.name)/'check.db'
        connect(self.db).close()

    def run_server(self,handler):
        server=ExclusiveLocalHTTPServer(('127.0.0.1',0),handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(3)))
        return server,f'http://127.0.0.1:{server.server_port}'

    def test_exclusive_option_precedes_bind_without_reuse(self):
        server=ExclusiveLocalHTTPServer.__new__(ExclusiveLocalHTTPServer)
        server.socket=Mock()
        trace=[]
        server.socket.setsockopt.side_effect=lambda *args:trace.append(('exclusive',args))
        with patch('threatwatch.startup.socket.SO_EXCLUSIVEADDRUSE',123456,create=True),patch('http.server.HTTPServer.server_bind',side_effect=lambda:trace.append(('bind',))) as binding:
            server.server_bind()
        self.assertEqual(trace,[('exclusive',(socket.SOL_SOCKET,123456,1)),('bind',)])
        self.assertFalse(server.allow_reuse_address)
        self.assertFalse(server.allow_reuse_port)

    def test_identity_is_verified_not_just_an_open_port(self):
        server,url=self.run_server(make_handler(self.db,instance_id='right-instance'))
        info=verify_server(url,instance_id='right-instance',version=__version__)
        self.assertEqual(info['instance_id'],'right-instance')
        with self.assertRaisesRegex(RuntimeError,'Another server'):
            verify_server(url,instance_id='old-instance',version=__version__)
        with self.assertRaisesRegex(RuntimeError,'Another server'):
            verify_server(url,instance_id='right-instance',version='5.2')

    def test_legacy_server_404_is_rejected(self):
        class Legacy(BaseHTTPRequestHandler):
            def do_GET(self):self.send_error(404)
            def log_message(self,*args):pass
        server,url=self.run_server(Legacy)
        with self.assertRaisesRegex(RuntimeError,'HTTP 404'):
            verify_server(url,instance_id='new-instance',version=__version__)

    def test_verification_failure_never_opens_browser_or_starts_collection(self):
        controller=Mock()
        with patch('threatwatch.startup.verify_server',side_effect=RuntimeError('Wrong instance')),patch('webbrowser.open') as browser,contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'Wrong instance'):
                serve(self.db,port=0,controller=controller,open_browser=True)
        browser.assert_not_called()
        controller.run_now.assert_not_called()
        controller.shutdown.assert_called_once()

    def test_invalid_remote_targets_rejected_before_request(self):
        for url in ('https://example.com','http://127.0.0.1@evil.test','http://user@localhost','http://127.0.0.1/x','http://127.0.0.1/?x=1'):
            with self.assertRaises(ValueError):verify_server(url,instance_id='a',version='b')

    def test_windows_access_conflict_tries_different_port(self):
        conflict=OSError('Exclusive bind conflict');conflict.winerror=10013
        server=Mock()
        with patch('threatwatch.startup.ExclusiveLocalHTTPServer',side_effect=[conflict,server]) as factory,contextlib.redirect_stdout(io.StringIO()):
            self.assertIs(bind_dashboard(self.db,None,'127.0.0.1',8765,desktop=True),server)
        self.assertEqual([c.args[0][1] for c in factory.call_args_list],[8765,8766])


if __name__=='__main__':unittest.main()

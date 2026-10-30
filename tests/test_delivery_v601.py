"""Verify which installed copy opens, and keep new exports on the v6 scale."""
import contextlib
import io
import json
import http.client
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from http.server import ThreadingHTTPServer

from threatwatch import __version__
from threatwatch.cli import build_parser, print_summary, export
from threatwatch.dashboard import make_handler, bind_dashboard, serve
from threatwatch.runtime import runtime_info
from threatwatch.store import connect, upsert_organizations
from threatwatch.config import Organization
from threatwatch.control import CollectionController
from threatwatch.web_controls import control_page


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.db=Path(folder.name)/'data.db'
        self.con=connect(self.db);self.addCleanup(self.con.close)
        upsert_organizations(self.con,[Organization('one','One Example','technology','US',('One Example',))])

    def test_runtime_identity_is_current_installation(self):
        info=runtime_info(self.db)
        self.assertEqual(info['version'],__version__)
        self.assertEqual(Path(info['database_path']),self.db.resolve())
        self.assertTrue((Path(info['source_dir'])/'threatwatch'/'runtime.py').is_file())
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as caught:
            build_parser().parse_args(['--version'])
        self.assertEqual(caught.exception.code,0)
        self.assertIn(__version__,out.getvalue())

    def test_desktop_uses_new_port_while_old_copy_remains_bound(self):
        old=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.db))
        self.addCleanup(old.server_close)
        port=old.server_address[1]
        if port>65525:self.skipTest('OS selected port outside retry range')
        with contextlib.redirect_stdout(io.StringIO()):
            fresh=bind_dashboard(self.db,None,'127.0.0.1',port,desktop=True)
        self.addCleanup(fresh.server_close)
        self.assertNotEqual(fresh.server_address[1],port)
        self.assertEqual(old.server_address[1],port)
        with self.assertRaises(OSError):bind_dashboard(self.db,None,'127.0.0.1',port)

    def test_desktop_opens_overview_on_actual_bound_port(self):
        server=Mock();server.server_address=('127.0.0.1',8976)
        controller=Mock()
        def timer(_delay,callback):
            timer=Mock();timer.start.side_effect=callback;return timer
        with patch('threatwatch.dashboard.bind_dashboard',return_value=server),patch('threatwatch.dashboard.threading.Timer',side_effect=timer),patch('webbrowser.open') as browser,contextlib.redirect_stdout(io.StringIO()):
            serve(self.db,controller=controller,open_browser=True)
        browser.assert_called_once_with('http://127.0.0.1:8976/')
        controller.shutdown.assert_called_once()
        server.server_close.assert_called_once()

    def test_about_and_runtime_api_identify_database(self):
        controller=CollectionController(self.db)
        server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.db,controller))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            for path in ('/about','/api/runtime'):
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                conn.request('GET',path);response=conn.getresponse();body=response.read().decode();conn.close()
                self.assertEqual(response.status,200)
                self.assertEqual(response.getheader('Cache-Control'),'no-store')
                self.assertIn(__version__,body)
                if path.endswith('runtime'):self.assertEqual(json.loads(body)['database_path'],str(self.db))
            for busy in (True,False):
                controller._busy=busy
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                conn.request('GET','/');response=conn.getresponse();body=response.read().decode();conn.close()
                self.assertEqual(response.getheader('Refresh'),'8' if busy else None)
                self.assertEqual('role="status"' in body,busy)
        finally:server.shutdown();server.server_close();thread.join(5)

    def test_visible_export_and_terminal_summary_use_new_scale(self):
        page=control_page(CollectionController(self.db),'test').decode()
        self.assertIn('href="/export/risks"',page)
        self.assertNotIn('href="/export/scores"',page)
        with contextlib.redirect_stdout(io.StringIO()) as out:print_summary(self.con)
        self.assertIn('0–100',out.getvalue())
        path=self.db.parent/'risks.json'
        self.assertEqual(export(self.con,path,'risks'),1)
        record=json.loads(path.read_text())[0]
        self.assertEqual(record['score_max'],100)
        self.assertIsNone(record['score'])


if __name__=='__main__':unittest.main()

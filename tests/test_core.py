import json,unittest,tempfile
from pathlib import Path
from app.detector import detect
from app.uri import vless_uri
from app.models import NormalizedConfig
from app.validators import validate_uri,validate_xray
from app.xray import xray_config

class CoreTests(unittest.TestCase):
    def test_vless_roundtrip_shape(self):
        p=NormalizedConfig(protocol='vless',address='example.com',port=443,uuid='00000000-0000-0000-0000-000000000000',remark='نام فارسی',network='ws',security='tls',path='/x',host='cdn.example',sni='cdn.example',alpn=['h2','http/1.1'],fingerprint='chrome')
        u=vless_uri(p); self.assertTrue(u.startswith('vless://')); self.assertTrue(validate_uri(u)[0]); self.assertTrue(validate_xray(xray_config(p))[0])
    def test_npvt_signature(self): self.assertEqual(detect(b'NPVT1abc,xyz','x').key,'npvt')
    def test_dark_malformed(self): self.assertIsNone(detect(b'not a config','x.bin'))
    def test_json_unicode(self):
        s=json.dumps({'remarks':'نام فارسی'},ensure_ascii=False); self.assertIn('نام فارسی',s)
    def test_ssc_shape_detection(self): self.assertIsNotNone(detect(b'aa'*20,'x.bin'))

if __name__=='__main__':unittest.main()

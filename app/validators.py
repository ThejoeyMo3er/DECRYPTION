from __future__ import annotations
import json
from urllib.parse import urlsplit

def validate_uri(uri):
    try:
        u=urlsplit(uri)
        if u.scheme not in {'vless','vmess'} or not u.netloc:return False,'invalid URI structure'
        if u.scheme=='vless' and not u.username:return False,'VLESS UUID missing'
        return True,''
    except Exception as e:return False,str(e)

def validate_xray(cfg):
    if not isinstance(cfg,dict) or not isinstance(cfg.get('outbounds'),list) or not cfg['outbounds']:return False,'missing outbounds'
    for o in cfg['outbounds']:
        if o.get('protocol') not in {'vless','vmess'}:return False,'unsupported outbound protocol'
        try:v=o['settings']['vnext'][0]; int(v['port']); users=v['users'];
        except Exception:return False,'invalid vnext structure'
        if not v.get('address') or not users:return False,'address/users missing'
        if not users[0].get('id'):return False,'user id missing'
    try:json.dumps(cfg,ensure_ascii=False,allow_nan=False)
    except Exception as e:return False,f'not JSON serializable: {e}'
    return True,''

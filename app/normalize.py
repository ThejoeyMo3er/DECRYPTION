from __future__ import annotations
import json
from typing import Any
from .models import NormalizedConfig

def _first(d,*keys):
    if not isinstance(d,dict):return None
    for k in keys:
        if k in d and d[k] not in (None,''):return d[k]
    return None

def _int(v):
    try:return int(v)
    except:return None

def _alpn(v):
    if isinstance(v,list):return [str(x) for x in v if str(x)]
    if isinstance(v,str):return [x.strip() for x in v.split(',') if x.strip()]
    return []

def iter_profiles(value):
    if isinstance(value,str):
        s=value.strip()
        if s.startswith(('{','[')):
            try:yield from iter_profiles(json.loads(s))
            except:pass
        return
    if isinstance(value,list):
        for x in value:yield from iter_profiles(x)
        return
    if not isinstance(value,dict):return
    proto=_first(value,'protocol','Protocol','v2rProtocol')
    addr=_first(value,'server','address','Hostname','hostname','v2rHost','add')
    port=_int(_first(value,'serverPort','port','Port','v2rPort'))
    uid=_first(value,'uuid','UUID','UserID','userId','v2rUserId','id')
    if proto and addr and port and str(proto).lower() in {'vless','vmess'} and uid:
        yield NormalizedConfig(protocol=str(proto).lower(),address=str(addr),port=port,uuid=str(uid),remark=_first(value,'remarks','remark','Remark','name','title'),network=_first(value,'network','net','TransferProtocol','v2rNetwork'),security=_first(value,'security','tls','TLSType','v2rTleSecurityType'),path=_first(value,'path','Path','v2rHttpPath'),host=_first(value,'host','Host','v2rHostHeader','hostHeader'),sni=_first(value,'sni','SNI','serverName','v2rTlsSni'),alpn=_alpn(_first(value,'alpn','Alpn','v2rTleAlpn')),fingerprint=_first(value,'fingerprint','FingerPrint','fp','v2rTleFingerprintType'),flow=_first(value,'flow','Flow'),extra=value)
    child=value.get('v2rayProfile')
    if isinstance(child,dict):yield from iter_profiles(child)
    for k,v in value.items():
        if isinstance(v,(dict,list)) and k!='v2rayProfile':yield from iter_profiles(v)

def normalize_all(parsed_values):
    out=[]; seen=set()
    for root in parsed_values:
        for p in iter_profiles(root):
            key=(p.protocol,p.address,p.port,p.uuid,p.password,p.network,p.security,p.path,p.host,p.sni,tuple(p.alpn),p.fingerprint,p.flow,json.dumps(p.extra,ensure_ascii=False,sort_keys=True,default=str))
            if key not in seen:seen.add(key);out.append(p)
    return out

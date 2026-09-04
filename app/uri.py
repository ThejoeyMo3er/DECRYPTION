from __future__ import annotations
import base64,json
from urllib.parse import quote,urlencode
from .models import NormalizedConfig

def vmess_uri(p:NormalizedConfig)->str|None:
    if p.protocol!='vmess' or not p.uuid:return None
    obj={'v':'2','ps':p.remark or '', 'add':p.address,'port':str(p.port),'id':p.uuid,'aid':'0','scy':'auto'}
    if p.network:obj['net']=p.network
    if p.network=='ws':
        if p.path is not None:obj['path']=p.path
        if p.host is not None:obj['host']=p.host
    elif p.network in {'httpupgrade','http-upgrade'}:
        obj['net']='httpupgrade';
        if p.path is not None:obj['path']=p.path
        if p.host is not None:obj['host']=p.host
    elif p.network=='xhttp':
        obj['net']='xhttp'
        if p.path is not None:obj['path']=p.path
        if p.host is not None:obj['host']=p.host
    if p.security in {'tls','ssl'}:
        obj['tls']='tls'
        if p.sni is not None:obj['sni']=p.sni
        if p.alpn:obj['alpn']=','.join(p.alpn)
        if p.fingerprint is not None:obj['fp']=p.fingerprint
    return 'vmess://'+base64.urlsafe_b64encode(json.dumps(obj,ensure_ascii=False,separators=(',',':')).encode()).decode().rstrip('=')

def vless_uri(p:NormalizedConfig)->str|None:
    if p.protocol!='vless' or not p.uuid:return None
    q=[]
    if p.network:q.append(('type',p.network))
    if p.security:q.append(('security','tls' if p.security=='ssl' else p.security))
    if p.network=='ws':
        if p.host is not None:q.append(('host',p.host))
        if p.path is not None:q.append(('path',p.path))
    elif p.network in {'httpupgrade','http-upgrade','xhttp'}:
        if p.host is not None:q.append(('host',p.host))
        if p.path is not None:q.append(('path',p.path))
    if p.sni is not None:q.append(('sni',p.sni))
    if p.alpn:q.append(('alpn',','.join(p.alpn)))
    if p.fingerprint is not None:q.append(('fp',p.fingerprint))
    if p.flow is not None:q.append(('flow',p.flow))
    uri=f'vless://{quote(p.uuid,safe="")}@{p.address}:{p.port}'
    if q:uri+='?'+urlencode(q)
    if p.remark:uri+='#'+quote(str(p.remark),safe='')
    return uri

def build_uri(p):return vmess_uri(p) if p.protocol=='vmess' else vless_uri(p)

from __future__ import annotations
from typing import Any
from .models import NormalizedConfig

def xray_config(p:NormalizedConfig)->dict[str,Any]|None:
    if p.protocol not in {'vless','vmess'} or not p.uuid:return None
    user={'id':p.uuid}
    if p.protocol=='vless':
        user['encryption']='none'
        if p.flow:user['flow']=p.flow
    else:
        user['alterId']=0; user['security']='auto'
    out={'protocol':p.protocol,'settings':{'vnext':[{'address':p.address,'port':p.port,'users':[user]}]}}
    stream={}
    if p.network:stream['network']=p.network
    sec='tls' if p.security=='ssl' else p.security
    if sec:stream['security']=sec
    net=(p.network or '').lower()
    if net=='ws':
        s={}
        if p.path is not None:s['path']=p.path
        if p.host is not None:s['headers']={'Host':p.host}
        if s:stream['wsSettings']=s
    elif net in {'httpupgrade','http-upgrade'}:
        s={}
        if p.path is not None:s['path']=p.path
        if p.host is not None:s['host']=p.host
        if s:stream['httpupgradeSettings']=s
    elif net=='xhttp':
        s={}
        if p.path is not None:s['path']=p.path
        if p.host is not None:s['host']=p.host
        if s:stream['xhttpSettings']=s
    elif net=='grpc' and p.extra.get('serviceName') is not None:stream['grpcSettings']={'serviceName':str(p.extra['serviceName'])}
    elif net=='tcp' and p.extra.get('headerType') is not None:stream['tcpSettings']={'header':{'type':str(p.extra['headerType'])}}
    if sec=='tls':
        t={}
        if p.sni is not None:t['serverName']=p.sni
        if p.alpn:t['alpn']=p.alpn
        if p.fingerprint is not None:t['fingerprint']=p.fingerprint
        if 'allowInsecure' in p.extra:t['allowInsecure']=bool(p.extra['allowInsecure'])
        if t:stream['tlsSettings']=t
    elif sec=='reality':
        r={}
        for k in ('fingerprint','serverName','publicKey','shortId'):
            v={'fingerprint':p.fingerprint,'serverName':p.sni,'publicKey':p.extra.get('publicKey'),'shortId':p.extra.get('shortId')}[k]
            if v not in (None,''):r[k]=v
        if r:stream['realitySettings']=r
    if stream:out['streamSettings']=stream
    return {'remarks':p.remark,'outbounds':[out]} if p.remark else {'outbounds':[out]}

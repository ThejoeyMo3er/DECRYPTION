from __future__ import annotations
import asyncio, base64, contextlib, dataclasses, gzip, hashlib, html, io, json, logging, os, pickle, re, secrets, shutil, sqlite3, struct, tempfile, time, uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit
from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Util.Padding import unpad
from argon2.low_level import hash_secret_raw, Type
import msgpack
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import Forbidden, TelegramError
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

# ===== database.py =====
import sqlite3, time
from pathlib import Path

DEFAULTS = {
    "daily_limit":"5", "maintenance":"0", "max_file_size":str(50*1024*1024),
    "process_timeout":"90", "max_configs":"100", "concurrency":"4",
    "duplicate_filter":"1", "validation":"1", "logging_level":"INFO",
    "output_uri":"1", "output_json":"1", "output_original":"1",
    "captcha_interval":"10", "captcha_max_attempts":"5",
    "admin_ids":"5728292317",
}
FORMATS = {
    "ehi":"HTTP Injector", "npvt":"NPV Tunnel", "hc":"HTTP Custom",
    "dark":"Dark Tunnel", "ssc":"SSC Custom",
}
FEATURES = ("decrypt","uri","json","original")

class Database:
    def __init__(self, path: Path): self.path=Path(path); self.conn=None
    def open(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.conn=sqlite3.connect(self.path,check_same_thread=False,timeout=30)
        self.conn.row_factory=sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL"); self.conn.execute("PRAGMA synchronous=NORMAL"); self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript('''
        CREATE TABLE IF NOT EXISTS users(user_id INTEGER PRIMARY KEY,username TEXT DEFAULT '',first_name TEXT DEFAULT '',last_name TEXT DEFAULT '',is_blocked INTEGER DEFAULT 0,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,total_files INTEGER DEFAULT 0,successful_files INTEGER DEFAULT 0,failed_files INTEGER DEFAULT 0,total_links INTEGER DEFAULT 0,captcha_verified INTEGER DEFAULT 0,captcha_ops INTEGER DEFAULT 0,captcha_failures INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS force_join_channels(id INTEGER PRIMARY KEY AUTOINCREMENT,chat_id TEXT NOT NULL UNIQUE,title TEXT NOT NULL DEFAULT '',username TEXT DEFAULT '',invite_url TEXT DEFAULT '',active INTEGER DEFAULT 1,created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS daily_usage(user_id INTEGER NOT NULL,day TEXT NOT NULL,count INTEGER DEFAULT 0,PRIMARY KEY(user_id,day),FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS sponsors(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,url TEXT NOT NULL,button_text TEXT NOT NULL,style TEXT NOT NULL DEFAULT 'primary',active INTEGER DEFAULT 1,sort_order INTEGER DEFAULT 0,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,filename TEXT NOT NULL,extension TEXT NOT NULL,status TEXT NOT NULL,links_count INTEGER DEFAULT 0,error TEXT DEFAULT '',created_at INTEGER NOT NULL,finished_at INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen); CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);
        ''')
        for col, ddl in (("captcha_verified","ALTER TABLE users ADD COLUMN captcha_verified INTEGER DEFAULT 0"),("captcha_ops","ALTER TABLE users ADD COLUMN captcha_ops INTEGER DEFAULT 0"),("captcha_failures","ALTER TABLE users ADD COLUMN captcha_failures INTEGER DEFAULT 0")):
            try:self.conn.execute(ddl)
            except sqlite3.OperationalError:pass
        for k,v in DEFAULTS.items(): self.conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",(k,v))
        legacy = {'ehi':'app_ehi','npvt':'app_npvt','hc':None,'dark':'app_dark','ssc':None}
        for fmt in FORMATS:
            legacy_key=legacy.get(fmt)
            legacy_val=self.get(legacy_key,'1') if legacy_key else '1'
            self.conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",(f"format_{fmt}",legacy_val))
            for f in FEATURES:
                old={'uri':'links','json':'json','original':'original'}.get(f)
                old_key=f"feature_{fmt}__{old}" if old else None
                val=self.get(old_key,'1') if old_key else '1'
                self.conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",(f"format_{fmt}_{f}",val))

            for f in FEATURES: self.conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",(f"format_{fmt}_{f}","1"))
        self.conn.commit()
    def get(self,k,d=""): return (self.conn.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone() or {"value":d})["value"]
    def set(self,k,v): self.conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,str(v))); self.conn.commit()
    def fmt_enabled(self,fmt): return self.get(f"format_{fmt}","0")=="1"
    def feature_enabled(self,fmt,f):
        if f=="decrypt": return self.fmt_enabled(fmt) and self.get(f"format_{fmt}_decrypt","0")=="1"
        if f=="uri": return self.fmt_enabled(fmt) and self.get("output_uri","0")=="1" and self.get(f"format_{fmt}_uri","0")=="1"
        if f=="json": return self.fmt_enabled(fmt) and self.get("output_json","0")=="1" and self.get(f"format_{fmt}_json","0")=="1"
        if f=="original": return self.fmt_enabled(fmt) and self.get("output_original","0")=="1" and self.get(f"format_{fmt}_original","0")=="1"
        return False
    def upsert_user(self,u):
        now=int(time.time()); self.conn.execute('''INSERT INTO users(user_id,username,first_name,last_name,first_seen,last_seen) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,first_name=excluded.first_name,last_name=excluded.last_name,last_seen=excluded.last_seen''',(u.id,u.username or '',u.first_name or '',u.last_name or '',now,now)); self.conn.commit()
    def user(self,uid): return self.conn.execute("SELECT * FROM users WHERE user_id=?",(uid,)).fetchone()
    def daily_usage(self,uid):
        day=time.strftime('%Y-%m-%d',time.gmtime()); r=self.conn.execute("SELECT count FROM daily_usage WHERE user_id=? AND day=?",(uid,day)).fetchone(); return int(r[0]) if r else 0
    def consume(self,uid):
        limit=int(self.get('daily_limit','5')); day=time.strftime('%Y-%m-%d',time.gmtime()); cur=self.daily_usage(uid)
        if limit and cur>=limit:return False
        self.conn.execute("INSERT INTO daily_usage(user_id,day,count) VALUES(?,?,1) ON CONFLICT(user_id,day) DO UPDATE SET count=count+1",(uid,day)); self.conn.execute("UPDATE users SET total_files=total_files+1 WHERE user_id=?",(uid,)); self.conn.commit(); return True
    def refund(self,uid):
        day=time.strftime('%Y-%m-%d',time.gmtime()); self.conn.execute("UPDATE daily_usage SET count=CASE WHEN count>0 THEN count-1 ELSE 0 END WHERE user_id=? AND day=?",(uid,day)); self.conn.execute("UPDATE users SET total_files=CASE WHEN total_files>0 THEN total_files-1 ELSE 0 END WHERE user_id=?",(uid,)); self.conn.commit()
    def success(self,uid,n): self.conn.execute("UPDATE users SET successful_files=successful_files+1,total_links=total_links+? WHERE user_id=?",(n,uid)); self.conn.commit()
    def failure(self,uid): self.conn.execute("UPDATE users SET failed_files=failed_files+1 WHERE user_id=?",(uid,)); self.conn.commit()
    def job(self,jid,uid,fn,ext): self.conn.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",(jid,uid,fn,ext,'processing',0,'',int(time.time()),0)); self.conn.commit()
    def finish(self,jid,status,n=0,error=''): self.conn.execute("UPDATE jobs SET status=?,links_count=?,error=?,finished_at=? WHERE id=?",(status,n,str(error)[:2000],int(time.time()),jid)); self.conn.commit()
    def stats(self):
        u=self.conn.execute("SELECT COUNT(*) n,COALESCE(SUM(total_files),0) f,COALESCE(SUM(successful_files),0) s,COALESCE(SUM(failed_files),0) e,COALESCE(SUM(total_links),0) l FROM users").fetchone(); return dict(users=u['n'],files=u['f'],success=u['s'],failed=u['e'],uris=u['l'],jobs24=self.conn.execute("SELECT COUNT(*) FROM jobs WHERE created_at>=?",(int(time.time())-86400,)).fetchone()[0])
    def close(self):
        if self.conn:self.conn.close()


# ===== models.py =====
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ParsedConfig:
    format_name: str
    data: Any
    source_name: str
    decrypted: bool = True
    warnings: list[str] = field(default_factory=list)

@dataclass
class NormalizedConfig:
    protocol: str
    address: str
    port: int
    uuid: str | None = None
    password: str | None = None
    remark: str | None = None
    network: str | None = None
    security: str | None = None
    path: str | None = None
    host: str | None = None
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    flow: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


# ===== detector.py =====
from dataclasses import dataclass
import json,re

@dataclass(frozen=True)
class FormatMatch:
    key:str; confidence:str; reason:str

def detect(data:bytes, filename:str='') -> FormatMatch|None:
    name=filename.lower()
    if data.startswith((b'NPVT1',b'NPVTSUB1')):
        return FormatMatch('npvt','signature','NPVT1/NPVTSUB1 header')
    if name.endswith('.ehi') or _looks_ehi(data): return FormatMatch('ehi','strong','EHI binary container')
    if name.endswith('.hc') or _looks_hc(data): return FormatMatch('hc','strong','HC XOR/hex envelope')
    if name.endswith('.dark') or _looks_dark(data): return FormatMatch('dark','strong','Dark Tunnel outer JSON/base64 envelope')
    if _looks_ssc(data,name): return FormatMatch('ssc','strong','SSC hex/ssc envelope')
    return None

def _looks_ehi(b): return len(b)>32 and b[:2] != b'\x1f\x8b' and any(x in b[:128] for x in (b'EHI',b'HTTP'))
def _looks_hc(b):
    try:return len(b)>20 and all(c in b'0123456789abcdefABCDEF\r\n\t ' for c in b[:200])
    except:return False
def _looks_dark(b):
    try:
        s=b.decode('utf-8-sig').strip(); raw=s.split('://',1)[-1]; o=json.loads(__import__('base64').b64decode(raw+'='*((4-len(raw)%4)%4))); return isinstance(o,dict) and 'encryptedLockedConfig' in o
    except:return False
def _looks_ssc(b,name):
    try:
        s=b.decode('utf-8-sig').strip(); s=s[6:] if s.startswith('ssc://') else s; s=re.sub(r'\s+','',s); return len(s)>=32 and len(s)%2==0 and bool(re.fullmatch(r'[0-9a-fA-F]+',s))
    except:return False


# ===== normalize.py =====
import json
from typing import Any

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


# ===== uri.py =====
import base64,json
from urllib.parse import quote,urlencode

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


# ===== validators.py =====
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


# ===== xray.py =====
from typing import Any

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


# ===== ehi.py =====

L1_KEY=bytes.fromhex('7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c'); L2_KEY=bytes.fromhex('b2bc617c32d8b9eb1943a5ffa8051eea'); EOO=b'null=V5kU5+FFrY\x00'
BYPASS=(bytes.fromhex('221d572349555f1d112133236b1f4a3f'),bytes.fromhex('5543494c53443e3f4a6a4539384e776a'),bytes.fromhex('374c2541575e4d531a3c327b75431e5f'))
STANDARD=(bytes.fromhex('2c5d1147bbad422b3b334d4d235f1a53'),bytes.fromhex('522b01433a5e8b2fc7549e1ad368e541'),bytes.fromhex('337a1035aaedf3458ca167e92d74b839'))
CUSTOM='RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs'; STD='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
TRANS=str.maketrans(CUSTOM,STD)

def b64(s):
 s=s.replace('?',''); s+='='*((4-len(s)%4)%4); return base64.b64decode(s.translate(TRANS))
def xor_layer(s,key):
 if not s:return s
 try:
  raw=bytes.fromhex(b64(s[::-1]).decode('ascii')); out=bytes(b^ord(key[i%len(key)]) for i,b in enumerate(raw) if (b^ord(key[i%len(key)]))!=0); return out.decode('utf-8')
 except:return None
def xxtea(data,key):
 if len(data)%4:data+=b'\0'*(4-len(data)%4)
 k=struct.unpack('<4I',key.ljust(16,b'\0')[:16]); n=len(data)//4; v=list(struct.unpack(f'<{n}I',data)); delta=0x9e3779b9; sm=((6+52//n)*delta)&0xffffffff; y=v[0]
 while sm:
  e=(sm>>2)&3
  for p in range(n-1,0,-1):
   z=v[p-1]; mx=(((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((sm^y)+(k[(p&3)^e]^z)); y=v[p]=(v[p]-mx)&0xffffffff
  z=v[n-1]; mx=(((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((sm^y)+(k[e]^z)); y=v[0]=(v[0]-mx)&0xffffffff; sm=(sm-delta)&0xffffffff
 dec=struct.pack(f'<{n}I',*v); ln=v[-1]; return dec[:ln] if 0<ln<=n*4 else dec.rstrip(b'\0')
def decode_message(s):
 try:
  raw=base64.b64decode(s+'='*((4-len(s)%4)%4)); u16=raw.decode('utf-8',errors='replace').encode('utf-16-be'); chars=struct.unpack(f'>{len(u16)//2}H',u16); keys=[ord(c) for c in 'EHIMSG']; x=bytes().join(struct.pack('>H',c^keys[i%6]) for i,c in enumerate(chars)); return x.decode('utf-16-be').encode('utf-16').decode('utf-16')
 except:return s
def inner(d,salt):
 out={}
 for k,v in d.items(): out[k]=decode_message(v) if k=='configMessage' and isinstance(v,str) else (xor_layer(v,salt) if isinstance(v,str) and v else v)
 return out
def master(c):
 s=''.join(str(c.get(k,'')) for k in ('configAesKey','configIdentifier','configSalt','configTimestamp','configExpiryTimestamp','lockModes','lockModesHash','configHwid','configLockMobileOperatorId') if c.get(k,'')); return hashlib.sha256(s.encode()).digest()
def parse_ehi(file_bytes):
 f=io.BytesIO(file_bytes)
 def rutf():
  z=f.read(2)
  if len(z)<2: raise ValueError('truncated UTF length')
  n=struct.unpack('>H',z)[0]; d=f.read(n); 
  if len(d)!=n: raise ValueError('truncated UTF payload')
  return d.decode('utf-8')
 rutf(); f.read(8); rutf(); f.read(8); z=f.read(4)
 if len(z)<4: raise ValueError('missing payload length')
 n=struct.unpack('>I',z)[0]; f.read(8); payload=f.read(n)
 if len(payload)!=n: raise ValueError('truncated encrypted payload')
 config=None; iv=None
 for candidate in BYPASS+STANDARD:
  try:
   l1=unpad(AES.new(L1_KEY,AES.MODE_CBC,candidate).decrypt(payload),16).decode('utf-8'); parts=l1.split(':')
   if len(parts)<3: continue
   c2=unpad(AES.new(L2_KEY,AES.MODE_CBC,base64.b64decode(parts[0])).decrypt(base64.b64decode(parts[2])),16); raw=xxtea(c2,EOO); st=raw.find(b'{')
   if st>=0: config=json.loads(raw[st:].decode('utf-8')); iv=candidate; break
  except Exception: continue
 if not isinstance(config,dict): raise ValueError('EHI cryptographic validation failed')
 salt=config.get('configSalt','EVZJNI')
 if iv in BYPASS: final=config
 else:
  x=xor_layer(config.get('configData',''),salt)
  if not x: raise ValueError('EHI configData XOR layer failed')
  raw=base64.b64decode(x)
  if len(raw)<=50: raise ValueError('EHI authenticated payload is truncated')
  try:
   key=hash_secret_raw(secret=master(config),salt=raw[10:26],time_cost=int.from_bytes(raw[1:5],'little'),memory_cost=int.from_bytes(raw[5:9],'little'),parallelism=raw[9],hash_len=32,type=Type.ID)
   c=ChaCha20_Poly1305.new(key=key,nonce=raw[26:50]); c.update(raw[:26]); final=json.loads(c.decrypt_and_verify(raw[50:-16],raw[-16:]).decode('utf-8'))
  except Exception as e: raise ValueError(f'EHI authenticated decryption failed: {e}')
 final=inner(final,salt)
 for k in ('v2rRawJson','overwriteServerData'):
  v=final.get(k)
  if isinstance(v,str):
   try:
    a=v.find('{'); b=v.rfind('}');
    if a>=0 and b>a: final[k]=json.loads(v[a:b+1])
   except Exception: pass
 return final


# ===== hc.py =====
CHACHA=[bytes.fromhex(x) for x in ['2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d','3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372','cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3','4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193','f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63','81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c','45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944','3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea']]
RST=[b'JN1k3YHc2.6_v235',b'JN1k3YHc_2.7_v71',b'JN1k3YHc2.7.ps69',b'JN1k3YHc2.7.6950',b'Jn1K3yHc2.8.ps08',b'Jn1K3yHc2.9.ps6c',b'Zk:L7>WKaiK*s9>D',b'!<f!&WIlM**R.B0X',b'b4a5opinx2uloec6']
OLD=bytes([0xd5,0xd4,0xd3,0xd2,0xd1,0xd0,0xcf,0xce,0xcd,0xcc,0xbd,0xbc,0xbb,0xba,0xb9,0xb8,0xb7,0xb6,0xb5,0xb4]); NEW=bytes([8,9,10,11,12,13,14,15,17,17,5,4,3,2,1,0,255,254,253,252]); NONCE=b'\xdb'*8; RX=bytes(range(2,22))
MAP={0:'payload',1:'proxy',2:'lockAllConfig',3:'blockedByRoot',4:'expiryTime',5:'noteEnabled',6:'notes',7:'sshField',8:'mobileDataAndLockProvider',9:'unlockUserAndPass',10:'ovpnConfig',11:'ovpnUserAndPass',12:'sni',13:'unlockUserAndPass2',14:'unknown14',15:'blockedByHwid',16:'cloudconfig',17:'psiphon',18:'name',19:'blockArea',20:'connectionMode',21:'blockedByPassword',22:'unknown22',23:'extraSniffer',24:'psiphon2',25:'v2rayEnabled',26:'v2rayConfig',27:'version',28:'slowdnsEnabled',29:'slowdnsServer',30:'slowdnsPublickey',31:'dnsResolver'}
def cleanhex(s):
 c=re.sub('[^0-9a-fA-F]','',str(s or '')); return ('0'+c) if len(c)%2 else c
def abc(s,key,nonce=NONCE):
 try:
  d=bytes.fromhex(cleanhex(s));
  if len(d)<=16:return ''
  c=ChaCha20.new(key=key,nonce=nonce); c.seek(64); return c.decrypt(d[:-16]).decode('utf-8',errors='ignore')
 except:return ''
def jkl(s,new=False):
 if not s:return s
 k=NEW if new else OLD
 try:
  d=bytearray(base64.b64decode(s+'='*((4-len(s)%4)%4),validate=True))
  for i,v in enumerate(d): d[i]=(((v^255)&0xca)|(v&0x35))^(((k[i%20]^255)&0xca)|(k[i%20]&0x35))
  return base64.b64decode(d.decode(),validate=True).decode()
 except:return s
def field(token,dyn):
 if not token or token in {'true','false','lifeTime','[splitPsiphon][splitPsiphon]'} or token.startswith('<'):return token
 cands=[]; h=cleanhex(token)
 if len(h)>=32 and re.fullmatch('[0-9a-fA-F]+',h):
  try:cands.append(bytes.fromhex(h))
  except:pass
 if len(token)>16:
  cands += [token.encode('latin-1',errors='ignore'),token.encode('utf-8')]
 for raw in cands:
  if len(raw)<=16:continue
  for key in CHACHA:
   try:
    c=ChaCha20.new(key=key,nonce=dyn); c.seek(64); s=c.decrypt(raw[:-16]).decode('utf-8',errors='ignore')
    for n in (True,False):
     z=jkl(s,n)
     if z!=s and sum(x.isprintable() or x in '\r\n\t' for x in z)/max(1,len(z))>.8:return z
    if sum(x.isprintable() or x in '\r\n\t' for x in s)/max(1,len(s))>.9:return s
   except:pass
 for n in (True,False):
  z=jkl(token,n)
  if z!=token:return z
 return token
def parse_hc(b):
 key=bytes.fromhex('e382e4b8adc386f09f9293'); raw=bytes(x^key[i%len(key)] for i,x in enumerate(b.decode('utf-8',errors='ignore').encode('latin-1',errors='ignore'))).decode('utf-8')
 outer=abc(raw,CHACHA[5]);
 if not outer or not outer.startswith('{'):raise ValueError('HC outer ChaCha20 validation failed')
 obj=json.loads(outer); cfg=obj.get('cfg',{}); new=isinstance(cfg,dict) and 'content' in cfg; meta={}; prot={}
 if new:
  for k,n in {'b':'hwid','f':'area'}.items():
   v=str(obj.get(k) or cfg.get(k) or '');
   if v:meta[n]=prot[n]=v
  target,split=cfg.get('content'),'[splitConfig]'
 else:
  a=obj.get('a') if isinstance(obj.get('a'),dict) else {}
  for k,n in {'bb':'hwid','e':'password','fe':'area','ed':'provider'}.items():
   v=obj.get(k) if k=='e' else a.get(k); z=abc(str(v),CHACHA[7]) if v else ''
   if z:meta[n]=prot[n]=z
  target,split=obj.get('xy') or a.get('xy'),obj.get('uv') or a.get('uv')
 if not target or not split:raise ValueError('HC wrapper has no configuration payload')
 h,p,pr,a=meta.get('hwid'),meta.get('password'),meta.get('provider'),meta.get('area'); dh=(h.encode().hex()*2) if h and not any((p,pr,a)) else ''.join(x.encode().hex() for x in (p,h,pr,a) if x); dyn=bytearray(NONCE)
 if dh:
  for i,x in enumerate(bytes.fromhex(dh)[:8]):dyn[i]=x
 dec=None
 if new:
  try:
   bs=bytes(x^RX[i%20] for i,x in enumerate(str(target).encode())); ct=base64.b64decode(bs)
   for k in RST:
    try:
     s=unpad(AES.new(k,AES.MODE_ECB).decrypt(ct),16).decode()
     if split in s: dec=s;break
    except:pass
  except Exception: pass
  if dec is None:
   for k in CHACHA:
    z=abc(str(target),k)
    if split in z:dec=z;break
 else:dec=abc(str(target),CHACHA[1])
 if not dec:raise ValueError('HC master ciphertext could not be decrypted')
 out={}
 for i,t in enumerate(dec.split(str(split))):
  if i in {22,24}:continue
  v=field(t,bytes(dyn)) if new else jkl(abc(t,CHACHA[7],bytes(dyn)) if re.fullmatch('[0-9a-fA-F]+',t or '') and len(t)>=16 else t)
  if i==7:v=_cred(v,True)
  elif i==11:v=_cred(v,False)
  if isinstance(v,str) and v.startswith(('{','[')):
   try:v=json.loads(v)
   except:pass
  if v and not (isinstance(v,str) and re.fullmatch('[0-9a-fA-F]+',v)):out[MAP.get(i,f'field_{i}')]=v
 return {'Protections':prot,'Config':out}
BRAILLE='⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠚'
def _z3a(v,iv):
 if not v:return ''
 out=bytearray()
 for m in re.finditer(r'(-?\d+)\.(-?\d+)',v):
  a,b=int(m.group(1))-iv,int(m.group(2))-iv
  try:out.append((a//(1<<b))%256)
  except Exception:pass
 return out.decode('utf-8',errors='ignore')
def _braille(v):
 try:return bytes((BRAILLE.index(v[i])*16+BRAILLE.index(v[i+1]))&255 for i in range(0,len(v)-1,2)).decode('utf-8')
 except:return v
def _cred(v,ssh=False):
 if not v:return v
 if ssh and v[0] in BRAILLE:v=_braille(v)
 pat=r'^([\w\.-]+):([\d\-]+)@(.+):(.+)$' if ssh else r'^([^:]+):(.+)$'; m=re.match(pat,v)
 if not m:return v
 g=m.groups(); u,p=g[-2],g[-1]; iv=len(re.findall(r'(-?\d+)\.(-?\d+)',u)); ip=len(re.findall(r'(-?\d+)\.(-?\d+)',p)); du=_z3a(u,iv) or u; dp=_z3a(p,ip) or p
 return f'{g[0]}:{g[1]}@{du}:{dp}' if ssh else f'{du}:{dp}' 


# ===== dark.py =====
K256=b'$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd'; K192=b'F)J@NcRfUjXn2r4u7x!A%D*G'; IV=bytes.fromhex('232e39185523184a5723586242200e05')
def b64(s):
 s=s.replace('-','+').replace('_','/'); return base64.b64decode(s+'='*((4-len(s)%4)%4))
def dec(d,k):return AES.new(k,AES.MODE_CFB,iv=IV,segment_size=128).decrypt(d)
def norm(v):
 if isinstance(v,dict):return {k:norm(x) for k,x in v.items() if k!='Password'}
 if isinstance(v,list):return [norm(x) for x in v]
 if isinstance(v,bytes):
  try:s=v.decode('utf-8'); return norm(json.loads(s)) if s.strip().startswith(('{','[')) else s
  except:return list(v)
 if isinstance(v,str):
  s=v.strip()
  if s.startswith(('{','[')):
   try:return norm(json.loads(re.sub(r'(:\s*)(\$[A-Za-z0-9_]+)',r'\1"\2"',s)))
   except:pass
 return v
def clean(v,k,iv):
 if isinstance(v,dict):
  o={}
  for a,b in v.items():
   if isinstance(a,str) and a.startswith('Encrypted') and isinstance(b,(bytes,bytearray)):
    try:o[a]=dec(bytes(b),k)
    except:o[a]=b
   else:o[a]=clean(b,k,iv)
  return o
 if isinstance(v,list):return [clean(x,k,iv) for x in v]
 return v
def parse_dark(data):
 s=data.decode('utf-8',errors='ignore').strip(); s=s.split('://',1)[-1] if '://' in s else s
 try:outer=json.loads(b64(s).decode('utf-8'))
 except Exception as e:raise ValueError(f'Dark Tunnel outer base64/JSON failed: {e}')
 if 'encryptedLockedConfig' not in outer:raise ValueError('Dark Tunnel encryptedLockedConfig missing')
 try:uo=msgpack.unpackb(dec(b64(outer['encryptedLockedConfig']),K256),raw=False,strict_map_key=False)
 except Exception as e:raise ValueError(f'Dark Tunnel MessagePack/AES failed: {e}')
 if 'EncryptedLockedConfig' in uo:
  try:ui=msgpack.unpackb(dec(uo['EncryptedLockedConfig'],K192),raw=False,strict_map_key=False); uo['EncryptedLockedConfig']=clean(ui,K192,IV)
  except Exception as e:raise ValueError(f'Dark Tunnel inner decryption failed: {e}')
 outer['encryptedLockedConfig']=uo; return norm(outer)


# ===== ssc.py =====
N=struct.pack('<Q',0xf7479d9f87f3d074); L1=bytes.fromhex('c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b'); L2=bytes.fromhex('7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e'); L3=bytes.fromhex('d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e')
MAP=dict(zip('abcefg hijklmnopqrstuv wxyz'.replace(' ',''),['CONFIGS','NOTE','EXPIRY DATE','CONFIGNAME','PAYLOAD ENABLED','PAYLOAD','PROXY','PROXY PORT','TYPE','PROXY ENABLED','ADDRESS','PORT','IS PREMIUM','USERNAME','PASSWORD','TIMEOUT','PROTOCOL','VERSION','ENCRYPTION','COMPRESSIONLEVEL','DNS','NSSERVER','PUBKEY','ISDEFAULT','LOCALPORT']))
ENC=set('ghlovxiw')
def dec(k,n,d):c=ChaCha20.new(key=k,nonce=n);c.seek(64);return c.decrypt(d)
def cstring(b):return b.split(b'\0')[0].decode('utf-8',errors='ignore')
def clean(v,key=None):
 if not isinstance(v,str):return v
 v=''.join(c for c in v if ord(c)>=32)
 if key in {'ADDRESS','DNS','H','NSSERVER'}:
  m=re.search(r'(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?',v)
  return m.group(0) if m else ''.join(c for c in v if c.isalnum() or c in '.-_')
 if key in {'USERNAME','PASSWORD'}:
  if v.isalnum():return v
  m=re.match(r'^[a-zA-Z0-9!@#$%^&*()._-]+',v); return m.group(0) if m else v.strip()
 if key=='PAYLOAD':return v.split('\x00')[0] if '[crlf]' in v else v.strip()
 return v.strip()

def inner_nonce(key):
 if not key or len(key)!=32:return None
 try:return bytes.fromhex(f'{key[16:32][::-1]}68{key[0:16]}')[:8]
 except:return None
def obj(b):
 t=b.decode('utf-8',errors='ignore').split('\0')[0]; a=t.find('{');z=t.rfind('}')
 if a<0:return None
 try:return json.loads(t[a:z+1])
 except:return None
def parse_ssc(data):
 s=data.decode('utf-8-sig',errors='ignore').strip(); s=s[6:][::-1] if s.startswith('ssc://') else s; s=''.join(s.split())
 if len(s)%2:raise ValueError('SSC hex length is odd')
 try:l1=obj(dec(L1,N,bytes.fromhex(s)))
 except Exception as e:raise ValueError(f'SSC layer 1 failed: {e}')
 if not l1:raise ValueError('SSC layer 1 JSON invalid')
 target=None
 if isinstance(l1.get('a'),str) and 'c' in l1:
  try:target=obj(dec(L2,bytes.fromhex(l1['a'][:16]),bytes.fromhex(l1['c'])))
  except Exception as e:raise ValueError(f'SSC layer 2 failed: {e}')
 elif isinstance(l1.get('a'),list):target=l1
 if not target:raise ValueError('SSC final configuration not found')
 configs=target.get('a')
 if isinstance(configs,list):
  for item in configs:
   n=inner_nonce(item.get('b')) if isinstance(item,dict) else None
   if n:
    for f in ENC.intersection(item):
     v=item[f]
     if isinstance(v,str) and len(v)>16:
      try:item[f]=cstring(dec(L3,n,bytes.fromhex(v)))
      except:pass
   if isinstance(item,dict):
    for k,v in list(item.items()):item[MAP.get(k,k)]=clean(v,MAP.get(k,k)); 
    for k in list(item):
     if k in MAP and k!=MAP[k]:del item[k]
  target['a']=configs
 return _rename(target)
def _rename(d):
 if isinstance(d,dict):return {MAP.get(k,k):_rename(v) for k,v in d.items()}
 if isinstance(d,list):return [_rename(x) for x in d]
 return clean(d, None)


# ===== npvt.py =====

def load_state(path=None):
 blob=os.getenv('NPVT_WHITEBOX_B64','').strip()
 if not blob: raise FileNotFoundError('NPVT white-box state is not configured. Set NPVT_WHITEBOX_B64.')
 try: return pickle.loads(gzip.decompress(base64.b64decode(blob,validate=True)))
 except Exception as e: raise ValueError(f'NPVT white-box state is invalid: {e}')

def wb(block,p2,p3,p4,p5):
 state=list(block); perm=[0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]
 for r in range(2):
  state=[state[perm[i]] for i in range(16)]
  if r==1:break
  mid=[0]*16
  for col in range(4):
   t0,t1,t2,t3=[p3[r][col*4+i][state[col*4+i]] for i in range(4)]
   for row in range(4):
    idx=col*24+row*6; hi,lo=28-row*8,24-row*8
    x1=p2[r][idx][(t0>>hi)&15][(t1>>hi)&15]; x2=p2[r][idx+1][(t2>>hi)&15][(t3>>hi)&15]; hv=p2[r][idx+4][x1][x2]
    x1=p2[r][idx+2][(t0>>lo)&15][(t1>>lo)&15]; x2=p2[r][idx+3][(t2>>lo)&15][(t3>>lo)&15]; lv=p2[r][idx+5][x1][x2]; mid[col*4+row]=((hv<<4)|lv)&255
  new=[0]*16
  for col in range(4):
   t0,t1,t2,t3=[p5[r][col*4+i][mid[col*4+i]] for i in range(4)]
   for row in range(4):
    idx=col*24+row*6; hi,lo=28-row*8,24-row*8
    x1=p2[r][idx][(t0>>hi)&15][(t1>>hi)&15];x2=p2[r][idx+1][(t2>>hi)&15][(t3>>hi)&15];hv=p2[r][idx+4][x1][x2]
    x1=p2[r][idx+2][(t0>>lo)&15][(t1>>lo)&15];x2=p2[r][idx+3][(t2>>lo)&15][(t3>>lo)&15];lv=p2[r][idx+5][x1][x2];new[col*4+row]=((hv<<4)|lv)&255
  state=new
 for i in range(16):state[i]=p4[i][state[i]]
 return bytes(state)
def parse_npvt(data,state_path=None):
 raw=data.decode('utf-8',errors='strict').strip()
 if raw.startswith('NPVTSUB1'):raw=raw[8:].strip()
 elif raw.startswith('NPVT1'):raw=raw[5:].strip()
 else:raise ValueError('NPVT header missing')
 parts=raw.split(',')
 if len(parts)<2:raise ValueError('NPVT payload field missing')
 p2,p3,p4,p5=load_state(state_path); rawb=base64.b64decode(parts[1]);
 if len(rawb)<16:raise ValueError('NPVT ciphertext shorter than IV')
 iv=bytearray(rawb[:16]);ct=rawb[16:]; out=bytearray()
 for j,b in enumerate(ct):
  if j%16==0:
   ks=wb(iv,p2,p3,p4,p5)
   for k in range(15,-1,-1):
    iv[k]=(iv[k]+1)&255
    if iv[k]!=0:break
  out.append(b^ks[j%16])
 try:v=json.loads(out.decode('utf-8'))
 except Exception as e:raise ValueError(f'NPVT decrypted JSON invalid: {e}')
 return v[0] if isinstance(v,list) and v else v


# ===== pipeline =====
@dataclass
class PipelineResult:
    format_key:str|None=None; format_name:str|None=None; parsed:list=field(default_factory=list); normalized:list=field(default_factory=list); uris:list[str]=field(default_factory=list); xray:list[dict]=field(default_factory=list); errors:list[str]=field(default_factory=list); warnings:list[str]=field(default_factory=list); detected_reason:str=''
PARSERS={'ehi':parse_ehi,'hc':parse_hc,'dark':parse_dark,'ssc':parse_ssc,'npvt':parse_npvt}
def process(data:bytes,filename:str,enabled_formats:set[str],max_configs:int=100,validate=True,npvt_state=None,do_uri=True,do_json=True)->PipelineResult:
 r=PipelineResult(); m=detect(data,filename)
 if not m:r.errors.append('فرمت فایل شناسایی نشد.');return r
 r.format_key=m.key;r.format_name=FORMATS.get(m.key,m.key);r.detected_reason=m.reason
 if m.key not in enabled_formats:r.errors.append('این فرمت توسط مدیر غیرفعال شده است.');return r
 try:
  parsed=PARSERS[m.key](data,npvt_state) if m.key=='npvt' else PARSERS[m.key](data);r.parsed=[ParsedConfig(m.key,parsed,filename)]
 except Exception as e:r.errors.append(f'decrypt/parse: {type(e).__name__}: {e}');return r
 r.normalized=normalize_all([x.data for x in r.parsed])[:max_configs]
 for p in r.normalized:
  if do_uri:
   try:
    u=build_uri(p)
    if u:
     ok,why=validate_uri(u) if validate else (True,'')
     if ok:r.uris.append(u)
     else:r.warnings.append(f'URI validation: {why}')
   except Exception as e:r.warnings.append(f'URI generation: {e}')
  if do_json:
   try:
    c=xray_config(p)
    if c:
     ok,why=validate_xray(c) if validate else (True,'')
     if ok:r.xray.append(c)
     else:r.warnings.append(f'JSON validation: {why}')
   except Exception as e:r.warnings.append(f'JSON generation: {e}')
 return r

# ===== bot =====
VERSION="1.0.0"
APP_NAME="Config Processor"
BUILD_DATE="2026-09-05"
BOT_TOKEN=os.getenv("BOT_TOKEN","").strip()
DATA_DIR=Path(os.getenv("DATA_DIR","/app/data")); DB_PATH=DATA_DIR/"prodecryptor.db"
DEFAULT_ADMIN_ID=5728292317
DB=Database(DB_PATH)
JOBS={}; CAPTCHA={}; ADMIN_STATE={}; LOG_BUFFER=[]; LOG_LOCK=asyncio.Lock(); LIMITER=None
MAX_LOG_LINES=500

class MemoryLog(logging.Handler):
    def emit(self,record):
        try:
            LOG_BUFFER.append(self.format(record))
            del LOG_BUFFER[:-MAX_LOG_LINES]
        except Exception: pass

logging.basicConfig(level=logging.INFO,format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
log=logging.getLogger("bot"); log.addHandler(MemoryLog())

def esc(x): return html.escape(str(x or ""),quote=True)
def is_admin(uid:int)->bool:
    try:return uid in {int(x) for x in DB.get("admin_ids",str(DEFAULT_ADMIN_ID)).split(',') if x.strip()}
    except:return uid==DEFAULT_ADMIN_ID

def settings_reload():
    global LIMITER
    LIMITER=asyncio.Semaphore(max(1,int(DB.get("concurrency","4"))))

def kb(rows):return InlineKeyboardMarkup(rows)
def back(cb):return kb([[InlineKeyboardButton("🔙 بازگشت",callback_data=cb)]])

def sponsor_rows():
    if not DB.conn:return []
    rows=[]
    for s in DB.conn.execute("SELECT * FROM sponsors WHERE active=1 ORDER BY sort_order,id").fetchall():
        style_icon={'primary':'🔵','success':'🟢','danger':'🔴'}.get(s['style'],'🔵')
        rows.append([InlineKeyboardButton(f"{style_icon} {s['button_text']}",url=s['url'])])
    return rows

def user_menu():
    rows=[[InlineKeyboardButton("📤 ارسال فایل",callback_data="user:upload")],[InlineKeyboardButton("📊 سهمیه من",callback_data="user:quota"),InlineKeyboardButton("ℹ️ راهنما",callback_data="user:help")]]
    rows+=sponsor_rows(); return kb(rows)

def result_menu(uid):
    j=JOBS.get(uid,{}); fmt=j.get('format_key'); rows=[]
    if fmt:
        if j.get('uris') and DB.feature_enabled(fmt,'uri'):rows.append([InlineKeyboardButton("🔗 URI",callback_data=f"result:uri:{uid}")])
        if j.get('xray') and DB.feature_enabled(fmt,'json'):rows.append([InlineKeyboardButton("📋 JSON / Xray",callback_data=f"result:json:{uid}")])
        if DB.feature_enabled(fmt,'original') and j.get('original'):rows.append([InlineKeyboardButton("📄 فایل اصلی",callback_data=f"result:original:{uid}")])
    rows.append([InlineKeyboardButton("🗑 حذف نتیجه",callback_data=f"result:delete:{uid}")]); rows+=sponsor_rows(); return kb(rows)

def admin_menu():
    return kb([
      [InlineKeyboardButton("📊 داشبورد",callback_data="admin:dashboard"),InlineKeyboardButton("🛠 وضعیت",callback_data="admin:status")],
      [InlineKeyboardButton("⚙️ تنظیمات عمومی",callback_data="admin:general"),InlineKeyboardButton("📦 فرمت‌ها",callback_data="admin:formats")],
      [InlineKeyboardButton("🧪 سلامت parserها",callback_data="admin:health"),InlineKeyboardButton("📈 آمار خطا",callback_data="admin:errors")],
      [InlineKeyboardButton("👥 دسترسی ادمین",callback_data="admin:admins"),InlineKeyboardButton("🧾 فعالیت‌ها",callback_data="admin:jobs")],
      [InlineKeyboardButton("💾 دیتابیس",callback_data="admin:database"),InlineKeyboardButton("📜 لاگ اخیر",callback_data="admin:logs")],
      [InlineKeyboardButton("🔄 reload settings",callback_data="admin:reload"),InlineKeyboardButton("♻️ reset settings",callback_data="admin:reset")],
      [InlineKeyboardButton("📣 پیام همگانی",callback_data="admin:broadcast"),InlineKeyboardButton("🤝 اسپانسرها",callback_data="admin:sponsors")],
      [InlineKeyboardButton("🔒 عضویت اجباری",callback_data="admin:channels"),InlineKeyboardButton("📜 changelog / version",callback_data="admin:version")],
    ])

def format_menu():
    rows=[]
    for f,name in FORMATS.items():
        ready = f!='npvt' or bool(os.getenv('NPVT_WHITEBOX_B64','').strip())
        state='🟢' if DB.fmt_enabled(f) and ready else '⚪'
        rows.append([InlineKeyboardButton(f"{state} {name}",callback_data=f"admin:fmt:{f}")])
    rows.append([InlineKeyboardButton("🔙 پنل",callback_data="admin:dashboard")]); return kb(rows)

def format_settings_menu(fmt):
    rows=[]
    for f in FEATURES:
        on=DB.feature_enabled(fmt,f) if f!='decrypt' else DB.get(f'format_{fmt}_decrypt','0')=='1' and DB.fmt_enabled(fmt)
        label={'decrypt':'🔐 decrypt','uri':'🔗 URI','json':'📋 JSON','original':'📄 فایل اصلی'}[f]
        rows.append([InlineKeyboardButton(f"{'🟢' if on else '⚪'} {label}",callback_data=f"admin:toggle:{fmt}:{f}")])
    rows.append([InlineKeyboardButton("🔙 فرمت‌ها",callback_data="admin:formats")]); return kb(rows)

async def guard(update):
    u=update.effective_user
    if not u:return False
    DB.upsert_user(u); row=DB.user(u.id)
    if row and row['is_blocked'] and not is_admin(u.id):
        if update.callback_query: await update.callback_query.answer("دسترسی شما مسدود است.",show_alert=True)
        elif update.message: await update.message.reply_text("⛔ دسترسی شما مسدود است.")
        return False
    return True

async def force_join(update,context):
    if is_admin(update.effective_user.id):return True
    missing=[]
    for c in DB.conn.execute("SELECT * FROM force_join_channels WHERE active=1 ORDER BY id").fetchall():
        try:
            m=await context.bot.get_chat_member(c['chat_id'],update.effective_user.id)
            if getattr(m,'status','') not in {'creator','administrator','member'} and not (getattr(m,'status','')=='restricted' and getattr(m,'is_member',False)):missing.append(c)
        except Exception:missing.append(c)
    if not missing:return True
    rows=[]
    for c in missing:
        url=c['invite_url'] or (f"https://t.me/{c['username'].lstrip('@')}" if c['username'] else '')
        if url:rows.append([InlineKeyboardButton(f"📢 {c['title'] or c['username'] or c['chat_id']}",url=url)])
    rows.append([InlineKeyboardButton("✅ عضو شدم — بررسی",callback_data="access:join")])
    target=update.callback_query.message if update.callback_query else update.message
    await target.reply_text("🔒 برای استفاده باید در کانال‌های فعال عضو باشی.",reply_markup=kb(rows)); return False

def captcha_question():
    a=secrets.randbelow(40)+1;b=secrets.randbelow(40)+1;return a,b,a+b
async def captcha_guard(update,context):
    if is_admin(update.effective_user.id):return True
    uid=update.effective_user.id; verified,ops,fail=bool(DB.user(uid)['captcha_verified']),int(DB.user(uid)['captcha_ops']),int(DB.user(uid)['captcha_failures'])
    interval=max(1,int(DB.get('captcha_interval','10')))
    if verified and ops<interval:return True
    a,b,ans=captcha_question(); msg=update.callback_query.message if update.callback_query else update.message; sent=await msg.reply_text(f"🤖 {a} + {b} = ؟")
    CAPTCHA[uid]={'answer':ans,'message_id':sent.message_id}; return False

async def start(update,context):
    if not await guard(update) or not await force_join(update,context):return
    if not await captcha_guard(update,context):return
    if DB.get('maintenance','0')=='1' and not is_admin(update.effective_user.id):await update.message.reply_text("🛠 سرویس موقتاً در دسترس نیست.");return
    lim=int(DB.get('daily_limit','5')); await update.message.reply_text(f"✨ <b>{APP_NAME}</b> <code>v{VERSION}</code>\n\nفقط فایل کانفیگ را ارسال کن.\nسهمیه امروز: <b>{'∞' if lim==0 else lim}</b> فایل",parse_mode=ParseMode.HTML,reply_markup=user_menu())

async def help_cmd(update,context):
    if not await guard(update) or not await force_join(update,context) or not await captcha_guard(update,context):return
    await update.message.reply_text("ℹ️ <b>راهنما</b>\n\nفقط فایل دریافت می‌شود. فرمت پس از بررسی ساختار واقعی فایل تشخیص داده می‌شود.\nاگر decrypt یا خروجی خاصی خاموش باشد، همان مرحله اجرا یا نمایش داده نمی‌شود.\nفایل خراب یا غیرقابل‌اعتبارسنجی هرگز موفق گزارش نمی‌شود.",parse_mode=ParseMode.HTML,reply_markup=user_menu())

async def cancel(update,context):
    uid=update.effective_user.id; CAPTCHA.pop(uid,None); ADMIN_STATE.pop(uid,None); cleanup(uid); await update.message.reply_text("❎ عملیات لغو شد.",reply_markup=admin_menu() if is_admin(uid) else user_menu())

def cleanup(uid):
    j=JOBS.pop(uid,None)
    if j and j.get('directory'):shutil.rmtree(j['directory'],ignore_errors=True)

async def handle_captcha(update,context):
    uid=update.effective_user.id; p=CAPTCHA.pop(uid,None)
    if not p:return False
    try:
        ok=int((update.message.text or '').strip())==p['answer']
    except:ok=False
    try:await update.message.delete()
    except:pass
    if ok:
        DB.conn.execute("UPDATE users SET captcha_verified=1,captcha_ops=0,captcha_failures=0 WHERE user_id=?",(uid,));DB.conn.commit();await context.bot.send_message(uid,"✅ تأیید شد.",reply_markup=user_menu())
    else:
        DB.conn.execute("UPDATE users SET captcha_failures=captcha_failures+1 WHERE user_id=?",(uid,));DB.conn.commit();
        if int(DB.user(uid)['captcha_failures'])>=int(DB.get('captcha_max_attempts','5')):DB.conn.execute("UPDATE users SET is_blocked=1 WHERE user_id=?",(uid,));DB.conn.commit();await context.bot.send_message(uid,"⛔ دسترسی شما به‌دلیل تلاش‌های ناموفق مسدود شد.")
        else:
            a,b,ans=captcha_question();sent=await context.bot.send_message(uid,f"🤖 {a} + {b} = ؟");CAPTCHA[uid]={'answer':ans,'message_id':sent.message_id}
    return True

async def handle_document(update,context):
    if not await guard(update):return
    uid=update.effective_user.id
    if uid!=DEFAULT_ADMIN_ID and uid in CAPTCHA:
        await update.message.reply_text("🤖 ابتدا سؤال امنیتی را پاسخ بده.");return
    if not await force_join(update,context) or not await captcha_guard(update,context):return
    if DB.get('maintenance','0')=='1' and not is_admin(uid):await update.message.reply_text("🛠 سرویس موقتاً در دسترس نیست.");return
    doc=update.message.document; name=Path(doc.file_name or 'config.bin').name; size_limit=int(DB.get('max_file_size',str(50*1024*1024)))
    if doc.file_size and doc.file_size>size_limit:await update.message.reply_text(f"❌ حجم فایل بیشتر از حد مجاز است: {size_limit//1024//1024} MB");return
    if not DB.consume(uid):await update.message.reply_text(f"⛔ سهمیه امروز تمام شده است. سقف: {DB.get('daily_limit','5')}");return
    m=detect(await _download_bytes(doc),name)
    if not m:
        DB.refund(uid); await update.message.reply_text("❌ فرمت فایل قابل تشخیص نیست.");return
    if not DB.fmt_enabled(m.key):
        DB.refund(uid); await update.message.reply_text("⛔ این فرمت توسط مدیر غیرفعال شده است.");return
    if DB.get(f'format_{m.key}_decrypt','0')!='1':
        DB.refund(uid); await update.message.reply_text("⛔ decrypt این فرمت غیرفعال است.");return
    data=await _download_bytes(doc); msg=await update.message.reply_text("⏳ در حال اعتبارسنجی و پردازش فایل...")
    jid=uuid.uuid4().hex; DB.job(jid,uid,name,Path(name).suffix.lower())
    try:
        async with LIMITER:
            r=await asyncio.to_thread(process,data,name,set(FORMATS),int(DB.get('max_configs','100')),DB.get('validation','1')=='1',None,DB.feature_enabled(m.key,'uri'),DB.feature_enabled(m.key,'json'))
        if r.errors:raise RuntimeError('; '.join(r.errors))
        # deterministic duplicate filtering at the final artifact level
        if DB.get('duplicate_filter','1')=='1':
            r.uris=list(dict.fromkeys(r.uris));
            seen=set(); uniq=[]
            for c in r.xray:
                k=json.dumps(c,ensure_ascii=False,sort_keys=True,separators=(',',':'))
                if k not in seen:seen.add(k);uniq.append(c)
            r.xray=uniq
        if not r.uris and not r.xray and not DB.feature_enabled(m.key,'original'):raise RuntimeError('هیچ خروجی معتبر و فعال تولید نشد.')
        work=Path(tempfile.mkdtemp(prefix='cfg-')); original=work/name; original.write_bytes(data)
        JOBS[uid]={'directory':str(work),'format_key':m.key,'format_name':FORMATS[m.key],'filename':name,'uris':r.uris,'xray':r.xray,'original':str(original),'warnings':r.warnings,'reason':r.detected_reason}
        DB.success(uid,len(r.uris));DB.finish(jid,'success',len(r.uris));
        if not is_admin(uid):DB.conn.execute("UPDATE users SET captcha_ops=captcha_ops+1 WHERE user_id=?",(uid,));DB.conn.commit()
        await msg.edit_text(f"✅ <b>پردازش موفق</b>\n\nفرمت: <b>{esc(FORMATS[m.key])}</b>\nنتایج معتبر: <b>{len(r.uris)+len(r.xray)}</b>",parse_mode=ParseMode.HTML,reply_markup=result_menu(uid))
    except Exception as e:
        DB.failure(uid);DB.finish(jid,'failed',0,str(e));DB.refund(uid);log.exception('processing failed')
        await msg.edit_text(f"❌ <b>پردازش ناموفق</b>\n\n<code>{esc(str(e)[:1000])}</code>",parse_mode=ParseMode.HTML,reply_markup=user_menu())

def _download_bytes_sync(doc):return None
async def _download_bytes(doc):
    f=await doc.get_file(); path=Path(tempfile.mkstemp(prefix='dl-')[1]); await f.download_to_drive(custom_path=str(path)); data=path.read_bytes();path.unlink(missing_ok=True);return data

async def result_callback(update,context):
    q=update.callback_query;await q.answer();uid=q.from_user.id
    if not await guard(update) or not await force_join(update,context):return
    parts=q.data.split(':'); action=parts[1]; owner=int(parts[2])
    if uid!=owner:await q.answer('این نتیجه متعلق به شما نیست.',show_alert=True);return
    j=JOBS.get(uid)
    if not j:await q.message.reply_text('⚠️ نتیجه دیگر در دسترس نیست.');return
    fmt=j['format_key']
    if action in {'uri','json','original'} and not DB.feature_enabled(fmt,action):await q.answer('این قابلیت غیرفعال است.',show_alert=True);return
    if action=='uri':
        for u in j['uris']:await q.message.reply_text(f"<code>{esc(u)}</code>",parse_mode=ParseMode.HTML)
    elif action=='json':
        for c in j['xray']:await q.message.reply_text(f"<pre>{esc(json.dumps(c,ensure_ascii=False,indent=2))}</pre>",parse_mode=ParseMode.HTML)
    elif action=='original':
        with open(j['original'],'rb') as f:await q.message.reply_document(f,filename=j['filename'])
    elif action=='delete':cleanup(uid);await q.message.reply_text('🗑 نتیجه حذف شد.',reply_markup=user_menu());return
    await q.message.reply_text('↩️',reply_markup=result_menu(uid))

async def user_callback(update,context):
    q=update.callback_query;await q.answer();
    if not await guard(update) or not await force_join(update,context):return
    uid=q.from_user.id
    if q.data=='user:upload':await q.message.reply_text('📤 فایل را مستقیم ارسال کن.',reply_markup=user_menu())
    elif q.data=='user:quota':await q.message.reply_text(f"📊 مصرف امروز: <b>{DB.daily_usage(uid)}</b>\nسقف: <b>{'∞' if DB.get('daily_limit','5')=='0' else DB.get('daily_limit','5')}</b>",parse_mode=ParseMode.HTML,reply_markup=user_menu())
    elif q.data=='user:help':await help_cmd(type('U',(),{'effective_user':q.from_user,'message':q.message,'callback_query':q})(),context)
    elif q.data=='access:join':await force_join(update,context)

async def admin_command(update,context):
    if not is_admin(update.effective_user.id):return
    await update.message.reply_text(f"🛡 <b>Admin</b> <code>v{VERSION}</code>",parse_mode=ParseMode.HTML,reply_markup=admin_menu())

async def admin_callback(update,context):
    q=update.callback_query;await q.answer();uid=q.from_user.id
    if not is_admin(uid):return
    d=q.data
    if d=='admin:dashboard':await q.message.edit_text(f"📊 <b>داشبورد</b>\n\n{json.dumps(DB.stats(),ensure_ascii=False)}",parse_mode=ParseMode.HTML,reply_markup=admin_menu())
    elif d=='admin:formats':await q.message.edit_text('📦 <b>فرمت‌ها</b>\n\nهر فرمت مستقل است.',parse_mode=ParseMode.HTML,reply_markup=format_menu())
    elif d.startswith('admin:fmt:'):
        f=d.split(':')[-1];await q.message.edit_text(f"🎛 <b>{esc(FORMATS[f])}</b>\n\nفعال بودن خود فرمت: {'🟢' if DB.fmt_enabled(f) else '⚪'}",parse_mode=ParseMode.HTML,reply_markup=kb([[InlineKeyboardButton(('🟢 فعال' if DB.fmt_enabled(f) else '⚪ غیرفعال'),callback_data=f'admin:fmt_toggle:{f}')]] + format_settings_menu(f).inline_keyboard))
    elif d.startswith('admin:toggle:'):
        _,_,f,feat=d.split(':'); key=f'format_{f}_{feat}'
        if feat=='decrypt':DB.set(key,'0' if DB.get(key,'0')=='1' else '1')
        else:DB.set(key,'0' if DB.get(key,'1')=='1' else '1')
        await q.message.edit_text(f"🎛 <b>{esc(FORMATS[f])}</b>",parse_mode=ParseMode.HTML,reply_markup=format_settings_menu(f))
    elif d.startswith('admin:fmt_toggle:'):
        f=d.split(':')[-1]; DB.set(f'format_{f}','0' if DB.fmt_enabled(f) else '1'); await q.message.edit_text(f"🎛 <b>{esc(FORMATS[f])}</b>",parse_mode=ParseMode.HTML,reply_markup=kb([[InlineKeyboardButton(('🟢 فعال' if DB.fmt_enabled(f) else '⚪ غیرفعال'),callback_data=f'admin:fmt_toggle:{f}')]] + format_settings_menu(f).inline_keyboard))
    elif d=='admin:broadcast':ADMIN_STATE[uid]={'type':'broadcast'};await q.message.reply_text('📣 متن پیام همگانی را ارسال کن.',reply_markup=back('admin:dashboard'))
    elif d=='admin:sponsors':await admin_sponsors(q)
    elif d.startswith('admin:sponsor:toggle:'):
        sid=int(d.split(':')[-1]); r=DB.conn.execute('SELECT active FROM sponsors WHERE id=?',(sid,)).fetchone(); DB.conn.execute('UPDATE sponsors SET active=?,updated_at=? WHERE id=?',(0 if r and r[0] else 1,int(time.time()),sid));DB.conn.commit();await admin_sponsors(q)
    elif d.startswith('admin:sponsor:delete:'):
        DB.conn.execute('DELETE FROM sponsors WHERE id=?',(int(d.split(':')[-1]),));DB.conn.commit();await admin_sponsors(q)
    elif d=='admin:sponsor:add':ADMIN_STATE[uid]={'type':'sponsor_add'};await q.message.reply_text('نام|URL|متن دکمه|style را با | جدا کن.',reply_markup=back('admin:sponsors'))
    elif d=='admin:channels':await admin_channels(q)
    elif d.startswith('admin:channel:toggle:'):
        cid=int(d.split(':')[-1]);DB.conn.execute('UPDATE force_join_channels SET active=CASE active WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(cid,));DB.conn.commit();await admin_channels(q)
    elif d.startswith('admin:channel:delete:'):
        DB.conn.execute('DELETE FROM force_join_channels WHERE id=?',(int(d.split(':')[-1]),));DB.conn.commit();await admin_channels(q)
    elif d=='admin:channel:add':ADMIN_STATE[uid]={'type':'channel_add'};await q.message.reply_text('chat_id|title|username|invite_url را با | جدا کن.',reply_markup=back('admin:channels'))
    elif d=='admin:general':await admin_general(q)
    elif d.startswith('admin:global:'):
        k=d.split(':')[-1]; DB.set(k,'0' if DB.get(k,'1')=='1' else '1'); await admin_general(q)
    elif d=='admin:status':
        await q.message.edit_text(f"🛠 <b>وضعیت</b>\n\nنسخه: <code>{VERSION}</code>\nDB: <code>{esc(DB_PATH)}</code>\nPython: <code>{os.sys.version.split()[0]}</code>\nNPVT state: <b>{'آماده' if bool(os.getenv('NPVT_WHITEBOX_B64','').strip()) else 'در دسترس نیست'}</b>",parse_mode=ParseMode.HTML,reply_markup=back('admin:dashboard'))
    elif d=='admin:health':await admin_health(q)
    elif d.startswith('admin:test:'):await admin_test(q,d.split(':')[-1])
    elif d=='admin:errors':await admin_errors(q)
    elif d=='admin:jobs':await admin_jobs(q)
    elif d=='admin:logs':await admin_logs(q)
    elif d=='admin:database':await admin_database(q)
    elif d=='admin:admins':await admin_admins(q)
    elif d=='admin:admins:edit':ADMIN_STATE[uid]={'type':'admins'};await q.message.reply_text('شناسه‌های ادمین را با کاما ارسال کن.',reply_markup=back('admin:admins'))
    elif d=='admin:reload':settings_reload();await q.message.reply_text('✅ تنظیمات reload شد.',reply_markup=admin_menu())
    elif d=='admin:reset':
        for k,v in {'output_uri':'1','output_json':'1','output_original':'1','duplicate_filter':'1','validation':'1','logging_level':'INFO','max_file_size':str(50*1024*1024),'max_configs':'100','process_timeout':'90','concurrency':'4'}.items():DB.set(k,v)
        for f in FORMATS:
            DB.set(f'format_{f}','1' if f!='npvt' or bool(os.getenv('NPVT_WHITEBOX_B64','').strip()) else '0')
            for x in FEATURES:DB.set(f'format_{f}_{x}','1')
        settings_reload();await q.message.reply_text('♻️ تنظیمات به حالت پایه برگشت.',reply_markup=admin_menu())
    elif d=='admin:version':await q.message.edit_text(f"📜 <b>Version</b>\n\n<code>{VERSION}</code> — بازسازی اولیه\nBuild: {BUILD_DATE}\n\nقواعد: patch برای bugfix، minor برای feature، major برای breaking change.",parse_mode=ParseMode.HTML,reply_markup=back('admin:dashboard'))
    elif d=='admin:database':await admin_database(q)
    elif d=='admin:backup':await admin_backup(q)
    elif d=='admin:cancel':ADMIN_STATE.pop(uid,None);await q.message.reply_text('❎ لغو شد.',reply_markup=admin_menu())

async def admin_sponsors(q):
    rows=DB.conn.execute('SELECT * FROM sponsors ORDER BY sort_order,id').fetchall(); lines=['🤝 <b>اسپانسرها</b>','']; buttons=[]
    for r in rows:
        style_icon={'primary':'🔵','success':'🟢','danger':'🔴'}.get(r['style'],'🔵'); lines.append(f"{'🟢' if r['active'] else '⚪'} {style_icon} {esc(r['button_text'])} — {esc(r['style'])} #{r['id']}"); buttons.append([InlineKeyboardButton('فعال/غیرفعال',callback_data=f"admin:sponsor:toggle:{r['id']}"),InlineKeyboardButton('🗑',callback_data=f"admin:sponsor:delete:{r['id']}")])
    buttons.append([InlineKeyboardButton('➕ افزودن',callback_data='admin:sponsor:add')]);buttons.append([InlineKeyboardButton('🔙 پنل',callback_data='admin:dashboard')]);await q.message.edit_text('\n'.join(lines),parse_mode=ParseMode.HTML,reply_markup=kb(buttons))
async def admin_channels(q):
    rows=DB.conn.execute('SELECT * FROM force_join_channels ORDER BY id').fetchall();lines=['🔒 <b>عضویت اجباری</b>',''];buttons=[]
    for r in rows:
        lines.append(f"{'🟢' if r['active'] else '⚪'} {esc(r['title'] or r['username'] or r['chat_id'])}");buttons.append([InlineKeyboardButton('فعال/غیرفعال',callback_data=f"admin:channel:toggle:{r['id']}"),InlineKeyboardButton('🗑',callback_data=f"admin:channel:delete:{r['id']}")])
    buttons.append([InlineKeyboardButton('➕ افزودن',callback_data='admin:channel:add')]);buttons.append([InlineKeyboardButton('🔙 پنل',callback_data='admin:dashboard')]);await q.message.edit_text('\n'.join(lines),parse_mode=ParseMode.HTML,reply_markup=kb(buttons))

async def admin_general(q):
    keys=['output_uri','output_json','output_original','duplicate_filter','validation']; rows=[]
    for k in keys:rows.append([InlineKeyboardButton(f"{'🟢' if DB.get(k,'1')=='1' else '⚪'} {k}",callback_data=f'admin:global:{k}')])
    rows.append([InlineKeyboardButton('🔙 پنل',callback_data='admin:dashboard')])
    await q.message.edit_text(f"⚙️ <b>تنظیمات عمومی</b>\n\nحجم: {int(DB.get('max_file_size',str(50*1024*1024)))//1024//1024}MB\nتعداد کانفیگ: {DB.get('max_configs','100')}\nTimeout: {DB.get('process_timeout','90')}s\nConcurrency: {DB.get('concurrency','4')}\nLog level: {esc(DB.get('logging_level','INFO'))}",parse_mode=ParseMode.HTML,reply_markup=kb(rows))

async def admin_health(q):
    lines=['🧪 <b>سلامت parserها</b>','']
    for f,n in FORMATS.items():
        ready=f!='npvt' or bool(os.getenv('NPVT_WHITEBOX_B64','').strip())
        lines.append(f"{'🟢' if ready else '🔴'} {n}: {'آماده' if ready else 'نیازمند white-box state دقیق'}")
    rows=[[InlineKeyboardButton(f'🧪 تست {n}',callback_data=f'admin:test:{f}')] for f,n in FORMATS.items()];rows.append([InlineKeyboardButton('🔙 پنل',callback_data='admin:dashboard')])
    await q.message.edit_text('\n'.join(lines),parse_mode=ParseMode.HTML,reply_markup=kb(rows))

async def admin_test(q,fmt):
    try:
        path=Path('tests/fixtures')
        candidates=list(path.glob(f'{fmt}.*'))
        if not candidates: raise RuntimeError('fixture واقعی برای این parser در پروژه موجود نیست')
        data=candidates[0].read_bytes();r=await asyncio.to_thread(process,data,candidates[0].name,set(FORMATS),int(DB.get('max_configs','100')),True,None,True,True)
        text=f"🧪 {FORMATS[fmt]}\n\n{'✅' if not r.errors else '❌'}\n{esc('; '.join(r.errors+r.warnings))}"
    except Exception as e:text=f"🧪 {FORMATS.get(fmt,fmt)}\n\n⚠️ {esc(str(e))}"
    await q.message.edit_text(text,parse_mode=ParseMode.HTML,reply_markup=back('admin:health'))

async def admin_errors(q):
    rows=DB.conn.execute("SELECT filename,status,error,created_at FROM jobs WHERE status='failed' ORDER BY created_at DESC LIMIT 20").fetchall(); lines=['📈 <b>آخرین خطاها</b>','']
    for x in rows:lines.append(f"❌ <code>{esc(x['filename'])}</code> — {esc(x['error'][:180])}")
    await q.message.edit_text('\n'.join(lines),parse_mode=ParseMode.HTML,reply_markup=back('admin:dashboard'))
async def admin_jobs(q):
    rows=DB.conn.execute("SELECT filename,status,links_count,created_at FROM jobs ORDER BY created_at DESC LIMIT 20").fetchall();lines=['🧾 <b>آخرین فعالیت‌ها</b>','']
    for x in rows:lines.append(f"{'✅' if x['status']=='success' else '❌'} {esc(x['filename'])} | {x['links_count']}")
    await q.message.edit_text('\n'.join(lines),parse_mode=ParseMode.HTML,reply_markup=back('admin:dashboard'))
async def admin_logs(q):
    await q.message.edit_text('📜 <b>لاگ اخیر</b>\n\n'+esc('\n'.join(LOG_BUFFER[-100:]) or 'لاگی ثبت نشده.'),parse_mode=ParseMode.HTML,reply_markup=back('admin:dashboard'))
async def admin_database(q):
    await q.message.edit_text(f"💾 <b>دیتابیس</b>\n\nمسیر: <code>{esc(DB_PATH)}</code>\nوجود دارد: {'بله' if DB_PATH.exists() else 'خیر'}",parse_mode=ParseMode.HTML,reply_markup=kb([[InlineKeyboardButton('⬇️ بکاپ',callback_data='admin:backup')],[InlineKeyboardButton('🔙 پنل',callback_data='admin:dashboard')]]))
async def admin_backup(q):
    tmp=Path(tempfile.mkstemp(suffix='.db')[1]);
    try:
        dst=__import__('sqlite3').connect(tmp);DB.conn.backup(dst);dst.close()
        with tmp.open('rb') as f:await q.message.reply_document(f,filename='database-backup.db')
    finally:tmp.unlink(missing_ok=True)
async def admin_admins(q):
    await q.message.edit_text(f"👥 <b>ادمین‌ها</b>\n\n<code>{esc(DB.get('admin_ids',str(DEFAULT_ADMIN_ID)))}</code>",parse_mode=ParseMode.HTML,reply_markup=kb([[InlineKeyboardButton('✏️ ویرایش',callback_data='admin:admins:edit')],[InlineKeyboardButton('🔙 پنل',callback_data='admin:dashboard')]]))

async def admin_state_handler(update,context):
    uid=update.effective_user.id; state=ADMIN_STATE.get(uid)
    if not state:return False
    raw=(update.message.text or '').strip()
    if state.get('type')=='admins':
        try:ids=[str(int(x.strip())) for x in raw.split(',') if x.strip()]
        except:await update.message.reply_text('❌ شناسه نامعتبر است.');return True
        if not ids or str(DEFAULT_ADMIN_ID) not in ids:await update.message.reply_text('❌ ادمین فعلی باید حفظ شود.');return True
        DB.set('admin_ids',','.join(dict.fromkeys(ids)));ADMIN_STATE.pop(uid,None);await update.message.reply_text('✅ فهرست ادمین‌ها ذخیره شد.',reply_markup=admin_menu());return True
    if state.get('type')=='sponsor_add':
        try:name,url,button,style=[x.strip() for x in raw.split('|',3)]; style=style if style in {'primary','success','danger'} else 'primary'; now=int(time.time()); order=DB.conn.execute('SELECT COALESCE(MAX(sort_order),0)+1 FROM sponsors').fetchone()[0];DB.conn.execute('INSERT INTO sponsors(name,url,button_text,style,active,sort_order,created_at,updated_at) VALUES(?,?,?,?,1,?,?,?)',(name,url,button,style,order,now,now));DB.conn.commit();ADMIN_STATE.pop(uid,None);await update.message.reply_text('✅ اسپانسر ثبت شد.',reply_markup=admin_menu())
        except:await update.message.reply_text('❌ قالب صحیح: نام|URL|متن|style')
        return True
    if state.get('type')=='channel_add':
        try:chat,title,user,invite=[x.strip() for x in raw.split('|',3)];DB.conn.execute('INSERT OR REPLACE INTO force_join_channels(chat_id,title,username,invite_url,active,created_at) VALUES(?,?,?,?,1,?)',(chat,title,user,invite,int(time.time())));DB.conn.commit();ADMIN_STATE.pop(uid,None);await update.message.reply_text('✅ کانال ثبت شد.',reply_markup=admin_menu())
        except:await update.message.reply_text('❌ قالب صحیح: chat_id|title|username|invite_url')
        return True
    if state.get('type')=='broadcast':
        ADMIN_STATE.pop(uid,None); ok=bad=0
        for r in DB.conn.execute('SELECT user_id FROM users WHERE is_blocked=0').fetchall():
            try:await context.bot.send_message(r['user_id'],raw);ok+=1
            except (Forbidden,TelegramError):bad+=1
            await asyncio.sleep(.03)
        await update.message.reply_text(f'📣 پایان ارسال همگانی\nموفق: {ok}\nناموفق: {bad}',reply_markup=admin_menu());return True
    return False

async def handle_text(update,context):
    if not await guard(update):return
    uid=update.effective_user.id
    if uid in CAPTCHA:await handle_captcha(update,context);return
    if is_admin(uid) and await admin_state_handler(update,context):return
    # Text input is intentionally not an extraction interface.
    if not await force_join(update,context):return
    await update.message.reply_text('📤 فقط فایل قابل پردازش است.',reply_markup=user_menu())

async def error_handler(update,context):log.exception('Unhandled exception',exc_info=context.error)
async def post_init(app):
    DB.open();settings_reload();log.info('started version=%s db=%s',VERSION,DB_PATH)
async def post_shutdown(app):
    for uid in list(JOBS):cleanup(uid)
    DB.close()

def main():
    if not BOT_TOKEN:raise RuntimeError('BOT_TOKEN is not set')
    app=Application.builder().token(BOT_TOKEN).post_init(post_init).post_shutdown(post_shutdown).build()
    app.add_handler(CommandHandler('start',start));app.add_handler(CommandHandler('help',help_cmd));app.add_handler(CommandHandler('admin',admin_command));app.add_handler(CommandHandler('cancel',cancel))
    app.add_handler(CallbackQueryHandler(user_callback,pattern=r'^(user|access):'));app.add_handler(CallbackQueryHandler(result_callback,pattern=r'^result:'));app.add_handler(CallbackQueryHandler(admin_callback,pattern=r'^admin:'))
    app.add_handler(MessageHandler(filters.Document.ALL,handle_document));app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND,handle_text));app.add_error_handler(error_handler);app.run_polling(allowed_updates=Update.ALL_TYPES)
if __name__=='__main__':main()

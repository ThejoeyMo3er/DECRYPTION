import base64,json,re
from Crypto.Cipher import ChaCha20,AES
from Crypto.Util.Padding import unpad
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
def parse(b):
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

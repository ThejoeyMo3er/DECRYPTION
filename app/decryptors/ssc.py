import json,re,struct
from Crypto.Cipher import ChaCha20
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
def parse(data):
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

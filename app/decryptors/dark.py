import base64,json,re
from Crypto.Cipher import AES
import msgpack
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
def parse(data):
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

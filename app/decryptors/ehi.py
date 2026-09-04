import base64,contextlib,hashlib,io,json,struct
from Crypto.Cipher import AES,ChaCha20_Poly1305
from Crypto.Util.Padding import unpad
from argon2.low_level import hash_secret_raw,Type

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
def parse(file_bytes):
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

from __future__ import annotations
import base64,gzip,pickle,json,os

def load_state(path=None):
 p=path or os.getenv('NPVT_WHITEBOX_BLOB_FILE','data/npvt_whitebox.b64')
 if not os.path.exists(p):raise FileNotFoundError('NPVT white-box state is not installed')
 with open(p,'rb') as f: blob=f.read()
 if b'=' in blob[:200]: return pickle.loads(gzip.decompress(base64.b64decode(blob)))
 return pickle.loads(gzip.decompress(blob))

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
def parse(data,state_path=None):
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

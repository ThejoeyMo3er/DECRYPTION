from __future__ import annotations
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

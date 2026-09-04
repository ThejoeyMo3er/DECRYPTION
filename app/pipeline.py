from __future__ import annotations
from dataclasses import dataclass,field
from pathlib import Path
from .detector import detect
from .models import ParsedConfig
from .normalize import normalize_all
from .uri import build_uri
from .xray import xray_config
from .validators import validate_uri,validate_xray
from .decryptors import ehi,hc,dark,ssc,npvt

PARSERS={'ehi':ehi.parse,'hc':hc.parse,'dark':dark.parse,'ssc':ssc.parse,'npvt':npvt.parse}

@dataclass
class PipelineResult:
    format_key:str|None=None; format_name:str|None=None; parsed:list=field(default_factory=list); normalized:list=field(default_factory=list); uris:list[str]=field(default_factory=list); xray:list[dict]=field(default_factory=list); errors:list[str]=field(default_factory=list); warnings:list[str]=field(default_factory=list); detected_reason:str=''

def process(data:bytes,filename:str,enabled_formats:set[str],max_configs:int=100,validate=True,npvt_state=None,do_uri=True,do_json=True)->PipelineResult:
    r=PipelineResult(); m=detect(data,filename)
    if not m: r.errors.append('فرمت فایل شناسایی نشد.'); return r
    r.format_key=m.key;r.detected_reason=m.reason
    if m.key not in enabled_formats:r.errors.append('این فرمت توسط مدیر غیرفعال شده است.');return r
    parser=PARSERS[m.key]
    try:
        parsed=parser(data,npvt_state) if m.key=='npvt' else parser(data)
        r.parsed=[ParsedConfig(m.key,parsed,filename)]
    except Exception as e:
        r.errors.append(f'decrypt/parse: {type(e).__name__}: {e}');return r
    r.normalized=normalize_all([x.data for x in r.parsed])[:max_configs]
    for p in r.normalized:
        try:
            u=build_uri(p) if do_uri else None
            if u:
                ok,why=validate_uri(u) if validate else (True,'')
                if ok:r.uris.append(u)
                else:r.warnings.append(f'URI validation: {why}')
        except Exception as e:r.warnings.append(f'URI generation: {e}')
        try:
            c=xray_config(p) if do_json else None
            if c:
                ok,why=validate_xray(c) if validate else (True,'')
                if ok:r.xray.append(c)
                else:r.warnings.append(f'JSON validation: {why}')
        except Exception as e:r.warnings.append(f'JSON generation: {e}')
    return r

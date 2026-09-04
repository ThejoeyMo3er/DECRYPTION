from __future__ import annotations
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

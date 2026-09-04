from __future__ import annotations
import asyncio, html, json, logging, os, secrets, shutil, tempfile, time, uuid
from pathlib import Path
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import Forbidden, TelegramError
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters

from app.database import Database, FORMATS, FEATURES
from app.detector import detect
from app.pipeline import process

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
        rows.append([InlineKeyboardButton(s['button_text'],url=s['url'])])
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
        ready = f!='npvt' or Path(os.getenv('NPVT_WHITEBOX_BLOB_FILE','data/npvt_whitebox.b64')).exists()
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
            r=await asyncio.to_thread(process,data,name,set(FORMATS),int(DB.get('max_configs','100')),DB.get('validation','1')=='1',os.getenv('NPVT_WHITEBOX_BLOB_FILE'),DB.feature_enabled(m.key,'uri'),DB.feature_enabled(m.key,'json'))
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
        await q.message.edit_text(f"🛠 <b>وضعیت</b>\n\nنسخه: <code>{VERSION}</code>\nDB: <code>{esc(DB_PATH)}</code>\nPython: <code>{os.sys.version.split()[0]}</code>\nNPVT state: <b>{'آماده' if Path(os.getenv('NPVT_WHITEBOX_BLOB_FILE','data/npvt_whitebox.b64')).exists() else 'در دسترس نیست'}</b>",parse_mode=ParseMode.HTML,reply_markup=back('admin:dashboard'))
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
            DB.set(f'format_{f}','1' if f!='npvt' or Path(os.getenv('NPVT_WHITEBOX_BLOB_FILE','data/npvt_whitebox.b64')).exists() else '0')
            for x in FEATURES:DB.set(f'format_{f}_{x}','1')
        settings_reload();await q.message.reply_text('♻️ تنظیمات به حالت پایه برگشت.',reply_markup=admin_menu())
    elif d=='admin:version':await q.message.edit_text(f"📜 <b>Version</b>\n\n<code>{VERSION}</code> — بازسازی اولیه\nBuild: {BUILD_DATE}\n\nقواعد: patch برای bugfix، minor برای feature، major برای breaking change.",parse_mode=ParseMode.HTML,reply_markup=back('admin:dashboard'))
    elif d=='admin:database':await admin_database(q)
    elif d=='admin:backup':await admin_backup(q)
    elif d=='admin:cancel':ADMIN_STATE.pop(uid,None);await q.message.reply_text('❎ لغو شد.',reply_markup=admin_menu())

async def admin_sponsors(q):
    rows=DB.conn.execute('SELECT * FROM sponsors ORDER BY sort_order,id').fetchall(); lines=['🤝 <b>اسپانسرها</b>','']; buttons=[]
    for r in rows:
        lines.append(f"{'🟢' if r['active'] else '⚪'} {esc(r['button_text'])} #{r['id']}"); buttons.append([InlineKeyboardButton('فعال/غیرفعال',callback_data=f"admin:sponsor:toggle:{r['id']}"),InlineKeyboardButton('🗑',callback_data=f"admin:sponsor:delete:{r['id']}")])
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
        ready=f!='npvt' or Path(os.getenv('NPVT_WHITEBOX_BLOB_FILE','data/npvt_whitebox.b64')).exists()
        lines.append(f"{'🟢' if ready else '🔴'} {n}: {'آماده' if ready else 'نیازمند white-box state دقیق'}")
    rows=[[InlineKeyboardButton(f'🧪 تست {n}',callback_data=f'admin:test:{f}')] for f,n in FORMATS.items()];rows.append([InlineKeyboardButton('🔙 پنل',callback_data='admin:dashboard')])
    await q.message.edit_text('\n'.join(lines),parse_mode=ParseMode.HTML,reply_markup=kb(rows))

async def admin_test(q,fmt):
    try:
        path=Path('tests/fixtures')
        candidates=list(path.glob(f'{fmt}.*'))
        if not candidates: raise RuntimeError('fixture واقعی برای این parser در پروژه موجود نیست')
        data=candidates[0].read_bytes();r=await asyncio.to_thread(process,data,candidates[0].name,set(FORMATS),int(DB.get('max_configs','100')),True,os.getenv('NPVT_WHITEBOX_BLOB_FILE'),True,True)
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

import os
import re
import base64
import hashlib
import tempfile
import uvicorn
import gc
import time
import json
import secrets
from typing import Optional
from contextlib import asynccontextmanager
from datetime import datetime
from io import StringIO

from fastapi import FastAPI, File, UploadFile, Response, Cookie, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotnetfile import DotNetPE
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pydantic import BaseModel

HISTORY_FILE = "history.json"
ADMIN_CONFIG_FILE = "admin.json"
NEWS_FILE = "news.json"

SCANNED_HISTORY = []
NEWS_DATA = []
ADMIN_STATE = {"claimed": False, "token": None}

def load_data():
    global SCANNED_HISTORY, NEWS_DATA, ADMIN_STATE
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f: SCANNED_HISTORY = json.load(f)
        except: SCANNED_HISTORY = []
    if os.path.exists(NEWS_FILE):
        try:
            with open(NEWS_FILE, "r") as f: NEWS_DATA = json.load(f)
        except: NEWS_DATA = []
    if os.path.exists(ADMIN_CONFIG_FILE):
        try:
            with open(ADMIN_CONFIG_FILE, "r") as f: ADMIN_STATE = json.load(f)
        except: pass

def save_history():
    with open(HISTORY_FILE, "w") as f: json.dump(SCANNED_HISTORY, f)
def save_news():
    with open(NEWS_FILE, "w") as f: json.dump(NEWS_DATA, f)
def save_admin_state():
    with open(ADMIN_CONFIG_FILE, "w") as f: json.dump(ADMIN_STATE, f)

load_data()

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class NewsItem(BaseModel):
    title: str
    content: str
    image: str = ""

ASYNCRAT_SALT = bytes([191, 235, 30, 86, 251, 205, 151, 59, 178, 25, 2, 36, 48, 165, 120, 67, 0, 61, 86, 68, 210, 30, 98, 185, 212, 241, 128, 231, 230, 195, 57, 65])

def calculate_hashes(file_path):
    hashes = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
    try:
        with open(file_path, "rb") as f:
            data = f.read(10 * 1024 * 1024)
            for h in hashes.values(): h.update(data)
        return {k: v.hexdigest() for k, v in hashes.items()}
    except: return {}

class MalwareConfigExtractor:
    def __init__(self, file_path):
        self.file_path = file_path
        self.strings = []
        self.dotnet = None
    
    def load(self):
        self.strings = []
        try:
            self.dotnet = DotNetPE(self.file_path)
            us = self.dotnet.get_user_stream_strings()
            if us: self.strings.extend(us)
        except:
            pass

        try:
            with open(self.file_path, "rb") as f:
                data = f.read()

                # UTF-16 strings (wide chars)
                wide = re.findall(b'(?:[\x20-\x7E]\x00){5,}', data)
                for w in wide:
                    try:
                        s = w.decode('utf-16le').rstrip('\x00')
                        if len(s) >= 4: self.strings.append(s)
                    except: pass

                # ASCII strings (الأساسي)
                ascii_m = re.findall(b'[\x20-\x7E]{6,}', data)
                for a in ascii_m:
                    try:
                        s = a.decode('ascii')
                        if len(s) >= 6: self.strings.append(s)
                    except: pass
                
                # ASCII strings أقصر للـ domains و IPs
                short_ascii = re.findall(b'[\x20-\x7E]{4,}', data)
                for a in short_ascii:
                    try:
                        s = a.decode('ascii').strip()
                        # نضيف فقط إذا كان يشبه domain أو IP
                        if ('.' in s and len(s) >= 4) or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
                            self.strings.append(s)
                    except: pass

                # Base64 encoded strings
                b64_m = re.findall(b'[A-Za-z0-9+/=]{30,}', data)
                for b in b64_m:
                    try:
                        s = b.decode('ascii')
                        self.strings.append(s)
                    except: pass
                
                # Base64 أقصر (قد يكون port أو key قصير)
                b64_short = re.findall(b'[A-Za-z0-9+/=]{10,29}', data)
                for b in b64_short:
                    try:
                        s = b.decode('ascii')
                        self.strings.append(s)
                    except: pass
        except: pass

        self.strings = list(set([s.strip() for s in self.strings if s.strip() and len(s.strip()) >= 4]))


    def close(self):
        if self.dotnet: 
            try: self.dotnet.pe.close()
            except: pass
        self.dotnet = None
        gc.collect()

    def decrypt_aes_gcm(self, encrypted_b64, key_bytes, iv_bytes):
        try:
            raw = base64.b64decode(encrypted_b64)
            if len(raw) < 16: return None
            tag = raw[-16:]
            ciphertext = raw[:-16]
            cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv_bytes)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        except: return None

    def decrypt_async(self, c, k):
        try:
            p = base64.b64decode(k)
            km = hashlib.pbkdf2_hmac('sha1', p, ASYNCRAT_SALT, 50000, 96)
            data = base64.b64decode(c)
            cipher = AES.new(km[:32], AES.MODE_CBC, data[32:48])
            return unpad(cipher.decrypt(data[48:]), 16).decode('utf-8', errors='ignore')
        except: return None

    def derive_xworm_key(self, m):
        h = hashlib.md5(m.encode()).digest()
        k = bytearray(32)
        k[0:16] = h
        k[15:31] = h
        return bytes(k)

    def decrypt_xworm(self, e, k):
        try:
            return AES.new(k, AES.MODE_ECB).decrypt(base64.b64decode(e)).decode('utf-8', errors='ignore').strip(''.join(chr(i) for i in range(32)))
        except: return None

    def is_valid_config(self, s):
        if not s or len(s) < 1: return False
        
        blacklist_keywords = [
            'System.', 'Microsoft.', 'mscor', '.dll', '.exe', 'kernel',
            'user32', 'ntdll', 'avicap', 'Threading', 'Collections',
            'Runtime', 'Compiler', 'Diagnostics', 'ComponentModel',
            'Generic', 'Linq', 'Reflection', 'Drawing', 'Forms',
            'Security', 'Cryptography', 'Management', 'Principal',
            'CodeDom', 'WebServices', 'Protocols', 'VisualBasic',
            'My.', 'schtasks', 'powershell', 'Compression', 'Imaging',
            'Sockets', 'Interop', 'Design', 'Text', 'Services',
            'ApplicationServices', 'Devices', 'SoapHttp', 'schema'
        ]
        
        if any(keyword in s for keyword in blacklist_keywords):
            return False
        
        if len(s) > 100: return False
        
        bad_chars = ['~', '^', '{', '}', '|', '\\', '\x00']
        if any(c in s for c in bad_chars): return False
        
        if s.isdigit(): 
            return True
        
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
            if s in ["1.0.0.0", "14.0.0.0", "0.0.0.0"]:
                return False
            parts = [int(p) for p in s.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return True
        
        if "://" in s and ("http" in s.lower() or "tcp" in s.lower()):
            return True
        
        if "." in s and len(s) >= 4 and len(s) <= 50:
            parts = s.split(".")
            if len(parts) >= 2:
                tld = parts[-1]
                if tld.isalpha() and 2 <= len(tld) <= 6:
                    domain = parts[-2]
                    if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}$', domain):
                        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]{0,50}$', s):
                            return True
        
        if s == "USB.exe": 
            return True
        
        if s.startswith("<") and s.endswith(">") and 3 <= len(s) <= 20:
            return True
        
        if s.lower() == "localhost":
            return True
        
        return False

    def scan_umbral(self):
        potential_keys = []
        potential_ivs = []
        potential_encrypted = []

        for s in self.strings:
            if len(s) < 10: continue
            try:
                if re.match(r'^[A-Za-z0-9+/=]+$', s):
                    decoded = base64.b64decode(s)
                    l = len(decoded)
                    if l == 32: potential_keys.append(decoded)
                    elif l == 12: potential_ivs.append(decoded)
                    elif l > 16: potential_encrypted.append(s)
            except: pass

        if not potential_keys or not potential_ivs: return None

        for key in potential_keys:
            for iv in potential_ivs:
                found = False
                conf = {}
                for enc in potential_encrypted:
                    dec = self.decrypt_aes_gcm(enc, key, iv)
                    if dec and re.match(r'^[\x20-\x7E]+$', dec):
                        if "http" in dec or "discord" in dec: conf["C2"] = dec; found = True
                        elif dec.startswith("v"): conf["Version"] = dec
                        elif len(dec) == 20 and dec.isalnum(): conf["Mutex"] = dec
                if found:
                    conf.update({"Ping": "true", "Persistance": "true", "Anti VM": "true", "Melt File": "true"})
                    return {"Family": "UMBRALSTEALER", "Version": conf.get("Version", "v1.x"), "Config": conf}
        return None

    def scan_xworm(self):
        muts = [s for s in self.strings if 4 <= len(s) <= 40 and not re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", s)]
        
        all_results = []  # تخزين جميع النتائج الممكنة
        
        for m in muts:
            key = self.derive_xworm_key(m)
            x_res = []
            has_key_indicator = False
            
            for e in [s for s in self.strings if len(s) > 10 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", s)]:
                d = self.decrypt_xworm(e, key)
                if d and self.is_valid_config(d):
                    tag = "Value"
                    if d == "USB.exe": 
                        tag = "USBMM"
                    elif "://" in d or "." in d: 
                        tag = "Host"
                        has_key_indicator = True
                    elif d.isdigit():
                        if 1 <= int(d) <= 65535: 
                            tag = "Port"
                            has_key_indicator = True
                        else: 
                            tag = "Key"
                    elif "<" in d and ">" in d: 
                        tag = "Splitter"
                        has_key_indicator = True
                    x_res.append((tag, d))
            
            if has_key_indicator and len(x_res) > 0:
                all_results.append((m, x_res))
        
        # إذا وجدنا نتائج، نختار الأفضل (الأكثر اكتمالاً)
        if all_results:
            # ترتيب حسب عدد البيانات المهمة (Host + Port)
            def score_result(result):
                m, x_res = result
                score = 0
                has_host = any(tag == "Host" for tag, _ in x_res)
                has_port = any(tag == "Port" for tag, _ in x_res)
                has_key = any(tag == "Key" for tag, _ in x_res)
                has_splitter = any(tag == "Splitter" for tag, _ in x_res)
                
                if has_host: score += 10
                if has_port: score += 10
                if has_key: score += 5
                if has_splitter: score += 3
                score += len(x_res)  # عدد البيانات الإجمالي
                return score
            
            # اختيار أفضل نتيجة
            best_result = max(all_results, key=score_result)
            m, x_res = best_result
            
            conf = {}
            conf["RAT Version"] = "XWorm"
            conf["Mutex"] = m
            
            all_hosts = []
            all_ports = []
            
            for tag, val in x_res:
                if tag == "USBMM": 
                    conf["USBMM"] = val
                elif tag == "Host": 
                    all_hosts.append(val)
                elif tag == "Port": 
                    all_ports.append(val)
                elif tag == "Key": 
                    if "Traffic Encryption Key" not in conf: 
                        conf["Traffic Encryption Key"] = val
                    else: 
                        if val not in conf["Traffic Encryption Key"]:
                            conf["Traffic Encryption Key"] += "\n" + val
                elif tag == "Splitter": 
                    conf["SPL"] = val
            
            for s in self.strings:
                if len(s) < 4 or len(s) > 100:
                    continue
                
                if "System." in s or "Microsoft." in s or ".dll" in s:
                    continue
                
                if s.lower() == "localhost":
                    all_hosts.append(s)
                
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
                    if s not in ["1.0.0.0", "14.0.0.0", "0.0.0.0"]:
                        parts = s.split(".")
                        if all(0 <= int(p) <= 255 for p in parts):
                            all_hosts.append(s)
                
                elif "://" in s and ("http" in s.lower() or "tcp" in s.lower()):
                    if len(s) <= 100:
                        all_hosts.append(s)
                
                elif "." in s and not any(c in s for c in ['~', '^', '{', '}', '|', '\\']):
                    parts = s.split(".")
                    if len(parts) >= 2:
                        tld = parts[-1]
                        if tld.isalpha() and 2 <= len(tld) <= 6:
                            domain = parts[-2]
                            if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}$', domain):
                                if not any(kw in s for kw in ['Threading', 'Collections', 'Generic', 'Linq']):
                                    all_hosts.append(s)
                
                if s.isdigit() and 1 < int(s) < 65535 and len(s) <= 5:
                    all_ports.append(s)
            
            if all_hosts:
                urls = [h for h in all_hosts if "://" in h]
                domains = [h for h in all_hosts if "." in h and "://" not in h and h != "localhost"]
                ips = [h for h in all_hosts if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', h)]
                localhost = [h for h in all_hosts if h.lower() == "localhost"]
                
                if urls:
                    conf["C2s"] = urls[0]
                elif domains:
                    conf["C2s"] = domains[0]
                elif ips:
                    conf["C2s"] = ips[0]
                elif localhost:
                    conf["C2s"] = localhost[0]
            
            if all_ports:
                unique_ports = list(dict.fromkeys(all_ports))
                conf["Ports"] = "\n".join(unique_ports)
            
            return {"Family": "XWORM", "Version": "v5.x/v6.x", "Config": conf}
        
        return None

    def scan(self):
        if len(self.strings) < 10: return None

        res = self.scan_umbral()
        if res: return res

        res = self.scan_xworm()
        if res: return res

        nj = next((s for s in self.strings if "<- NjRAT" in s), None)
        if nj:
            conf = {"RAT Version": nj}
            
            all_hosts = []
            all_ports = []
            
            for s in self.strings:
                # تخطي strings غير صالحة
                if len(s) < 4 or len(s) > 100:
                    continue
                if "System." in s or "Microsoft." in s or ".dll" in s:
                    continue
                
                # IPs فقط
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
                    parts = s.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        all_hosts.append(s)
                
                # localhost
                elif s.lower() == "localhost":
                    all_hosts.append(s)
                
                # ddns domains
                elif ".ddns." in s and len(s) <= 50:
                    if not any(kw in s for kw in ['System', 'Microsoft']):
                        all_hosts.append(s)
                
                # Domains صحيحة
                elif "." in s and not any(c in s for c in ['~', '^', '{', '}', '|', '\\']):
                    parts = s.split(".")
                    if len(parts) >= 2:
                        tld = parts[-1]
                        if tld.isalpha() and 2 <= len(tld) <= 6:
                            domain = parts[-2]
                            if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}$', domain):
                                all_hosts.append(s)
                
                # Ports
                if s.isdigit() and 1 < int(s) < 65535 and len(s) <= 5:
                    all_ports.append(s)
                
                # Mutex
                if re.match(r'^[0-9a-f]{32}$', s):
                    conf["Mutex"] = s
            
            if all_hosts: 
                conf["C2s"] = "\n".join(list(set(all_hosts)))
            if all_ports: 
                conf["Ports"] = "\n".join(list(set(all_ports)))
            
            return {"Family": "NjRAT", "Version": nj, "Config": conf}

        mk = next((s for s in self.strings if len(s) == 44 and s.endswith('=') and not s.startswith('%')), None)
        if mk:
            conf = {"RAT Version": "AsyncRAT Engine", "Master Key": mk}
            
            # فك التشفير
            all_hosts = []
            all_ports = []
            all_paths = []
            all_settings = []
            
            candidates = [s for s in self.strings if len(s) > 40 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", s)]
            for c in candidates:
                dec = self.decrypt_async(c, mk)
                if dec and self.is_valid_config(dec):
                    if dec.isdigit() and 1 <= int(dec) <= 65535: 
                        all_ports.append(dec)
                    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', dec) or "." in dec: 
                        all_hosts.append(dec)
                    elif "%" in dec: 
                        all_paths.append(dec)
                    elif dec.lower() in ["true", "false"]: 
                        all_settings.append(dec)
            
            # إضافة بيانات plaintext بفلترة صارمة
            for s in self.strings:
                # تخطي strings غير صالحة
                if len(s) < 4 or len(s) > 100:
                    continue
                if "System." in s or "Microsoft." in s or ".dll" in s:
                    continue
                
                # IPs
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
                    parts = s.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        all_hosts.append(s)
                
                # Domains صحيحة
                elif "." in s and not any(c in s for c in ['~', '^', '{', '}', '|', '\\']):
                    parts = s.split(".")
                    if len(parts) >= 2:
                        tld = parts[-1]
                        if tld.isalpha() and 2 <= len(tld) <= 6:
                            domain = parts[-2]
                            if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}$', domain):
                                all_hosts.append(s)
                
                # Ports
                if s.isdigit() and 1 < int(s) < 65535 and len(s) <= 5:
                    all_ports.append(s)
            
            if all_hosts: conf["C2s"] = "\n".join(list(set(all_hosts)))
            if all_ports: conf["Ports"] = "\n".join(list(set(all_ports)))
            if all_paths: conf["Install Path"] = "\n".join(list(set(all_paths)))
            if all_settings: conf["Settings"] = "\n".join(list(set(all_settings)))
            
            if len(conf) > 2:  # أكثر من RAT Version + Master Key
                return {"Family": "AsyncRAT", "Version": "Latest", "Config": conf}

        return None

def generate_export_content(mode):
    out = StringIO()
    for item in SCANNED_HISTORY:
        cfg = item.get("malware", {}).get("Config", {})
        hosts = cfg.get("C2s") or cfg.get("C2") or cfg.get("Host")
        port = cfg.get("Ports") or cfg.get("Port")
        key = cfg.get("Traffic Encryption Key") or cfg.get("Master Key")
        if not hosts: continue
        h = str(hosts).split('\n')[0].strip()
        p = str(port or "80").split('\n')[0].strip()
        k = str(key or "NULL")
        if mode == "host_port": out.write(f"{h}:{p}\n")
        elif mode == "host_port_key": out.write(f"{h}:{p}:{k}\n")
    return out.getvalue()

@app.get("/auth/status")
def auth_status(hdoom_admin: Optional[str] = Cookie(None)):
    return {"claimed": ADMIN_STATE["claimed"], "is_admin": hdoom_admin == ADMIN_STATE.get("token")}

@app.post("/auth/claim")
def claim_admin(response: Response):
    if ADMIN_STATE["claimed"]: return {"status": "error", "message": "Already claimed"}
    token = secrets.token_hex(64)
    ADMIN_STATE["claimed"] = True
    ADMIN_STATE["token"] = token
    save_admin_state()
    response.set_cookie(key="hdoom_admin", value=token, max_age=31536000, httponly=False)
    return {"status": "success"}

@app.post("/api/extract")
async def extract_config(file: UploadFile = File(...)):
    tmp_path = None
    extractor = None
    start = time.time()
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        
        hashes = calculate_hashes(tmp_path)
        extractor = MalwareConfigExtractor(tmp_path)
        extractor.load()
        res = extractor.scan()
        
        data = {
            "id": int(time.time() * 1000),
            "status": "success" if res else "clean",
            "meta": {
                "filename": file.filename,
                "size": f"{os.stat(tmp_path).st_size} B",
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "time": f"{(time.time()-start)*1000:.2f}ms"
            },
            "hashes": hashes,
            "malware": res
        }
        if res:
            SCANNED_HISTORY.append(data)
            save_history()
        return JSONResponse(data)
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)})
    finally:
        if extractor: extractor.close()
        try: os.unlink(tmp_path)
        except: pass

@app.get("/api/history")
def get_history(): return SCANNED_HISTORY

@app.delete("/api/history/all")
def delete_all(hdoom_admin: Optional[str] = Cookie(None)):
    if hdoom_admin != ADMIN_STATE.get("token"): raise HTTPException(403)
    global SCANNED_HISTORY
    SCANNED_HISTORY = []
    save_history()
    return {"status": "cleared"}

@app.delete("/api/history/{item_id}")
def delete_item(item_id: int, hdoom_admin: Optional[str] = Cookie(None)):
    if hdoom_admin != ADMIN_STATE.get("token"): raise HTTPException(403)
    global SCANNED_HISTORY
    SCANNED_HISTORY = [x for x in SCANNED_HISTORY if x["id"] != item_id]
    save_history()
    return {"status": "deleted"}

@app.get("/api/export")
def export_data(mode: str, hdoom_admin: Optional[str] = Cookie(None)):
    if hdoom_admin != ADMIN_STATE.get("token"): raise HTTPException(403)
    if mode == "all": return JSONResponse(SCANNED_HISTORY)
    content = generate_export_content(mode)
    return Response(content=content, media_type="text/plain", headers={"Content-Disposition": f"attachment; filename=hdoom_{mode}.txt"})

@app.get("/api/news")
def get_news(): return JSONResponse(NEWS_DATA)

@app.post("/api/news")
def add_news(item: NewsItem, hdoom_admin: Optional[str] = Cookie(None)):
    if hdoom_admin != ADMIN_STATE.get("token"): raise HTTPException(403)
    NEWS_DATA.insert(0, {**item.dict(), "id": int(time.time()*1000), "views": 0, "date": datetime.now().strftime("%Y-%m-%d")})
    save_news()
    return {"status": "success"}

@app.delete("/api/news/{news_id}")
def delete_news(news_id: int, hdoom_admin: Optional[str] = Cookie(None)):
    if hdoom_admin != ADMIN_STATE.get("token"): raise HTTPException(403)
    global NEWS_DATA
    NEWS_DATA = [n for n in NEWS_DATA if n["id"] != news_id]
    save_news()
    return {"status": "deleted"}

@app.post("/api/news/{news_id}/view")
def view_news(news_id: int):
    for n in NEWS_DATA:
        if n["id"] == news_id:
            n["views"] += 1
            save_news()
            return {"status": "ok", "views": n["views"]}
    return {"status": "error"}

@app.get("/")
async def read_index(): return FileResponse('public/index.html')

app.mount("/static", StaticFiles(directory="public"), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
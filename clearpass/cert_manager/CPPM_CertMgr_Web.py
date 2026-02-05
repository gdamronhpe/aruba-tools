#!/usr/bin/env python3
import os, time, json, datetime, threading, urllib.parse, secrets, webbrowser, warnings, socket, tempfile, pathlib, textwrap, time, re
from typing import List, Dict, Any
from flask import Flask, request, jsonify, make_response, session, render_template_string, send_file, abort
import requests
from dateutil.parser import UnknownTimezoneWarning
from dateutil import tz, parser as dparser
import atexit, signal
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
import base64


warnings.filterwarnings("ignore", category=UnknownTimezoneWarning)

# -------------------- Helpers / constants --------------------
SERVICE_NAMES = ["RADIUS", "HTTPS(RSA)", "HTTPS(ECC)", "RadSec"]
REQUIRED_PRIVILEGES = {
    "#admin_restore",
    "%cppm_cert_trust_list",
    "%cppm_certificates",
    "?api_index",
    "?cppm_config",
    "?platform",
    "apigility",
}

def canonical_service_name(s: str) -> str:
    if not s: return s
    u = str(s).strip().upper()
    if "RADSEC" in u: return "RadSec"
    if "RADIUS" in u and "RADSEC" not in u: return "RADIUS"
    if "HTTPS" in u and "ECC" in u: return "HTTPS(ECC)"
    if "HTTPS" in u: return "HTTPS(RSA)"
    return s

_TZINFOS = {
    "UTC": tz.UTC, "Z": tz.UTC,
    "EST": tz.gettz("America/New_York"), "EDT": tz.gettz("America/New_York"),
    "CST": tz.gettz("America/Chicago"),  "CDT": tz.gettz("America/Chicago"),
    "MST": tz.gettz("America/Denver"),   "MDT": tz.gettz("America/Denver"),
    "PST": tz.gettz("America/Los_Angeles"), "PDT": tz.gettz("America/Los_Angeles"),
}

def parse_date(d: str):
    if not d: return None
    s = str(d).strip()
    if s.endswith("Z"): s = s[:-1] + "+00:00"
    try:
        return datetime.datetime.fromisoformat(s)
    except Exception:
        pass
    try:
        return dparser.parse(s, tzinfos=_TZINFOS)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ","%Y-%m-%dT%H:%M:%SZ","%Y-%m-%d %H:%M:%S","%Y-%m-%d"):
        try: return datetime.datetime.strptime(s, fmt)
        except Exception: continue
    return None

def first_of(obj: dict, keys):
    if not isinstance(obj, dict): return None
    for k in keys:
        if isinstance(k, (list, tuple)):
            cur = obj; ok = True
            for p in k:
                if not isinstance(cur, dict) or p not in cur: ok=False; break
                cur = cur[p]
            if ok and cur is not None: return cur
        else:
            if k in obj and obj[k] is not None: return obj[k]
    return None

def _normalize_name(val):
    if val is None: return None
    if isinstance(val, dict):
        for k in ("common_name","cn","name"):
            if k in val and val[k]: return str(val[k])
        try:
            return ", ".join(f"{k}={v}" for k,v in val.items() if v is not None)
        except Exception:
            return str(val)
    return str(val)

def local_url(host: str, port: int, path: str) -> str:
    return f"http://{host}:{port}{path}"

def get_lan_ip() -> str:
    # best-effort to choose a LAN ip ClearPass might reach
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# -------------------- ClearPass REST wrapper --------------------
class ClearPassAPI:
    def __init__(self, base_url: str, client_id: str = None, client_secret: str = None, token: str = None, verify_tls=True):
        self.base = base_url.rstrip("/")
        if not self.base.startswith("http"):
            self.base = "https://" + self.base
        self.client_id = client_id; self.client_secret = client_secret
        self.session = requests.Session(); self.session.verify = verify_tls
        self._token = token.strip() if token else None
        self._token_static = bool(self._token)
        self._exp = 0

    def _now(self): return int(time.time())

    def _auth_header_value(self, token: str) -> str:
        t = (token or "").strip()
        if not t: return ""
        if " " in t: return t
        return f"Bearer {t}"

    def token(self):
        if self._token_static:
            auth = self._auth_header_value(self._token)
            if not auth:
                raise RuntimeError("Empty token provided")
            self.session.headers.update({"Authorization": auth, "accept": "application/json", "content-type": "application/json"})
            return self._token
        if self._token and self._now() < self._exp - 10: return self._token
        url = f"{self.base}/api/oauth"
        r = self.session.post(url, json={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }, timeout=30)
        if r.status_code not in (200,201):
            raise RuntimeError(f"OAuth failed {r.status_code}: {r.text[:400]}")
        j = r.json(); tok = j.get("access_token") or j.get("token")
        if not tok: raise RuntimeError(f"No token in oauth response: {j}")
        self._token = tok; self._exp = self._now() + int(j.get("expires_in",3600))
        self.session.headers.update({"Authorization": f"Bearer {tok}","accept": "application/json","content-type": "application/json"})
        return tok

    def _extract_list(self, obj):
        if obj is None: return []
        if isinstance(obj,(list,tuple)): return list(obj)
        if not isinstance(obj,dict): return []
        if "results" in obj and isinstance(obj["results"],(list,tuple)): return list(obj["results"])
        if "_embedded" in obj:
            emb = obj["_embedded"]
            if isinstance(emb,dict) and "items" in emb and isinstance(emb["items"],(list,tuple)): return list(emb["items"])
            if isinstance(emb,(list,tuple)): return list(emb)
        if "items" in obj and isinstance(obj["items"],(list,tuple)): return list(obj["items"])
        return []

    def _get(self, path, params=None):
        self.token()
        url = f"{self.base}{path}"
        r = self.session.get(url, params=params, timeout=30)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {path} -> {r.status_code}: {r.text[:500]}")
        try: return r.json()
        except Exception: return {"text": r.text}

    def list_cluster_servers(self):
        data = self._get("/api/cluster/server")
        out = []
        for s in self._extract_list(data):
            if isinstance(s,dict):
                out.append({
                    "uuid": s.get("server_uuid") or s.get("uuid") or s.get("id"),
                    "name": s.get("name") or s.get("server_dns_name") or s.get("hostname"),
                    "ip_address": s.get("management_ip") or s.get("server_ip") or s.get("ip_address") or s.get("mgmt_ip"),
                    "fqdn": s.get("fqdn") or s.get("server_dns_name") or s.get("dns_name"),
                    "raw": s
                })
        return out

    def get_server_cert_by_name(self, server_uuid: str, cert_name: str):
        svc = canonical_service_name(cert_name)
        self.token()
        url = f"{self.base}/api/server-cert/name/{urllib.parse.quote(server_uuid,'')}/{urllib.parse.quote(svc,'')}"
        r = self.session.get(url, timeout=30)
        if r.status_code == 200:
            try: j = r.json()
            except Exception: j = {"raw_text": r.text}
            rec = j["results"][0] if (isinstance(j,dict) and isinstance(j.get("results"),list) and j["results"]) else j
            return {
                "id": rec.get("id") or rec.get("certificate_id") or svc,
                "service": svc,
                "server_uuid": server_uuid,
                "subject": rec.get("subject") or rec.get("subject_dn") or rec.get("subjectName"),
                "issuer":  rec.get("issuer")  or rec.get("issuer_dn"),
                "valid_from": rec.get("valid_from") or rec.get("notBefore") or rec.get("validFrom"),
                "valid_to":   rec.get("valid_to")   or rec.get("notAfter")  or rec.get("validTo"),
                "thumbprint": rec.get("thumbprint") or rec.get("fingerprint") or rec.get("sha1"),
                "pem": rec.get("pem") or rec.get("certificate") or None,
                "raw": rec
            }
        try: err = r.json()
        except Exception: err = {"status": r.status_code, "text": r.text[:500]}
        return {
            "id": svc, "service": svc, "server_uuid": server_uuid,
            "subject": "No certificate", "issuer": None,
            "valid_from": None, "valid_to": None, "thumbprint": None, "pem": None,
            "raw": {"_error": err}
        }

    def list_member_named_certs(self, server_uuid: str, names: List[str]):
        out, seen = [], set()
        for n in (names or SERVICE_NAMES):
            c = canonical_service_name(n)
            if c in seen: continue
            seen.add(c)
            out.append(self.get_server_cert_by_name(server_uuid, c))
        return out

    def put_server_cert_pkcs12(self, server_uuid: str, service_name: str, pfx_url: str, passphrase: str):
        svc = canonical_service_name(service_name)
        self.token()
        url = f"{self.base}/api/server-cert/name/{urllib.parse.quote(server_uuid,'')}/{urllib.parse.quote(svc,'')}"
        body = {"pkcs12_file_url": pfx_url}
        if passphrase:
            body["pkcs12_passphrase"] = passphrase
        r = self.session.put(url, json=body, timeout=60)
        try:
            j = r.json()
        except Exception:
            j = {"text": r.text}
        return r.status_code, j

    # ---- Trust list: add CA/intermediate PEM ----
    def add_trust_cert(self, cert_pem: str, usage: str = "Others", enabled: bool = True):
        self.token()
        url = f"{self.base}/api/cert-trust-list"
        body = {
            "cert_usage": [usage] if isinstance(usage, str) else usage,
            "cert_file": cert_pem,
            "enabled": bool(enabled),
        }
        r = self.session.post(url, json=body, timeout=60)
        try:
            j = r.json()
        except Exception:
            j = {"text": r.text}
        return r.status_code, j

    def list_trust_certs(self):
        # Returns the list of trust list certificates
        data = self._get("/api/cert-trust-list")
        return self._extract_list(data)

    def list_privileges(self):
        data = self._get("/api/oauth/privileges")
        if isinstance(data, dict) and isinstance(data.get("privileges"), list):
            return data.get("privileges")
        return []

# -------------------- Flask app & file hosting --------------------
app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True
app.secret_key = os.environ.get("CPPM_CERTMGR_SECRET", secrets.token_hex(16))
_APIS: Dict[str, ClearPassAPI] = {}

# simple in-memory registry of uploaded files (auto-clean)
#UPLOAD_DIR = pathlib.Path(tempfile.gettempdir()) / "cppm_certmgr_uploads"
#UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
# Store uploads in a subfolder next to the script so files are directly reachable on the host
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
UPLOAD_DIR = pathlib.Path(tempfile.gettempdir()) / "cppm_certmgr_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Debug: print routes on boot
def _print_routes():
    try:
        print("=== Registered routes ===")
        for r in app.url_map.iter_rules():
            print(f"{r.methods} {r.rule}")
        print("=========================")
    except Exception as e:
        print("Route print failed:", e)
_print_routes()

def _cleanup_uploaded_files():
    # remove only files we created and clear the registry
    for token, meta in list(_uploaded.items()):
        try:
            pathlib.Path(meta["path"]).unlink(missing_ok=True)
        except Exception:
            pass
        _uploaded.pop(token, None)

# Ensure we remove created files on normal exit
atexit.register(lambda: _cleanup_uploaded_files())

# Also attempt to clean up on SIGINT / SIGTERM
def _sig_handler(signum, frame):
    try:
        _cleanup_uploaded_files()
    finally:
        # ensure process exits
        os._exit(0)

for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _sig_handler)
    except Exception:
        pass

_uploaded: Dict[str, Dict[str, Any]] = {}  # token -> {path, ctime}

def _get_api():
    sid = session.get("sid")
    if not sid or sid not in _APIS:
        raise RuntimeError("Not connected.")
    return _APIS[sid]

def _cleanup_loop():
    while True:
        try:
            now = time.time()
            for token, meta in list(_uploaded.items()):
                if now - meta["ctime"] > 3600:  # 1 hour TTL
                    try:
                        pathlib.Path(meta["path"]).unlink(missing_ok=True)
                    except Exception:
                        pass
                    _uploaded.pop(token, None)
        except Exception:
            pass
        time.sleep(120)
threading.Thread(target=_cleanup_loop, daemon=True).start()

@app.route("/")
def index():
    # r-string so JS backslashes don't get eaten by Python
    return render_template_string(r"""
<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ClearPass Certificate Manager (Web)</title>
<style>

 body{font-family:ui-sans-serif,system-ui,Arial,sans-serif;margin:16px}
 .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
 input[type=text],input[type=password]{padding:8px;min-width:240px}
 button{padding:8px 12px;cursor:pointer}
 table{border-collapse:collapse;width:100%;margin-top:0}
 th,td{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;user-select:none}
 th{cursor:pointer}
#modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.45);
  align-items: center; justify-content: center; }
#modal.show { display: flex}
 tr:hover{background:#fafafa}
 .muted{color:#666}
 .topbar{position:sticky;top:0;background:#fff;padding:10px 0;border-bottom:1px solid #eee;z-index:10}
 .th-sort-asc::after{content:" ^";font-size:12px;color:#666}
 .th-sort-desc::after{content:" v";font-size:12px;color:#666}
 .badge{display:inline-block;padding:2px 6px;border-radius:4px;background:#eef}
 .danger{color:#b42318}
 .dim{color:#777}
 .pill{border:1px solid #ccc;border-radius:999px;padding:4px 10px}
 .btn-danger{background:#b42318;color:white;border:none}
 .btn{border:1px solid #ccc;background:#fff}
 .hidden{display:none}
 .topbar-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;align-items:start}
 .panel{border:1px solid #e6e6e6;border-radius:12px;padding:12px;background:#fafafa}
 .panel-title{font-weight:600;margin-bottom:8px}
 .stack{display:flex;flex-direction:column;gap:10px}
 .status-line{margin-top:6px}
/* --- modal overlay + card (correct selectors) --- */
#modal{
  position:fixed; inset:0; display:none;
  background:rgba(0,0,0,.55);           /* dim background */
  align-items:center; justify-content:center;
  z-index:2147483647;
}
#modal.show{ display:flex; }             /* if you toggle .show in JS */
body.modal-open{ overflow:hidden; }

#modalCard, .modal-card{                 /* support either id OR class */
  position:relative;
  background:#fff !important;            /* ensure opaque white */
  color:#222;
  border:1px solid #dcdcdc;
  border-radius:12px;
  box-shadow:0 18px 48px rgba(0,0,0,.35),0 0 0 1px rgba(0,0,0,.05);
  width:min(92vw,720px);
  max-height:80vh;
  overflow:auto;
  padding:20px 24px;
}

.modal-info{
  max-height:50vh;
  overflow:auto;
  white-space:pre-wrap;
  border:1px solid #eee;
  border-radius:6px;
  padding:10px;
  margin:12px 0;
  background:#fafafa;
}

/* inputs inside modal */
#modal input[type=text],
#modal input[type=password]{
  width:100%;
  padding:10px;
  margin:6px 0 12px 0;
  border:1px solid #cfcfcf;
  border-radius:8px;
  box-sizing:border-box;
  background:#fff;
}
.res-row{display:grid;grid-template-columns: 24px 1fr auto;gap:8px;align-items:start;padding:8px;border:1px solid #eee;border-radius:8px;margin:6px 0;background:#fafafa}
.res-ok{color:#137333}
.res-bad{color:#b42318}
.badge-min{font:12px/1 ui-sans-serif,system-ui,Arial;padding:2px 6px;border-radius:999px;border:1px solid #ddd;background:#fff;white-space:nowrap}
.hidden{display:none}
.details-box{white-space:pre-wrap;background:#fafafa;border:1px solid #eee;padding:10px;border-radius:8px;font:12px/1.4 ui-monospace,Consolas,Menlo,monospace}
</style>
</head><body>
<h2 style="margin:0 0 10px 0;">ClearPass Certificate Manager</h2>
<div class="topbar">
  <div class="topbar-grid">
    <div class="panel">
      <div class="panel-title">Step 1: Connect</div>
      <div class="stack">
        <div class="row">
          <strong>Publisher:</strong><input id="host" type="text" placeholder="cppm-pub.example.com or https://pub">
        </div>
        <div class="row">
          <strong>Token:</strong><input id="token" type="password" placeholder="ClearPass API token">
        </div>
        <div class="row">
          <label><input id="verify" type="checkbox" checked> Verify TLS</label>
          <button id="connectBtn" class="btn">Connect</button>
        </div>
        <div class="status-line"><span id="status" class="muted"></span></div>
      </div>
    </div>

    <!-- Replacement section is hidden until connected -->
    <div id="replaceSection" class="panel hidden">
      <div class="panel-title">Step 2: Upload & Host</div>
      <div class="stack">
        <div class="row">
          <input type="file" id="pfxFile" accept=".pfx,.p12,application/x-pkcs12" disabled>
          <input type="password" id="pfxPass" placeholder="PFX passphrase (optional)" disabled>
          <button id="uploadBtn" class="btn" disabled>Upload & Host</button>
        </div>
        <div class="row">
          <span id="fileStatus" class="muted"></span>
        </div>
      </div>
    </div>

    <div id="trustSection" class="panel hidden">
      <div class="panel-title">Step 3: Trust List</div>
      <div class="stack">
        <div class="row">
          <button id="importTrustBtn" class="btn" disabled>Import Trust</button>
          <span class="dim">Usage: <code>Others</code></span>
        </div>
        <div class="row">
          <span id="trustStatus" class="muted"></span>
        </div>
      </div>
    </div>

    <div id="replaceSection2" class="panel hidden">
      <div class="panel-title">Step 4: Replace</div>
      <div class="stack">
        <div class="row">
          <label><input id="selAll" type="checkbox"> Select visible</label>
          <button id="replaceBtn" class="btn-danger" disabled>Replace Certificate...</button>
        </div>
        <div class="row">
          <span class="dim">Select rows to target, then click Replace.</span>
        </div>
      </div>
    </div>
  </div>
</div>

<table id="grid" style="display:none">
  <thead>
    <tr id="filterRow" style="display:none">
      <td colspan="8">
        <div class="row" style="margin-top:8px;margin-bottom:0;">
          <strong>Filter services:</strong>
          <label><input type="checkbox" class="svc" value="RADIUS" checked> RADIUS</label>
          <label><input type="checkbox" class="svc" value="HTTPS(RSA)" checked> HTTPS(RSA)</label>
          <label><input type="checkbox" class="svc" value="HTTPS(ECC)" checked> HTTPS(ECC)</label>
          <label><input type="checkbox" class="svc" value="RadSec" checked> RadSec</label>
        </div>
      </td>
    </tr>
    <tr>
      <th data-key="__check" style="width:28px;"><input type="checkbox" id="hdrCheck"></th>
      <th data-key="server_label">Server</th>
      <th data-key="service">Service</th>
      <th data-key="enabled_sort">Enabled</th>
      <th data-key="subject">Subject</th>
      <th data-key="issuer">Issuer</th>
      <th data-key="issued_ts">Issued Date</th>
      <th data-key="expiry_ts">Expiry Date</th>
    </tr>
  </thead>
  <tbody></tbody>
</table>

<h3 id="detailHeader" class="hidden">Details</h3>
<div id="details" class="details-box hidden"></div>
<div class="row hidden" id="detailBtns" style="margin-top:8px;">
  <button id="copyPemBtn" class="btn">Copy PEM</button>
</div>

<!-- Confirmation Modal -->
<!-- Results Modal -->
<div id="resultModal" class="show hidden" style="position:fixed;inset:0;display:none;background:rgba(0,0,0,.55);align-items:center;justify-content:center;z-index:2147483647;">
  <div class="modal-card" style="width:min(92vw,800px);max-height:80vh;overflow:auto;">
    <h3>Certificate Replacement Results</h3>
    <div id="resultList"></div>
    <hr style="margin:12px 0;">
    <details>
      <summary style="cursor:pointer">Raw JSON</summary>
      <pre id="resultJson" style="background:#0b1020;color:#cde; padding:12px;border-radius:8px;overflow:auto;"></pre>
    </details>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px;">
      <button id="resultClose" class="btn">Close</button>
    </div>
  </div>
</div>
<div id="modal">
  <div class="modal-card">
    <h3 class="danger">Confirm Certificate Replacement</h3>
    <div id="modalBody" style="max-height:50vh;overflow:auto;white-space:pre-wrap;border:1px solid #eee;padding:10px;border-radius:6px;background:#fafafa"></div>
    <div style="margin-top:10px;">
      <label>PKCS#12 URL ClearPass should fetch (override if hosting elsewhere):</label><br/>
      <input type="text" id="modalUrl" style="width:100%;padding:8px" />
    </div>
    <div style="margin-top:10px;">
      <label>Enter passphrase:</label><br/>
      <input type="password" id="modalPass" style="width:100%;padding:8px" />
    </div>
    <div style="margin-top:10px;">
      Type <b id="confirmWord">CONFIRM</b> or the number <b id="confirmCount"></b> to proceed:
      <input type="text" id="confirmInput" class="pill" style="margin-left:8px;">
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px;">
      <button id="modalCancel" class="btn">Cancel</button>
      <button id="modalDo" class="btn-danger" disabled>Replace Now</button>
    </div>
  </div>
</div>
<footer style="
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        height: 32px;
        background-color: rgba(0,0,0,0.05);
        border-top: 1px solid #ccc;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0 12px;
        font-size: 13px;
        color: #666;
    ">
    <div>
        <button id="killBtnFooter" class="btn-danger" style="padding:4px 10px; font-size:12px;">Kill Script</button>
    </div>
    <div style="text-align:right;">
        <span>v0.1 | gregory.damron@hpe.com</span>
    </div>
</footer>
<script>
function $(id){return document.getElementById(id)}
function setStatus(m){$('status').textContent=m||''}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function svcFilter(){return new Set(Array.from(document.querySelectorAll(".svc:checked")).map(b=>b.value))}
function showModal(){ $('modal').classList.add('show'); }
function hideModal(){ $('modal').classList.remove('show'); }

// Ensure a single source of truth for the .svc filter controls: relocate any
// stray controls into the table's filterRow (or create the row if missing).
document.addEventListener('DOMContentLoaded', ()=>{
  const grid = document.getElementById('grid');
  const tableFilter = document.getElementById('filterRow');
  // Gather .svc controls that are NOT inside the table (stray duplicates)
  const stray = Array.from(document.querySelectorAll('.svc')).filter(cb => !cb.closest('#grid'));

  if (tableFilter) {
    // Move stray controls into the table's filter row container
    const container = tableFilter.querySelector('div.row') || tableFilter;
    stray.forEach(cb=>{
      const label = cb.closest('label') || cb.parentElement;
      if (label) container.appendChild(label);
    });
  } else if (grid && stray.length) {
    // If table has no filterRow yet, create it and move the stray controls in
    const thead = grid.querySelector('thead') || grid;
    const tr = document.createElement('tr'); tr.id = 'filterRow'; tr.style.display = 'none';
    const td = document.createElement('td'); td.colSpan = 8;
    const div = document.createElement('div'); div.className = 'row'; div.style.marginTop = '8px'; div.style.marginBottom = '0';
    const strong = document.createElement('strong'); strong.textContent = 'Filter services:';
    div.appendChild(strong);
    stray.forEach(cb=>{
      const label = cb.closest('label') || cb.parentElement;
      if (label) div.appendChild(label);
    });
    td.appendChild(div); tr.appendChild(td); thead.appendChild(tr);
  }

  // Attach idempotent handlers to .svc inputs that are now inside the table
  const fr = document.getElementById('filterRow');
  if (fr) {
    fr.querySelectorAll('.svc').forEach(cb=>{
      if (!cb._hasFilterHandler){
        cb.addEventListener('change', ()=>{ applyFiltersAndSort(); $('selAll').checked=false; });
        cb._hasFilterHandler = true;
      }
    });
  }
});

function asJSON(obj, indent=2){
  try{ return JSON.stringify(obj, null, indent); }catch(_){ return String(obj); }
}
function safeParse(maybeJSON){
  if (typeof maybeJSON !== 'string') return maybeJSON;
  try{ return JSON.parse(maybeJSON); }catch(_){ return maybeJSON; }
}
function showResultsModal(payload){
  // payload is the response from /api/replace: {results: [...]}
  const modal = $('resultModal');
  const list = $('resultList');
  const raw  = $('resultJson');

  // build rows
  list.innerHTML = '';
  (payload.results || []).forEach(r=>{
    const ok = (r.status>=200 && r.status<300);
    const msgObj = safeParse(r.message);
    const prettyMsg = typeof msgObj === 'object' ? asJSON(msgObj, 2) : String(msgObj||'');
    const div = document.createElement('div');
    div.className = 'res-row';
    div.innerHTML = `
      <div class="${ok?'res-ok':'res-bad'}">${ok?'OK':'X'}</div>
      <div>
        <div><strong>${esc(r.server_label||'')}</strong>  -  ${esc(r.service||'')}</div>
        <pre style="margin:6px 0 0;white-space:pre-wrap">${esc(prettyMsg)}</pre>
      </div>
      <div><span class="badge-min">${r.status ?? ''}</span></div>
    `;
    list.appendChild(div);
  });

  raw.textContent = asJSON(payload, 2);

  modal.classList.add('show');
  modal.classList.remove('hidden');
  modal.style.display = 'flex';
}
function hideResultsModal(){
  const modal = $('resultModal');
  modal.classList.remove('show');
  modal.classList.add('hidden');
  modal.style.display = 'none';
}
$('resultClose').addEventListener('click', hideResultsModal);
                                  
async function postJSON(url, body){
  const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
  if(!r.ok) throw new Error(await r.text()); return await r.json();
}
async function postForm(url, formData){
  const r = await fetch(url,{method:'POST',body:formData});
  if(!r.ok) throw new Error(await r.text()); return await r.json();
}

let allRows=[], viewRows=[], selectedIndex=-1, sortKey='server_label', sortDir='asc';
let hostedUrl='', hostedToken='', uploadedPass='';
let hostedTokenForTrust = '';

function applyFiltersAndSort(){
  const allowed = svcFilter();
  viewRows = allRows.filter(r => allowed.has(r.service));
  viewRows.sort((a,b)=>{
    const ak = a[sortKey], bk = b[sortKey];
    if (sortKey==='server_label' || sortKey==='service' || sortKey==='subject' || sortKey==='issuer'){
      const as = (ak||'').toString().toLowerCase(), bs = (bk||'').toString().toLowerCase();
      if (as < bs) return (sortDir==='asc')?-1:1;
      if (as > bs) return (sortDir==='asc')? 1:-1;
      return 0;
    }
    if (ak==null && bk==null) return 0;
    if (ak==null) return (sortDir==='asc') ? 1 : -1;
    if (bk==null) return (sortDir==='asc') ? -1 : 1;
    if (ak < bk) return (sortDir==='asc') ? -1 : 1;
    if (ak > bk) return (sortDir==='asc') ? 1 : -1;
    return 0;
  });
  renderTable();
  updateReplaceEnabled();
}

function clearSortIndicators(){
  document.querySelectorAll('#grid thead th').forEach(th=>{
    th.classList.remove('th-sort-asc','th-sort-desc');
  });
}
function setSortIndicator(th){
  th.classList.add(sortDir==='asc' ? 'th-sort-asc' : 'th-sort-desc');
}

function attachHeaderSorting(){
  document.querySelectorAll('#grid thead th').forEach(th=>{
    th.addEventListener('click', ()=>{
      const key = th.getAttribute('data-key');
      if (!key || key==='__check') return;
      if (sortKey === key){
        sortDir = (sortDir === 'asc') ? 'desc' : 'asc';
      } else {
        sortKey = key; sortDir = 'asc';
      }
      clearSortIndicators(); setSortIndicator(th);
      applyFiltersAndSort();
    });
  });
}

function renderTable(){
  const grid=$('grid'), tbody=grid.querySelector('tbody');
  tbody.innerHTML='';
  viewRows.forEach((r,i)=>{
    const tr=document.createElement('tr');
    tr.innerHTML = `
      <td><input type="checkbox" class="rowCheck" data-i="${i}"></td>
      <td>${esc(r.server_label||'')}</td>
      <td>${esc(r.service||'')}</td>
      <td>${esc(r.enabled_str||'')}</td>
      <td>${esc(r.subject||'')}</td>
      <td>${esc(r.issuer||'')}</td>
      <td>${esc(r.issued_date||'')}</td>
      <td>${esc(r.expiry_date||'')}</td>`;
    tr.addEventListener('click', (ev)=>{ if(ev.target.tagName!=="INPUT"){ selectRow(i) } });
    tbody.appendChild(tr);
  });
  grid.style.display = viewRows.length ? '' : 'none';
  const filterRow = document.getElementById('filterRow');
  if (filterRow) {
    const show = viewRows.length > 0;
    // For a table-row we toggle its display to '' (default) or 'none'.
    if (show) {
      filterRow.style.display = '';
      // Attach handlers to the checkboxes inside the filter row (idempotent)
      filterRow.querySelectorAll('.svc').forEach(cb=>{
        if (!cb._hasFilterHandler){
          cb.addEventListener('change', ()=>{ applyFiltersAndSort(); $('selAll').checked=false; });
          cb._hasFilterHandler = true;
        }
      });
    } else {
      filterRow.style.display = 'none';
    }
  }
  $('detailHeader').classList.add('hidden'); $('details').classList.add('hidden'); $('detailBtns').classList.add('hidden');
  selectedIndex=-1;

  // row checkboxes
  document.querySelectorAll('.rowCheck').forEach(ch=>{
    ch.addEventListener('change', updateReplaceEnabled);
  });
}

function selectRow(i){
  selectedIndex=i; const r=viewRows[i];
  $('detailHeader').classList.remove('hidden'); $('details').classList.remove('hidden'); $('detailBtns').classList.remove('hidden');
  const parts=[];
  parts.push('Server: ' + (r.server_label||''));
  parts.push('Service: ' + (r.service||''));
  parts.push('Server UUID: ' + (r.server_uuid||''));
  parts.push('Enabled: ' + (r.enabled_str||''));
  parts.push('Subject: ' + (r.subject||''));
  parts.push('Issuer: ' + (r.issuer||''));
  parts.push('Issued Date: ' + (r.issued_date||''));
  parts.push('Expiry Date: ' + (r.expiry_date||''));
  parts.push('');
  parts.push('PEM:');
  parts.push(r.pem || '');
  parts.push('');
  parts.push('Raw JSON:');
  parts.push(JSON.stringify(r.raw||{}, null, 2));
  $('details').textContent = parts.join('\n');
}

$('copyPemBtn').addEventListener('click', async ()=>{
  if(selectedIndex<0) return; const pem=viewRows[selectedIndex]?.pem||''; if(!pem){setStatus('No PEM available'); return;}
  await navigator.clipboard.writeText(pem); setStatus('PEM copied to clipboard');
});

// Filter checkbox handlers are attached idempotently when the filterRow is shown
// (keeps bindings local to the single filter row inside the table)

$('hdrCheck').addEventListener('change', (e)=>{
  const v = e.target.checked;
  document.querySelectorAll('.rowCheck').forEach(x=>{ x.checked=v; });
  updateReplaceEnabled();
});
$('selAll').addEventListener('change', (e)=>{
  const v = e.target.checked;
  document.querySelectorAll('.rowCheck').forEach(x=>{ x.checked=v; });
  updateReplaceEnabled();
});

function selectedTargets(){
  const t = [];
  document.querySelectorAll('.rowCheck').forEach(ch=>{
    if (ch.checked){
      const r = viewRows[parseInt(ch.dataset.i)];
      t.push({server_uuid: r.server_uuid, service: r.service, server_label: r.server_label});
    }
  });
  return t;
}
function updateReplaceEnabled(){
  const anySelected = selectedTargets().length > 0;
  const hasHosted = !!hostedUrl;          // set after successful upload
  $('replaceBtn').disabled = !(anySelected && hasHosted);
}

// ---- Connect & scan all services ----
$('connectBtn').addEventListener('click', async ()=>{
  try{
    setStatus('Connecting and scanning all services...');
    $('connectBtn').disabled = true;
    const host=$('host').value.trim(), token=$('token').value.trim(), verify=$('verify').checked;
    const j = await postJSON('/api/connect-and-scan', {host, token: token, verify_tls: verify});
    allRows = j.rows || [];
    sortKey='server_label'; sortDir='asc';
    document.querySelectorAll('#grid thead th').forEach(th=>th.classList.remove('th-sort-asc','th-sort-desc'));
    const th = document.querySelector('#grid thead th[data-key="server_label"]'); if (th) th.classList.add('th-sort-asc');
    applyFiltersAndSort();
    // Show replacement/upload UI and enable inputs now that we're connected
    try{
      $('replaceSection').classList.remove('hidden');
      $('pfxFile').disabled = false;
      $('pfxPass').disabled = false;
      $('uploadBtn').disabled = false;
      // enable the select-all checkbox so users can quickly pick visible rows
      const selAllEl = document.getElementById('selAll'); if (selAllEl) selAllEl.disabled = false;
    }catch(e){ console.warn('Failed to enable replace UI', e); }
    setStatus('Found ' + allRows.length + ' certificate items');
    if (!document.body._hdrInit){ attachHeaderSorting(); document.body._hdrInit = true; }
  }catch(e){
    console.error(e);
    // Try to show structured error {error, hint, details}
    let msg = e.message || String(e);
    try {
      const j = JSON.parse(msg);
      const parts = [j.error || 'Failed'];
      if (j.hint) parts.push(' -  ' + j.hint);
      setStatus(parts.join(' '));
    } catch(_) {
      setStatus('Failed: ' + msg);
    }
  }finally{
    $('connectBtn').disabled=false;
  }
});

// ---- Upload & host PFX ----
$('uploadBtn').addEventListener('click', async ()=>{
  try{
    const f = $('pfxFile').files[0];
    if (!f){ $('fileStatus').textContent='Choose a .pfx/.p12 file first'; return; }
    const fd = new FormData();
    fd.append('pfx', f);
    const j = await postForm('/api/upload-pfx', fd);
    hostedUrl = j.file_url; hostedToken = j.token;
    hostedTokenForTrust = j.token;
    uploadedPass = $('pfxPass').value || '';
    $('fileStatus').textContent = 'Hosted: ' + hostedUrl;
    updateReplaceEnabled();  // < -  enable Replace if rows are already selected
    const trustSection = document.getElementById('trustSection'); if (trustSection) trustSection.classList.remove('hidden');
    const rs2 = document.getElementById('replaceSection2'); if (rs2) rs2.classList.remove('hidden');
    $('importTrustBtn').disabled = false;
    // Check if CA/intermediates already exist in the trust list
    try{
      $('trustStatus').textContent = 'Checking trust list...';
      const check = await postJSON('/api/check-trust-from-pfx', {
        pfx_token: hostedTokenForTrust,
        passphrase: $('pfxPass').value || ''
      });
      if (check.all_present){
        $('importTrustBtn').disabled = true;
        $('trustStatus').textContent = 'CA/intermediate certificates already present in trust list. Import disabled.';
      } else if (check.matched > 0){
        $('trustStatus').textContent = `Found ${check.matched} of ${check.total} already in trust list.`;
      } else {
        $('trustStatus').textContent = '';
      }
    }catch(e){
      $('trustStatus').textContent = 'Trust list check failed: ' + e.message;
    }
  }catch(e){
    $('fileStatus').textContent = 'Upload failed: ' + e.message;
  }
});

// Keep passphrase in sync so the modal can reuse it without re-entry
$('pfxPass').addEventListener('input', ()=>{
  uploadedPass = $('pfxPass').value || '';
});

// ---- Import CA/intermediates to Trust ----
$('importTrustBtn').addEventListener('click', async ()=>{
  try{
    if(!hostedTokenForTrust){ $('trustStatus').textContent='Upload a PFX first'; return; }
    $('importTrustBtn').disabled = true;
    $('trustStatus').textContent = 'Importing chain into trust list...';
    const j = await postJSON('/api/import-trust-from-pfx', {
    pfx_token: hostedTokenForTrust,
    passphrase: $('pfxPass').value || '',
    usages: ["Others"]
    });
    // Show results in the same pretty modal
    showResultsModal(j);
    $('trustStatus').textContent = 'Trust import complete.';
  }catch(e){
    $('trustStatus').textContent = 'Trust import failed: ' + e.message;
  }finally{
    $('importTrustBtn').disabled = false;
  }
});

// ---- Replace flow (confirmation modal) ----
$('replaceBtn').addEventListener('click', ()=>{
  const t = selectedTargets();
  if (!t.length){ return; }
  const body = [
    'You are about to replace certificates for the following targets:',
    '',
    ...t.map(x => `    * ${x.server_label}  -  ${x.service}`),
    '',
    'This will call PUT /api/server-cert/name/{server_uuid}/{service_name} on the Publisher.',
    'Ensure ClearPass can reach the PKCS#12 URL over HTTP.'
  ].join('\n');
  $('modalBody').textContent = body;
  $('modalUrl').value = hostedUrl || '';
  $('modalPass').value = $('pfxPass').value || uploadedPass || '';
  $('confirmCount').textContent = String(t.length);
  $('confirmInput').value = '';
  $('modalDo').disabled = true;
  $('modal').classList.remove('hidden');
  showModal();
});

$('modalCancel').addEventListener('click', ()=>{ hideModal(); });

$('confirmInput').addEventListener('input', ()=>{
  const need = $('confirmCount').textContent;
  const v = $('confirmInput').value.trim();
  $('modalDo').disabled = !(v === need || v.toUpperCase() === 'CONFIRM');
});

$('modalDo').addEventListener('click', async ()=>{
  try{
    const t = selectedTargets();
    const url = $('modalUrl').value.trim();
    const pass = $('modalPass').value;
    if (!url){ alert('Please provide a PKCS#12 URL (hosted by this app or elsewhere)'); return; }
    $('modalDo').disabled = true;
    setStatus('Replacing certificates on ' + t.length + ' targets...');
    const j = await postJSON('/api/replace', {targets: t, pkcs12_url: url, passphrase: pass});
    hideModal();
    // Show results
    showResultsModal(j);
    setStatus('Replacement done. See results modal.');
  }catch(e){
    setStatus('Replace failed: ' + e.message);
  }finally{
    $('modalDo').disabled = false;
  }
});
// Move kill logic to footer button
const killBtnFooter = document.getElementById('killBtnFooter');
if (killBtnFooter) {
    killBtnFooter.addEventListener('click', async ()=>{
    try {
        const r = await fetch('/api/kill', {method:'POST'});
        if (!r.ok) throw new Error(await r.text());
        setStatus('Script killed.');
        setTimeout(()=>window.close(), 800);
    } catch(e) {
        alert('Kill failed: ' + e.message);
    }
    });
}
</script>
</body></html>
    """)

@app.route("/api/connect-and-scan", methods=["POST"])
def api_connect_and_scan():
    data = request.get_json(force=True, silent=True) or {}
    host = (data.get("host") or "").strip()
    token  = (data.get("token") or "").strip()
    verify = bool(data.get("verify_tls", True))
    if not host or not token:
        return jsonify(error="host and token required"), 400

    api = ClearPassAPI(host, token=token, verify_tls=verify)
    # -- Better error feedback for connect/token issues
    try:
        api.token()
    except requests.exceptions.SSLError as e:
        return jsonify(
            error="TLS certificate validation failed",
            hint="If you are sure this is the correct ClearPass server, uncheck 'Verify TLS' and try again.",
            details=str(e)
        ), 495
    except requests.exceptions.ConnectionError as e:
        return jsonify(
            error="Server not reachable",
            hint="Check host/FQDN, network, firewall, and that the Publisher is up and reachable on HTTPS.",
            details=str(e)
        ), 502
    except requests.exceptions.Timeout as e:
        return jsonify(
            error="Connection timed out",
            hint="Verify network reachability and DNS, then try again.",
            details=str(e)
        ), 504
    except RuntimeError as e:
        em = str(e)
        if "OAuth failed 401" in em or "OAuth failed 403" in em or "No token" in em or "token" in em.lower():
            return jsonify(
                error="Authentication failed",
                hint="Token is invalid or lacks permissions. Check Administration -> API Services -> API Clients.",
                details=em
            ), 401
        return jsonify(error="Connect failed, Check credentials", details=em), 500
    # Check API token privileges
    try:
        privs = set(api.list_privileges() or [])
        missing = sorted([p for p in REQUIRED_PRIVILEGES if p not in privs])
        if missing:
            return jsonify(
                error="API token missing required privileges",
                hint="Token must include the required ClearPass API privileges.",
                required=sorted(REQUIRED_PRIVILEGES),
                missing=missing
            ), 403
    except Exception as e:
        return jsonify(
            error="Unable to verify token privileges",
            hint="Check that the Publisher is reachable and the token is valid.",
            details=str(e)
        ), 502

    sid = session.get("sid") or secrets.token_hex(8)
    session["sid"] = sid; _APIS[sid] = api

    services = SERVICE_NAMES[:]
    servers = api.list_cluster_servers()
    out = []
    for sv in servers:
        label = sv.get("name") or sv.get("fqdn") or sv.get("ip_address") or sv.get("uuid")
        uuid  = sv.get("uuid")
        if not uuid: continue
        certs = api.list_member_named_certs(uuid, services)
        for c in certs:
            raw = c.get("raw") or {}
            enabled = first_of(raw, ["enabled","active","validity"])
            issued  = first_of(raw, ["issue_date","issueDate","issue_time","issue","valid_from","validFrom","notBefore",["certificate","notBefore"]])
            expiry  = first_of(raw, ["expiry_date","expiry","expiryDate","expiry_time","valid_to","validTo","notAfter",["certificate","notAfter"]])
            issuer_val = first_of(raw, ["issuer","issuer_dn","issuerName","issued_by",["certificate","issuer"],["certificate","issuer_dn"]])
            if issuer_val is None: issuer_val = c.get("issuer")
            issuer_val = _normalize_name(issuer_val)

            vf = parse_date(issued) if issued else parse_date(c.get("valid_from"))
            vt = parse_date(expiry) if expiry else parse_date(c.get("valid_to"))

            out.append({
                "server_label": label,
                "server_uuid": c.get("server_uuid"),
                "service": c.get("service"),
                "id": c.get("id"),
                "enabled": enabled,
                "enabled_str": "" if enabled is None else str(enabled),
                "subject": c.get("subject"),
                "issuer": issuer_val,
                "issued_date": issued if issued is not None else (c.get("valid_from") or ""),
                "expiry_date": expiry if expiry is not None else (c.get("valid_to") or ""),
                "issued_ts": None if vf is None else vf.timestamp(),
                "expiry_ts": None if vt is None else vt.timestamp(),
                "pem": c.get("pem"),
                "raw": raw
            })
    return jsonify(rows=out)

# ---------- File hosting ----------
@app.route("/api/upload-pfx", methods=["POST"])
def api_upload_pfx():
    if "pfx" not in request.files:
        return jsonify(error="No file part 'pfx'"), 400
    f = request.files["pfx"]
    if not f or f.filename == "":
        return jsonify(error="Empty filename"), 400
    token = secrets.token_hex(8)
    dst = UPLOAD_DIR / f"{token}.p12"
    file = request.files.get("pfx")
    if not file:
        return jsonify(error="no pfx file"), 400
    file.save(dst)
    try:
        os.chmod(dst, 0o600)
    except Exception:
        pass
    file_url = f"{request.host_url.rstrip('/')}/files/{token}.p12"
    return jsonify({
        "file_url": file_url,
        "token": token
    })

@app.route("/files/<name>")
def files(name):
    safe = os.path.basename(name)
    p = UPLOAD_DIR / safe
    if not p.exists():
        print(f"[DEBUG] File not found for download: {p}")
        return "Not found", 404
    return send_file(p.as_posix(), mimetype="application/x-pkcs12",
                     as_attachment=False, download_name=safe)
 
# ---------- Import CA/intermediates from PFX into trust list ----------
def _openssl_extract_chain(pfx_path: pathlib.Path, passphrase: str):
    """
    Pure-Python replacement for OpenSSL command.
    Extracts CA + intermediate certs from a PFX (.p12) and returns a list of PEM strings.
    """
    password_bytes = passphrase.encode() if passphrase else None

    try:
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()
        # Load key, cert, and additional certs
        key, cert, additional_certs = pkcs12.load_key_and_certificates(pfx_data, password_bytes)
    except Exception as e:
        raise RuntimeError(f"Failed to read or parse PFX: {e}")

    # Collect chain certs (intermediates + root)
    certs = []
    if additional_certs:
        for c in additional_certs:
            try:
                pem = c.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                certs.append(pem)
            except Exception as e:
                print("[DEBUG] Skipped a malformed cert:", e)

    # If no additional certs, sometimes the main cert might be self-signed
    if not certs and cert:
        try:
            pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            certs.append(pem)
        except Exception as e:
            print("[DEBUG] Failed to convert primary cert:", e)

    print(f"[DEBUG] Extracted {len(certs)} cert(s) from PFX in pure Python.")
    return certs

def _normalize_fingerprint(fp: str) -> str:
    if not fp:
        return ""
    return re.sub(r"[^A-Fa-f0-9]", "", str(fp)).upper()

def _fingerprint_from_pem(pem: str) -> str:
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        return cert.fingerprint(hashes.SHA1()).hex().upper()
    except Exception:
        return ""

@app.route("/api/check-trust-from-pfx", methods=["POST"])
def api_check_trust_from_pfx():
    api = _get_api()
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("pfx_token") or "").strip()
    passphrase = data.get("passphrase") or ""

    if not token:
        return jsonify(error="pfx_token required"), 400

    pfx_path = UPLOAD_DIR / f"{token}.p12"
    if not pfx_path.exists():
        return jsonify(error="uploaded PFX not found or expired"), 404

    # Extract chain
    try:
        certs = _openssl_extract_chain(pfx_path, passphrase)
    except Exception as e:
        print("[ERROR] OpenSSL extraction failed:", e)
        return jsonify(error=str(e)), 500

    if not certs:
        return jsonify(error="No CA/chain certificates found in PFX"), 400

    # Get trust list and build a fingerprint set
    trust_list = api.list_trust_certs()
    existing_fps = set()
    for c in trust_list:
        fp = first_of(c, ["thumbprint", "fingerprint", "sha1", "sha1_fingerprint", "sha1Fingerprint"])
        fp = _normalize_fingerprint(fp)
        if not fp:
            pem = first_of(c, ["pem", "certificate", "cert_file"])
            if pem:
                fp = _normalize_fingerprint(_fingerprint_from_pem(str(pem)))
        if fp:
            existing_fps.add(fp)

    # Compare with PFX chain
    pfx_fps = []
    for pem in certs:
        fp = _normalize_fingerprint(_fingerprint_from_pem(pem))
        if fp:
            pfx_fps.append(fp)

    matched = [fp for fp in pfx_fps if fp in existing_fps]
    return jsonify({
        "total": len(pfx_fps),
        "matched": len(matched),
        "all_present": (len(pfx_fps) > 0 and len(matched) == len(pfx_fps))
    })

@app.route("/api/import-trust-from-pfx", methods=["POST"])
def api_import_trust_from_pfx():
    api = _get_api()
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("pfx_token") or "").strip()
    passphrase = data.get("passphrase") or ""
    usages = data.get("usages") or ["Others"]

    if not token:
        return jsonify(error="pfx_token required"), 400

    pfx_path = UPLOAD_DIR / f"{token}.p12"
    if not pfx_path.exists():
        return jsonify(error="uploaded PFX not found or expired"), 404

    # Extract chain
    try:
        certs = _openssl_extract_chain(pfx_path, passphrase)
    except Exception as e:
        print("[ERROR] OpenSSL extraction failed:", e)
        return jsonify(error=str(e)), 500

    if not certs:
        return jsonify(error="No CA/chain certificates found in PFX"), 400

    results = []
    for pem in certs:
        for usage in usages:
            try:
                status, body = api.add_trust_cert(pem, usage=usage, enabled=True)
                results.append({
                    "server_label": "Trust List",
                    "service": f"Add {usage}",
                    "status": status,
                    "message": body if isinstance(body, str) else body
                })
            except Exception as e:
                print(f"[ERROR] Trust import failed for {usage}:", e)
                results.append({
                    "server_label": "Trust List",
                    "service": f"Add {usage}",
                    "status": 599,
                    "message": str(e)
                })
    return jsonify({"results": results})

# ---------- Replace certificates ----------
@app.route("/api/replace", methods=["POST"])
def api_replace():
    api = _get_api()
    data = request.get_json(force=True, silent=True) or {}
    targets = data.get("targets") or []
    pfx_url = (data.get("pkcs12_url") or "").strip()
    passphrase = data.get("passphrase") or ""
    if not targets:
        return jsonify(error="No targets selected"), 400
    if not pfx_url:
        return jsonify(error="pkcs12_url required"), 400
    results = []
    for t in targets:
        uuid = t.get("server_uuid"); svc = t.get("service"); label = t.get("server_label") or uuid
        if not uuid or not svc:
            results.append({"server_label": label, "service": svc, "status": 400, "message": "Missing uuid/service"}); continue
        try:
            status, body = api.put_server_cert_pkcs12(uuid, svc, pfx_url, passphrase)
            msg = body if isinstance(body, str) else (json.dumps(body) if isinstance(body, dict) else str(body))
            results.append({"server_label": label, "service": svc, "status": status, "message": msg[:500]})
        except Exception as e:
            results.append({"server_label": label, "service": svc, "status": 599, "message": str(e)})
    resp = app.response_class(
        response=json.dumps({"results": results}, indent=2, sort_keys=True),
        status=200,
        mimetype="application/json"
    )
    return resp

# --- Graceful kill endpoint ---
@app.route("/api/kill", methods=["POST"])
def api_kill():
    # (optional) tidy hosted files older than 1 day
    try:
        now = time.time()
        for p in UPLOAD_DIR.glob("*.p12"):
            if now - p.stat().st_mtime > 86400:
                try: p.unlink()
                except: pass
    except: pass

    # Try Werkzeug shutdown if available (dev server)
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()
        return jsonify(status="terminating via werkzeug"), 200

    # Fallback for waitress/gunicorn/etc.
    def _hard_exit():
        time.sleep(0.2)
        os._exit(0)
    threading.Thread(target=_hard_exit, daemon=True).start()
    return jsonify(status="terminating via os._exit"), 200

# Backward-compat alias if something still posts here
@app.route("/api/exit", methods=["POST"])
def api_exit():
    return api_kill()

@app.route("/favicon.ico")
def favicon():
    return make_response(b"", 204)

@app.route("/shutdown", methods=["POST"])
def shutdown():
    try:
        _cleanup_uploaded_files()
    except Exception:
        pass

    func = request.environ.get("werkzeug.server.shutdown")
    if func is None:
        os._exit(0)
    threading.Timer(0.05, func).start()
    return jsonify(message="Server shutting down... uploads cleaned.")

# -------------------- Run --------------------
if __name__ == "__main__":
    os.environ.pop("QT_DEBUG_PLUGINS", None)
    # Bind to all interfaces so remote ClearPass instances can fetch hosted PKCS#12 files.
    # Note: ensure your machine's firewall allows incoming connections on the chosen port.
    host = "0.0.0.0"
    port = 5000
    # Show a LAN-accessible URL in the console/browser (useful when running on a machine with a LAN IP)
    public_host = get_lan_ip()
    url = f"http://{public_host}:{port}/"
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    print(f"Serving on {url} (listening on {host}:{port})")
    import logging as _log
    _log.getLogger("werkzeug").setLevel(_log.INFO)
    app.run(host=host, port=port, debug=False)




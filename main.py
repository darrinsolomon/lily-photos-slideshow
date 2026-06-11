import asyncio
import datetime
import hashlib
import hmac
import os
import secrets
import time
from collections import deque
from pathlib import Path

from fastapi import Cookie, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

PHOTOS_DIR = Path(os.getenv("PHOTOS_DIR", "/data/photos"))
PHOTOS_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_TOKEN      = os.getenv("UPLOAD_TOKEN", "")
SLIDESHOW_PASSWORD = os.getenv("SLIDESHOW_PASSWORD", "")

_COOKIE_NAME     = "lily_auth"
_ADMIN_COOKIE    = "lily_admin"
_COOKIE_MAX_AGE  = 60 * 60 * 24 * 365  # 1 year

# In-memory visit log: (timestamp, ip, path)
_visits: deque = deque(maxlen=500)
_last_upload: float | None = None
_start_time: float = time.time()

# SSE subscribers — each is an asyncio.Queue
_sse_clients: set[asyncio.Queue] = set()


def _broadcast_reload() -> None:
    for q in list(_sse_clients):
        q.put_nowait("reload")


def _make_cookie(key: str, secret: str) -> str:
    return hmac.new(secret.encode(), key.encode(), hashlib.sha256).hexdigest()


def _is_authenticated(cookie: str | None) -> bool:
    if not SLIDESHOW_PASSWORD:
        return True
    return bool(cookie and hmac.compare_digest(cookie, _make_cookie("slideshow", SLIDESHOW_PASSWORD)))


def _is_admin(cookie: str | None) -> bool:
    if not UPLOAD_TOKEN:
        return False
    return bool(cookie and hmac.compare_digest(cookie, _make_cookie("admin", UPLOAD_TOKEN)))


app = FastAPI(docs_url=None, redoc_url=None)
app.mount("/photos", StaticFiles(directory=PHOTOS_DIR), name="photos")

SUPPORTED = {".jpg", ".jpeg", ".png", ".webp"}


@app.middleware("http")
async def track_visits(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/" and response.status_code == 200:
        ip = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
        _visits.append((time.time(), ip))
    return response


def _image_list() -> list[Path]:
    return sorted(
        (f for f in PHOTOS_DIR.iterdir() if f.suffix.lower() in SUPPORTED),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )


def _photos_dir_size() -> int:
    return sum(f.stat().st_size for f in PHOTOS_DIR.iterdir() if f.is_file())


def _active_sessions(window_minutes: int = 30) -> list[tuple]:
    cutoff = time.time() - window_minutes * 60
    recent = [(ts, ip) for ts, ip in _visits if ts > cutoff]
    # unique IPs with their most recent visit
    seen: dict[str, float] = {}
    for ts, ip in recent:
        if ip not in seen or ts > seen[ip]:
            seen[ip] = ts
    return sorted(seen.items(), key=lambda x: x[1], reverse=True)


def _fmt_uptime(seconds: float) -> str:
    s = int(seconds)
    h, m = divmod(s // 60, 60)
    d, h = divmod(h, 24)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "never"
    return datetime.datetime.fromtimestamp(ts).strftime("%b %d %Y, %-I:%M %p")


# ── Login pages ──────────────────────────────────────────────────────────────

def _login_html(title: str, action: str, error: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{background:#111;display:flex;align-items:center;justify-content:center;height:100vh;font-family:-apple-system,sans-serif}}
    .card{{background:#1e1e1e;border-radius:16px;padding:48px 40px;text-align:center;width:320px}}
    h1{{color:#fff;font-size:1.6em;margin-bottom:8px}}
    p{{color:#888;font-size:.9em;margin-bottom:32px}}
    input[type=password]{{width:100%;padding:14px 16px;font-size:1.1em;border-radius:10px;border:1px solid #333;background:#2a2a2a;color:#fff;text-align:center;letter-spacing:4px;margin-bottom:16px;outline:none}}
    input[type=password]:focus{{border-color:#555}}
    button{{width:100%;padding:14px;font-size:1em;font-weight:600;border-radius:10px;border:none;background:#fff;color:#111;cursor:pointer}}
    button:hover{{background:#eee}}
    .error{{color:#ff6b6b;font-size:.85em;margin-top:12px}}
  </style>
</head><body>
  <div class="card">
    <h1>{title}</h1>
    <p>Enter password to continue</p>
    <form method="post" action="{action}">
      <input type="password" name="password" autofocus placeholder="••••••••">
      <button type="submit">Enter</button>
      {error}
    </form>
  </div>
</body></html>"""


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(_login_html("Lily's Photos", "/login"))


@app.post("/login")
def login(password: str = Form(...)):
    if not SLIDESHOW_PASSWORD or secrets.compare_digest(password, SLIDESHOW_PASSWORD):
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(_COOKIE_NAME, _make_cookie("slideshow", SLIDESHOW_PASSWORD or password),
                        max_age=_COOKIE_MAX_AGE, httponly=True, samesite="lax")
        return resp
    return HTMLResponse(_login_html("Lily's Photos", "/login",
                                    '<p class="error">Incorrect password</p>'), status_code=401)


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page():
    return HTMLResponse(_login_html("Admin", "/admin/login"))


@app.post("/admin/login")
def admin_login(password: str = Form(...)):
    if not UPLOAD_TOKEN or not secrets.compare_digest(password, UPLOAD_TOKEN):
        return HTMLResponse(_login_html("Admin", "/admin/login",
                                        '<p class="error">Incorrect password</p>'), status_code=401)
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(_ADMIN_COOKIE, _make_cookie("admin", UPLOAD_TOKEN),
                    max_age=_COOKIE_MAX_AGE, httponly=True, samesite="lax")
    return resp


# ── Slideshow ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def slideshow(lily_auth: str | None = Cookie(default=None)):
    if not _is_authenticated(lily_auth):
        return RedirectResponse("/login")

    images = _image_list()
    if not images:
        return HTMLResponse("<html><body style='background:#000;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;font-size:2em;'>No photos yet — check back soon!</body></html>")

    slides_html = "\n".join(
        f'    <div class="slide"><img src="/photos/{f.name}" loading="lazy"></div>'
        for f in images
    )
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Lily</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    html,body{{background:#000;width:100%;height:100%;overflow:hidden}}
    .slideshow{{position:relative;width:100vw;height:100vh}}
    .slide{{position:absolute;inset:0;opacity:0;transition:opacity 1.2s ease-in-out}}
    .slide.active{{opacity:1}}
    .slide img{{width:100%;height:100%;object-fit:contain}}
    .counter{{position:fixed;bottom:16px;right:20px;color:rgba(255,255,255,.3);font-family:sans-serif;font-size:13px;pointer-events:none}}
  </style>
</head><body>
  <div class="slideshow">
{slides_html}
  </div>
  <div class="counter" id="counter"></div>
  <script>
    const slides = document.querySelectorAll('.slide');
    const counter = document.getElementById('counter');
    for (let i = slides.length - 1; i > 0; i--) {{
      const j = Math.floor(Math.random() * (i + 1));
      slides[i].parentNode.insertBefore(slides[j], slides[i]);
      slides[i].parentNode.insertBefore(slides[i], slides[j].nextSibling);
    }}
    const sh = document.querySelectorAll('.slide');
    let cur = 0;
    function show(i) {{
      sh[cur].classList.remove('active');
      cur = (i + sh.length) % sh.length;
      sh[cur].classList.add('active');
      counter.textContent = (cur+1) + ' / ' + sh.length;
    }}
    show(0);
    const timer = setInterval(() => show(cur + 1), 7000);
    document.body.addEventListener('click', () => show(cur + 1));

    const es = new EventSource('/events');
    es.addEventListener('reload', () => location.reload());
  </script>
</body></html>""")


# ── Admin ────────────────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
def admin(lily_admin: str | None = Cookie(default=None)):
    if not _is_admin(lily_admin):
        return RedirectResponse("/admin/login")

    images = _image_list()
    photo_count = len(images)
    dir_size_mb = _photos_dir_size() / 1e6
    uptime = _fmt_uptime(time.time() - _start_time)
    active = _active_sessions(30)
    recent_all = list(_visits)[-20:][::-1]

    sessions_html = "".join(
        f'<tr><td>{ip}</td><td>{_fmt_ts(ts)}</td></tr>'
        for ip, ts in active
    ) or "<tr><td colspan=2 style='color:#555'>No activity in last 30 min</td></tr>"

    recent_html = "".join(
        f'<tr><td>{_fmt_ts(ts)}</td><td>{ip}</td></tr>'
        for ts, ip in recent_all
    ) or "<tr><td colspan=2 style='color:#555'>No visits yet</td></tr>"

    photos_html = "".join(
        f'<tr><td><code style="font-size:.8em">{f.name}</code></td>'
        f'<td>{f.stat().st_size // 1024:,} KB</td>'
        f'<td>{_fmt_ts(f.stat().st_mtime)}</td>'
        f'<td><button class="del-btn" data-name="{f.name}">Delete</button></td></tr>'
        for f in images
    )

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Lily Admin</title>
  <style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{background:#0f0f0f;color:#ccc;font-family:-apple-system,sans-serif;padding:32px 24px}}
    h1{{color:#fff;font-size:1.4em;margin-bottom:4px}}
    .sub{{color:#555;font-size:.85em;margin-bottom:32px}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:40px}}
    .stat{{background:#1a1a1a;border-radius:12px;padding:20px}}
    .stat .val{{color:#fff;font-size:2em;font-weight:700}}
    .stat .lbl{{color:#555;font-size:.8em;margin-top:4px}}
    h2{{color:#fff;font-size:1em;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #222}}
    .section{{margin-bottom:40px}}
    table{{width:100%;border-collapse:collapse;font-size:.85em}}
    th{{color:#555;text-align:left;padding:6px 8px;font-weight:500;border-bottom:1px solid #1e1e1e}}
    td{{padding:8px;border-bottom:1px solid #1a1a1a;color:#aaa}}
    tr:hover td{{background:#161616}}
    .dot{{display:inline-block;width:8px;height:8px;border-radius:50%;background:#4caf50;margin-right:6px}}
    a{{color:#555;font-size:.8em;text-decoration:none}}
    a:hover{{color:#888}}
    .del-btn{{background:none;border:1px solid #3a1a1a;color:#c44;border-radius:6px;padding:3px 10px;cursor:pointer;font-size:.8em}}
    .del-btn:hover{{background:#3a1a1a}}
    .upload-zone{{border:2px dashed #333;border-radius:12px;padding:32px;text-align:center;cursor:pointer;color:#555;transition:border-color .2s}}
    .upload-zone.drag{{border-color:#666;color:#888}}
    .upload-btn{{background:#fff;color:#111;border:none;border-radius:8px;padding:10px 24px;font-size:.9em;font-weight:600;cursor:pointer;margin-top:12px}}
    .upload-btn:hover{{background:#eee}}
    #upload-status{{font-size:.85em;color:#888;margin-top:10px}}
  </style>
</head><body>
  <h1>Lily's Photos — Admin</h1>
  <div class="sub">Server uptime: {uptime} &nbsp;·&nbsp; <a href="/">View slideshow →</a></div>

  <div class="grid">
    <div class="stat"><div class="val">{photo_count}</div><div class="lbl">Photos on server</div></div>
    <div class="stat"><div class="val">{dir_size_mb:.0f} MB</div><div class="lbl">Storage used</div></div>
    <div class="stat"><div class="val">{len(active)}</div><div class="lbl">Active viewers (30 min)</div></div>
    <div class="stat"><div class="val">{len(_visits)}</div><div class="lbl">Total visits this session</div></div>
  </div>

  <div class="section">
    <h2><span class="dot"></span>Active Viewers (last 30 min)</h2>
    <table>
      <tr><th>IP Address</th><th>Last Seen</th></tr>
      {sessions_html}
    </table>
  </div>

  <div class="section">
    <h2>Recent Activity</h2>
    <table>
      <tr><th>Time</th><th>IP</th></tr>
      {recent_html}
    </table>
  </div>

  <div class="section">
    <h2>Add Photos</h2>
    <div class="upload-zone" id="upload-zone">
      Drop JPG / PNG / WEBP files here, or click to browse
      <br><button class="upload-btn">Choose Files</button>
      <input type="file" id="upload-input" multiple accept=".jpg,.jpeg,.png,.webp" style="display:none">
    </div>
    <div id="upload-status"></div>
  </div>

  <div class="section">
    <h2>Photos on Server ({photo_count})</h2>
    <table>
      <tr><th>Filename</th><th>Size</th><th>Uploaded</th><th></th></tr>
      {photos_html}
    </table>
  </div>

  <script>
    // ── Delete ────────────────────────────────────────────────────────────────
    document.querySelectorAll('.del-btn').forEach(btn => {{
      btn.addEventListener('click', async () => {{
        if (!confirm('Delete ' + btn.dataset.name + '?')) return;
        btn.disabled = true;
        const r = await fetch('/photos/' + encodeURIComponent(btn.dataset.name), {{method: 'DELETE'}});
        if (r.ok) btn.closest('tr').remove();
        else {{ alert('Delete failed'); btn.disabled = false; }}
      }});
    }});

    // ── Upload ────────────────────────────────────────────────────────────────
    const zone   = document.getElementById('upload-zone');
    const input  = document.getElementById('upload-input');
    const status = document.getElementById('upload-status');

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover',  e => {{ e.preventDefault(); zone.classList.add('drag'); }});
    zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
    zone.addEventListener('drop', e => {{ e.preventDefault(); zone.classList.remove('drag'); doUpload(e.dataTransfer.files); }});
    input.addEventListener('change', () => doUpload(input.files));

    async function doUpload(files) {{
      if (!files.length) return;
      status.textContent = 'Uploading ' + files.length + ' file(s)...';
      const fd = new FormData();
      for (const f of files) fd.append('files', f);
      const r = await fetch('/admin/upload', {{method: 'POST', body: fd}});
      if (r.ok) {{
        const d = await r.json();
        status.textContent = d.uploaded.length + ' photo(s) added. Reloading page...';
        setTimeout(() => location.reload(), 1200);
      }} else {{
        status.textContent = 'Upload failed (' + r.status + ').';
      }}
    }}
  </script>
</body></html>""")


# ── Server-Sent Events ───────────────────────────────────────────────────────

@app.get("/events")
async def events(lily_auth: str | None = Cookie(default=None)):
    if not _is_authenticated(lily_auth):
        raise HTTPException(401, "Unauthorized")

    queue: asyncio.Queue = asyncio.Queue()
    _sse_clients.add(queue)

    async def stream():
        try:
            yield "retry: 5000\n\n"  # tell browser to reconnect after 5 s if dropped
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=25)
                    yield f"event: {msg}\ndata: \n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"  # prevent proxy from closing idle connection
        finally:
            _sse_clients.discard(queue)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.get("/photos/list")
def photos_list(authorization: str = Header(...)):
    if not UPLOAD_TOKEN:
        raise HTTPException(500, "UPLOAD_TOKEN not configured")
    if not secrets.compare_digest(authorization, f"Bearer {UPLOAD_TOKEN}"):
        raise HTTPException(401, "Unauthorized")
    return {"photos": [f.name for f in _image_list()]}


@app.delete("/photos/{filename}")
def delete_photo(filename: str, lily_admin: str | None = Cookie(default=None)):
    if not _is_admin(lily_admin):
        raise HTTPException(401, "Unauthorized")
    target = PHOTOS_DIR / filename
    if PHOTOS_DIR.resolve() not in target.resolve().parents:
        raise HTTPException(400, "Invalid filename")
    if not target.exists() or target.suffix.lower() not in SUPPORTED:
        raise HTTPException(404, "Not found")
    target.unlink()
    _broadcast_reload()
    return {"deleted": filename, "total_photos": len(_image_list())}


@app.post("/admin/upload")
async def admin_upload(files: list[UploadFile] = File(...), lily_admin: str | None = Cookie(default=None)):
    if not _is_admin(lily_admin):
        raise HTTPException(401, "Unauthorized")
    saved = []
    for f in files:
        if Path(f.filename).suffix.lower() not in SUPPORTED:
            continue
        (PHOTOS_DIR / f.filename).write_bytes(await f.read())
        saved.append(f.filename)
    if saved:
        _broadcast_reload()
    return {"uploaded": saved, "total_photos": len(_image_list())}


@app.post("/upload")
async def upload(files: list[UploadFile] = File(...), authorization: str = Header(...)):
    global _last_upload
    if not UPLOAD_TOKEN:
        raise HTTPException(500, "UPLOAD_TOKEN not configured")
    if not secrets.compare_digest(authorization, f"Bearer {UPLOAD_TOKEN}"):
        raise HTTPException(401, "Unauthorized")
    saved = []
    for f in files:
        if Path(f.filename).suffix.lower() not in SUPPORTED:
            continue
        (PHOTOS_DIR / f.filename).write_bytes(await f.read())
        saved.append(f.filename)
    _last_upload = time.time()
    if saved:
        _broadcast_reload()
    return {"uploaded": saved, "total_photos": len(_image_list())}


@app.delete("/clear")
def clear(authorization: str = Header(...)):
    if not UPLOAD_TOKEN:
        raise HTTPException(500, "UPLOAD_TOKEN not configured")
    if not secrets.compare_digest(authorization, f"Bearer {UPLOAD_TOKEN}"):
        raise HTTPException(401, "Unauthorized")
    removed = [f.name for f in PHOTOS_DIR.iterdir() if f.is_file()]
    for f in PHOTOS_DIR.iterdir():
        if f.is_file():
            f.unlink()
    return {"cleared": len(removed)}


@app.get("/health")
def health():
    return {"status": "ok", "photo_count": len(_image_list())}

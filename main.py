import hashlib
import hmac
import os
import secrets
from pathlib import Path

from fastapi import Cookie, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

PHOTOS_DIR = Path(os.getenv("PHOTOS_DIR", "/data/photos"))
PHOTOS_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_TOKEN = os.getenv("UPLOAD_TOKEN", "")
SLIDESHOW_PASSWORD = os.getenv("SLIDESHOW_PASSWORD", "")

# Cookie value is HMAC of the password — never stores the password itself
_COOKIE_NAME = "lily_auth"
_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year


def _make_cookie_value(password: str) -> str:
    return hmac.new(password.encode(), b"lily-slideshow-auth", hashlib.sha256).hexdigest()


def _is_authenticated(cookie_value: str | None) -> bool:
    if not SLIDESHOW_PASSWORD:
        return True  # no password set → open
    if not cookie_value:
        return False
    expected = _make_cookie_value(SLIDESHOW_PASSWORD)
    return hmac.compare_digest(cookie_value, expected)


app = FastAPI(docs_url=None, redoc_url=None)
app.mount("/photos", StaticFiles(directory=PHOTOS_DIR), name="photos")

SUPPORTED = {".jpg", ".jpeg", ".png", ".webp"}


def _image_list() -> list[str]:
    files = sorted(
        (f for f in PHOTOS_DIR.iterdir() if f.suffix.lower() in SUPPORTED),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )
    return [f.name for f in files]


_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lily's Photos</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      background: #111;
      display: flex; align-items: center; justify-content: center;
      height: 100vh;
      font-family: -apple-system, sans-serif;
    }}
    .card {{
      background: #1e1e1e;
      border-radius: 16px;
      padding: 48px 40px;
      text-align: center;
      width: 320px;
    }}
    h1 {{ color: #fff; font-size: 1.6em; margin-bottom: 8px; }}
    p  {{ color: #888; font-size: 0.9em; margin-bottom: 32px; }}
    input[type=password] {{
      width: 100%;
      padding: 14px 16px;
      font-size: 1.1em;
      border-radius: 10px;
      border: 1px solid #333;
      background: #2a2a2a;
      color: #fff;
      text-align: center;
      letter-spacing: 4px;
      margin-bottom: 16px;
      outline: none;
    }}
    input[type=password]:focus {{ border-color: #555; }}
    button {{
      width: 100%;
      padding: 14px;
      font-size: 1em;
      font-weight: 600;
      border-radius: 10px;
      border: none;
      background: #fff;
      color: #111;
      cursor: pointer;
    }}
    button:hover {{ background: #eee; }}
    .error {{ color: #ff6b6b; font-size: 0.85em; margin-top: 12px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Lily's Photos</h1>
    <p>Enter the password to view</p>
    <form method="post" action="/login">
      <input type="password" name="password" autofocus placeholder="••••••••">
      <button type="submit">View Photos</button>
      {error}
    </form>
  </div>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse(_LOGIN_PAGE.format(error=""))


@app.post("/login")
def login(password: str = Form(...)):
    if not SLIDESHOW_PASSWORD or secrets.compare_digest(password, SLIDESHOW_PASSWORD):
        cookie_value = _make_cookie_value(SLIDESHOW_PASSWORD or password)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            _COOKIE_NAME, cookie_value,
            max_age=_COOKIE_MAX_AGE, httponly=True, samesite="lax",
        )
        return response
    return HTMLResponse(
        _LOGIN_PAGE.format(error='<p class="error">Incorrect password</p>'),
        status_code=401,
    )


@app.get("/", response_class=HTMLResponse)
def slideshow(lily_auth: str | None = Cookie(default=None)):
    if not _is_authenticated(lily_auth):
        return RedirectResponse("/login")

    images = _image_list()
    if not images:
        return HTMLResponse("<html><body style='background:#000;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;font-size:2em;'>No photos yet — check back soon!</body></html>")

    slides_html = "\n".join(
        f'    <div class="slide"><img src="/photos/{name}" loading="lazy"></div>'
        for name in images
    )

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lily</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    html, body {{
      background: #000;
      width: 100%; height: 100%;
      overflow: hidden;
    }}
    .slideshow {{
      position: relative;
      width: 100vw; height: 100vh;
    }}
    .slide {{
      position: absolute;
      inset: 0;
      opacity: 0;
      transition: opacity 1.2s ease-in-out;
    }}
    .slide.active {{ opacity: 1; }}
    .slide img {{
      width: 100%; height: 100%;
      object-fit: contain;
    }}
    .counter {{
      position: fixed;
      bottom: 16px; right: 20px;
      color: rgba(255,255,255,0.3);
      font-family: sans-serif;
      font-size: 13px;
      pointer-events: none;
    }}
  </style>
</head>
<body>
  <div class="slideshow">
{slides_html}
  </div>
  <div class="counter" id="counter"></div>
  <script>
    const slides = document.querySelectorAll('.slide');
    const counter = document.getElementById('counter');

    // Shuffle slides in place (Fisher-Yates)
    for (let i = slides.length - 1; i > 0; i--) {{
      const j = Math.floor(Math.random() * (i + 1));
      slides[i].parentNode.insertBefore(slides[j], slides[i]);
      slides[i].parentNode.insertBefore(slides[i], slides[j].nextSibling);
    }}
    const shuffled = document.querySelectorAll('.slide');

    let cur = 0;
    function show(i) {{
      shuffled[cur].classList.remove('active');
      cur = (i + shuffled.length) % shuffled.length;
      shuffled[cur].classList.add('active');
      counter.textContent = (cur + 1) + ' / ' + shuffled.length;
    }}

    show(0);
    const timer = setInterval(() => show(cur + 1), 7000);

    document.body.addEventListener('click', () => {{
      clearInterval(timer);
      show(cur + 1);
    }});
  </script>
</body>
</html>""")


@app.post("/upload")
async def upload(
    files: list[UploadFile] = File(...),
    authorization: str = Header(...),
):
    if not UPLOAD_TOKEN:
        raise HTTPException(500, "UPLOAD_TOKEN not configured on server")
    if not secrets.compare_digest(authorization, f"Bearer {UPLOAD_TOKEN}"):
        raise HTTPException(401, "Unauthorized")

    saved = []
    for f in files:
        suffix = Path(f.filename).suffix.lower()
        if suffix not in SUPPORTED:
            continue
        dest = PHOTOS_DIR / f.filename
        dest.write_bytes(await f.read())
        saved.append(f.filename)

    return {"uploaded": saved, "total_photos": len(_image_list())}


@app.delete("/clear")
def clear(authorization: str = Header(...)):
    if not UPLOAD_TOKEN:
        raise HTTPException(500, "UPLOAD_TOKEN not configured on server")
    if not secrets.compare_digest(authorization, f"Bearer {UPLOAD_TOKEN}"):
        raise HTTPException(401, "Unauthorized")
    removed = []
    for f in PHOTOS_DIR.iterdir():
        if f.is_file():
            f.unlink()
            removed.append(f.name)
    return {"cleared": len(removed)}


@app.get("/health")
def health():
    return {"status": "ok", "photo_count": len(_image_list())}

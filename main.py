import os
import secrets
from pathlib import Path

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

PHOTOS_DIR = Path(os.getenv("PHOTOS_DIR", "/data/photos"))
PHOTOS_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_TOKEN = os.getenv("UPLOAD_TOKEN", "")

app = FastAPI(docs_url=None, redoc_url=None)
app.mount("/photos", StaticFiles(directory=PHOTOS_DIR), name="photos")

SUPPORTED = {".jpg", ".jpeg", ".png", ".heic", ".webp"}


def _image_list() -> list[str]:
    files = sorted(
        (f for f in PHOTOS_DIR.iterdir() if f.suffix.lower() in SUPPORTED),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )
    return [f.name for f in files]


@app.get("/", response_class=HTMLResponse)
def slideshow():
    images = _image_list()
    if not images:
        return HTMLResponse("<html><body style='background:#000;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;font-size:2em;'>No photos yet — check back soon!</body></html>")

    slides_html = "\n".join(
        f'    <div class="slide"><img src="/photos/{name}" loading="lazy"></div>'
        for name in images
    )
    count = len(images)

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
    let current = 0;

    function show(i) {{
      slides[current].classList.remove('active');
      current = (i + slides.length) % slides.length;
      slides[current].classList.add('active');
      counter.textContent = (current + 1) + ' / ' + slides.length;
    }}

    show(0);
    const timer = setInterval(() => show(current + 1), 7000);

    // tap/click to advance manually
    document.body.addEventListener('click', () => {{
      clearInterval(timer);
      show(current + 1);
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


@app.get("/health")
def health():
    return {"status": "ok", "photo_count": len(_image_list())}

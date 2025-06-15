from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import json
import os

app = FastAPI()

# ✅ Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["http://localhost:4200"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request body model
class ScanRequest(BaseModel):
    image: str

@app.post("/scan")
def scan_image(req: ScanRequest):
    try:
        print(f"Scanning image: {req}")
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--scanners", "vuln,secret,license", req.image],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)

        vulnerabilities = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                vulnerabilities.append({
                    "Package": vuln.get("PkgName"),
                    "ID": vuln.get("VulnerabilityID"),
                    "InstalledVersion": vuln.get("InstalledVersion"),
                    "FixedVersion": vuln.get("FixedVersion"),
                    "Severity": vuln.get("Severity"),
                    "Title": vuln.get("Title"),
                })

        return {"vulnerabilities": vulnerabilities}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=e.stderr or "scan failed")

app.mount("/", StaticFiles(directory="frontend/dist/scanner-frontend/browser", html=True), name="static")

# Fallback route for Angular (handles client-side routing)
@app.get("/{full_path:path}")
async def catch_all(full_path: str):
    index_file = os.path.join("frontend/dist/scanner-frontend/", "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    raise HTTPException(status_code=404, detail="Page not found")


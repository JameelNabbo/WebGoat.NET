"""
SAST Gateway API - Routes scan requests to language-specific scanners.
Manages queue, handles zip upload/extraction, cleanup.
"""
import asyncio
import os
import sys
import json
import uuid
import shutil
import tempfile
import zipfile
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sast-gateway")

app = FastAPI(title="SAST Offline Scanner Gateway", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Scanner registry - maps language extensions to scanner service URLs
SCANNER_REGISTRY: Dict[str, dict] = {
    "python": {"port": 9001, "extensions": [".py", ".pyw", ".pyx"], "name": "Python Scanner"},
    "javascript": {"port": 9002, "extensions": [".js", ".jsx", ".mjs", ".cjs"], "name": "JavaScript Scanner"},
    "typescript": {"port": 9002, "extensions": [".ts", ".tsx"], "name": "TypeScript Scanner"},
    "csharp": {"port": 9003, "extensions": [".cs", ".csx"], "name": "C# Scanner"},
    "java": {"port": 9004, "extensions": [".java"], "name": "Java Scanner"},
    "go": {"port": 9005, "extensions": [".go"], "name": "Go Scanner"},
    "php": {"port": 9006, "extensions": [".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"], "name": "PHP Scanner"},
    "ruby": {"port": 9007, "extensions": [".rb", ".erb", ".rake", ".gemspec"], "name": "Ruby Scanner"},
    "cpp": {"port": 9008, "extensions": [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"], "name": "C/C++ Scanner"},
    "rust": {"port": 9009, "extensions": [".rs"], "name": "Rust Scanner"},
    "swift": {"port": 9010, "extensions": [".swift"], "name": "Swift Scanner"},
    "objc": {"port": 9011, "extensions": [".m", ".mm", ".h"], "name": "Objective-C Scanner"},
    "kotlin": {"port": 9012, "extensions": [".kt", ".kts"], "name": "Kotlin Scanner"},
    "dart": {"port": 9013, "extensions": [".dart"], "name": "Dart Scanner"},
    "scala": {"port": 9014, "extensions": [".scala", ".sc"], "name": "Scala Scanner"},
    "fsharp": {"port": 9015, "extensions": [".fs", ".fsx", ".fsi"], "name": "F# Scanner"},
    "vb": {"port": 9016, "extensions": [".vb", ".vbs", ".bas"], "name": "VB/VB.NET Scanner"},
    "perl": {"port": 9017, "extensions": [".pl", ".pm", ".t", ".cgi"], "name": "Perl Scanner"},
    "plsql": {"port": 9018, "extensions": [".sql", ".pls", ".plb", ".pck", ".pkb", ".pks", ".fnc", ".prc", ".trg"], "name": "PL/SQL Scanner"},
    "iac": {"port": 9019, "extensions": [".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf"], "name": "IaC Scanner"},
    "dockerfile": {"port": 9019, "extensions": ["Dockerfile", ".dockerfile"], "name": "IaC Scanner"},
    "oracle_forms": {"port": 9020, "extensions": [".fmb", ".fmx", ".xml"], "name": "Oracle Forms Scanner"},
    "ai_llm": {"port": 9021, "extensions": [], "name": "AI/LLM Scanner"},
}

# Scan queue
scan_queue: Dict[str, dict] = {}
MAX_CONCURRENT_SCANS = 3
active_scans = 0
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS)

def get_scanner_for_file(filepath: str) -> Optional[str]:
    """Determine which scanner handles a given file based on extension."""
    fname = os.path.basename(filepath)
    ext = os.path.splitext(filepath)[1].lower()
    
    # Special cases
    if fname == "Dockerfile" or fname.endswith(".dockerfile"):
        return "iac"
    
    for lang, info in SCANNER_REGISTRY.items():
        if ext in info["extensions"]:
            return lang
    return None

def group_files_by_scanner(file_list: List[str]) -> Dict[str, List[str]]:
    """Group files by their target scanner."""
    groups: Dict[str, List[str]] = {}
    for fpath in file_list:
        scanner = get_scanner_for_file(fpath)
        if scanner:
            # Normalize typescript to javascript scanner
            if scanner == "typescript":
                scanner = "javascript"
            if scanner == "dockerfile":
                scanner = "iac"
            if scanner not in groups:
                groups[scanner] = []
            groups[scanner].append(fpath)
    return groups

async def scan_files_with_scanner(scanner_name: str, files: List[str], scan_dir: str) -> dict:
    """Send files to the appropriate scanner service."""
    scanner_info = SCANNER_REGISTRY.get(scanner_name, {})
    port = scanner_info.get("port", 0)
    url = f"http://127.0.0.1:{port}/scan"
    
    # Read file contents
    file_contents = {}
    for fpath in files:
        full_path = os.path.join(scan_dir, fpath)
        try:
            with open(full_path, 'r', errors='ignore') as f:
                file_contents[fpath] = f.read()
        except Exception as e:
            logger.warning(f"Could not read {fpath}: {e}")
    
    if not file_contents:
        return {"vulnerabilities": [], "filesScanned": 0, "scanDuration": "0s"}
    
    payload = {
        "files": file_contents,
        "scanId": str(uuid.uuid4()),
    }
    
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Scanner {scanner_name} returned {response.status_code}")
                return {"vulnerabilities": [], "filesScanned": len(files), "scanDuration": "0s", "error": f"Scanner returned {response.status_code}"}
    except httpx.ConnectError:
        logger.warning(f"Scanner {scanner_name} not available on port {port}")
        return {"vulnerabilities": [], "filesScanned": len(files), "scanDuration": "0s", "error": f"Scanner {scanner_name} not available"}
    except Exception as e:
        logger.error(f"Error calling scanner {scanner_name}: {e}")
        return {"vulnerabilities": [], "filesScanned": len(files), "scanDuration": "0s", "error": str(e)}

def cleanup_scan_dir(scan_dir: str):
    """Remove temporary scan directory."""
    try:
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)
            logger.info(f"Cleaned up scan directory: {scan_dir}")
    except Exception as e:
        logger.error(f"Failed to cleanup {scan_dir}: {e}")

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "sast-gateway", "version": "1.0.0"}

@app.get("/scanners")
async def list_scanners():
    """List all registered scanners and their status."""
    scanner_status = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for name, info in SCANNER_REGISTRY.items():
            try:
                resp = await client.get(f"http://127.0.0.1:{info['port']}/health")
                scanner_status[name] = {"status": "online", "port": info["port"], "name": info["name"]}
            except:
                scanner_status[name] = {"status": "offline", "port": info["port"], "name": info["name"]}
    return scanner_status

@app.post("/scan")
async def scan_upload(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """Upload a zip file for scanning. Returns scan results."""
    global active_scans
    
    scan_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Create temp directory for extraction
    scan_dir = tempfile.mkdtemp(prefix=f"sast-scan-{scan_id[:8]}-")
    
    try:
        # Save uploaded file
        zip_path = os.path.join(scan_dir, "upload.zip")
        content = await file.read()
        
        with open(zip_path, 'wb') as f:
            f.write(content)
        
        # Extract zip
        if not zipfile.is_zipfile(zip_path):
            cleanup_scan_dir(scan_dir)
            raise HTTPException(status_code=400, detail="Invalid zip file")
        
        extract_dir = os.path.join(scan_dir, "source")
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Security: prevent zip slip
            for member in zf.namelist():
                member_path = os.path.realpath(os.path.join(extract_dir, member))
                if not member_path.startswith(os.path.realpath(extract_dir)):
                    raise HTTPException(status_code=400, detail="Zip contains path traversal")
            zf.extractall(extract_dir)
        
        # Remove zip after extraction to save space
        os.remove(zip_path)
        
        # Collect all source files
        all_files = []
        for root, dirs, files in os.walk(extract_dir):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.svn', 'vendor', 'bin', 'obj', '.idea', '.vs', 'target', 'build', 'dist', '.gradle'}]
            for fname in files:
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, extract_dir)
                all_files.append(rel_path)
        
        # Group files by scanner
        file_groups = group_files_by_scanner(all_files)
        
        if not file_groups:
            cleanup_scan_dir(scan_dir)
            return JSONResponse({
                "scanId": scan_id,
                "vulnerabilities": [],
                "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "filesScanned": len(all_files),
                "scanDuration": f"{time.time() - start_time:.1f}s",
                "message": "No supported source files found"
            })
        
        # Scan with each scanner concurrently
        active_scans += 1
        try:
            tasks = []
            for scanner_name, files in file_groups.items():
                tasks.append(scan_files_with_scanner(scanner_name, files, extract_dir))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            active_scans -= 1
        
        # Merge results
        all_vulns = []
        total_files_scanned = 0
        errors = []
        
        for i, (scanner_name, _) in enumerate(file_groups.items()):
            result = results[i]
            if isinstance(result, Exception):
                errors.append(f"{scanner_name}: {str(result)}")
                continue
            if isinstance(result, dict):
                all_vulns.extend(result.get("vulnerabilities", []))
                total_files_scanned += result.get("filesScanned", 0)
                if "error" in result:
                    errors.append(f"{scanner_name}: {result['error']}")
        
        # Calculate summary
        summary = {"total": len(all_vulns), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in all_vulns:
            sev = v.get("severity", "info").lower()
            if sev in summary:
                summary[sev] += 1
        
        duration = time.time() - start_time
        
        response = {
            "scanId": scan_id,
            "vulnerabilities": all_vulns,
            "summary": summary,
            "filesScanned": total_files_scanned,
            "totalFiles": len(all_files),
            "scanDuration": f"{duration:.1f}s",
            "scannersUsed": list(file_groups.keys()),
        }
        if errors:
            response["errors"] = errors
        
        return JSONResponse(response)
    
    finally:
        # Always cleanup
        cleanup_scan_dir(scan_dir)

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get status of a scan."""
    if scan_id in scan_queue:
        return scan_queue[scan_id]
    raise HTTPException(status_code=404, detail="Scan not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)

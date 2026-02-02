from fastapi import FastAPI, UploadFile, BackgroundTasks, HTTPException, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import tempfile
import shutil
import zipfile
import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uvicorn

# Mas_core
from mas_core.graph import create_scan_graph
from mas_core.state import ScanState

app = FastAPI(
    title="Security Scanner MAS API",
    description="SAST + SCA Security Scanning Service",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

scan_results: Dict[str, Dict[str, Any]] = {}

#=============== Models ================
class ScanRequest(BaseModel):
    project_name: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str 
    progress: Optional[int] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ========== Helper ===============

def extract_codebase(zip_file: UploadFile) -> Path:
    temp_dir = Path(tempfile.mkdtemp(prefix="mas_scan_"))
    zip_path = temp_dir / "codebase.zip"
    with open(zip_path, "wb") as f:
        shutil.copyfileobj(zip_file.file, f)
    
    extract_dir = temp_dir / "project"
    extract_dir.mkdir()
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    
    zip_path.unlink()
    return extract_dir

async def run_scan_task(scan_id: str, project_path: Path):
    """Background task to run MAS scan"""
    try: 
        scan_results[scan_id]["status"] = "scanning"
        scan_results[scan_id]["progress"] = 10

        # initialize MAS
        app_graph = create_scan_graph()
        initial_state: ScanState = {
            'project_path': str(project_path),
            'all_files': [],
            'total_files': 0,
            'sast_results': {},
            'sca_results': {},
            'final_report': {},
            'scan_status': []
        }
        scan_results[scan_id]["progress"] = 30

        #Run scan
        final_state = app_graph.invoke(initial_state)
        
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["progress"] = 100
        scan_results[scan_id]["result"] = final_state['final_report']
        scan_results[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()

    except Exception as e:
        scan_results[scan_id]["status"] = "failed"
        scan_results[scan_id]["error"] = str(e)
        scan_results[scan_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
    
    finally:
        shutil.rmtree(project_path.parent, ignore_errors=True)


# ==================== API Endpoints ====================

@app.get("/")
async def root():
    return {
        "service": "Security Scanner MAS API",
        "version": "1.0.0",
        "status":"running"
    }

@app.post("/scan", response_model=ScanResponse)
async def create_scan(
    background_tasks: BackgroundTasks,
    codebase: UploadFile = File(..., description="Zip file containing project codebase"),
    project_name: str = "unnamed_project"
):
    """
    Upload codebase as ZIP and start security scan
    
    **Request:**
    - **codebase**: ZIP file containing the entire project
    - **project_name**: Optional name for the scan
    
    **Response:**
    - **scan_id**: Unique ID to track scan progress
    - **status**: "pending" (scan queued)
    """
    if not codebase.filename.endswith('.zip'): #type: ignore
        raise HTTPException(status_code=400, detail="Only ZIP files are accepted")

    scan_id = str(uuid.uuid4())
    try:
        project_path = extract_codebase(codebase)
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "project_name": project_name,
            "status": "pending",
            "progress": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "result": None,
            "error": None
        }

        background_tasks.add_task(run_scan_task, scan_id, project_path)
        return ScanResponse(
            scan_id=scan_id,
            status="pending",
            message=f"Scan started for {project_name}"
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")
    
@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """
    Get scan status and results
    
    **Parameters:**
    - **scan_id**: UUID from /scan endpoint
    
    **Response:**
    - **status**: "pending" | "scanning" | "completed" | "failed"
    - **progress**: 0-100 (percentage)
    - **result**: Full scan report (only when status="completed")
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    scan_data = scan_results[scan_id]
    return ScanStatusResponse(
        scan_id=scan_id,
        status = scan_data["status"],
        progress = scan_data.get("progress"),
        result = scan_data.get("result"),
        error = scan_data.get("error")
    )

@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete scan record"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    
    del scan_results[scan_id]
    return {"message": "Scan record deleted"}

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "active_scans": len([s for s in scan_results.values()
                              if s["status"] == "scanning"]),
        "total_scans": len(scan_results)
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
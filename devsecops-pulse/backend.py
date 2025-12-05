from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response


from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict
import os
import random


REQUEST_COUNT = Counter('devsecops_requests_total', 'Total requests')
REQUEST_LATENCY = Histogram('devsecops_request_latency_seconds', 'Request latency')




app = FastAPI(title="DevSecOps Pulse API")

@app.middleware("http")
async def add_metrics(request, call_next):
    REQUEST_COUNT.inc()
    import time
    start = time.time()
    response = await call_next(request)
    REQUEST_LATENCY.observe(time.time() - start)
    return response

@app.get("/metrics")
def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)



@app.middleware("http")
async def set_security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    return resp


# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GitHub API Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "your_token_here")
REPO_OWNER = "UzairRan"
REPO_NAME = "Devsecops-pipeline-artifact"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/api/workflow-runs")
def get_workflow_runs():
    """Get real GitHub Actions workflow runs"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs"
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        data = response.json()
        
        runs = []
        for run in data.get("workflow_runs", [])[:50]:  # Last 50 runs
            runs.append({
                "id": run["id"],
                "run_number": run["run_number"],
                "status": run["status"],
                "conclusion": run["conclusion"],
                "created_at": run["created_at"],
                "updated_at": run["updated_at"],
                "head_branch": run["head_branch"],
                "duration": calculate_duration(run),
                "html_url": run["html_url"]
            })
        
        return {"total_count": data["total_count"], "runs": runs}
    
    except Exception as e:
        return {"error": str(e), "runs": []}

@app.get("/api/workflow-run/{run_id}")
def get_workflow_run_details(run_id: int):
    """Get details for a specific workflow run"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}"
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/workflow-jobs/{run_id}")
def get_workflow_jobs(run_id: int):
    """Get jobs for a specific workflow run"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs/{run_id}/jobs"
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/metrics")
def get_pipeline_metrics(days: int = 30):
    """Generate pipeline metrics from real GitHub Actions data"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/runs"
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        data = response.json()
        
        # Calculate metrics
        runs = data.get("workflow_runs", [])
        successful_runs = [r for r in runs if r.get("conclusion") == "success"]
        failed_runs = [r for r in runs if r.get("conclusion") == "failure"]
        
        # Get recent runs (last N days) - FIXED TIMEZONE ISSUE
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        recent_runs = [
            r for r in runs 
            if datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")) > cutoff_date
        ]
        
        # Generate time series data
        metrics = []
        for i in range(days):
            date = datetime.now() - timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            
            # Count runs for this day
            day_runs = [
                r for r in recent_runs 
                if r["created_at"].startswith(date_str)
            ]
            
            day_success = [r for r in day_runs if r.get("conclusion") == "success"]
            
            metrics.append({
                "Date": date.strftime("%Y-%m-%d"),
                "Success Rate (%)": (len(day_success) / len(day_runs) * 100) if day_runs else 100,
                "Build Time (s)": calculate_avg_duration(day_runs),
                "Vulnerabilities": random.randint(0, 10),  # Mock data
                "Environment": "Production" if i % 3 == 0 else ("Staging" if i % 3 == 1 else "Development")
            })
        
        # Calculate overall metrics
        total_runs = len(recent_runs)
        success_rate = (len(successful_runs) / len(runs) * 100) if runs else 100
        
        return {
            "metrics": metrics[::-1],  # Reverse to show oldest first
            "summary": {
                "total_runs": total_runs,
                "success_rate": round(success_rate, 1),
                "avg_build_time": calculate_avg_duration(recent_runs),
                "failed_runs": len(failed_runs)
            }
        }
    
    except Exception as e:
        return {"error": str(e), "metrics": [], "summary": {}}

@app.get("/api/vulnerabilities")
def get_vulnerabilities():
    """Get vulnerability data (mock - replace with real Trivy/SonarQube data)"""
    return [
        {
            "id": "CVE-2023-12345",
            "package": "requests",
            "severity": "High",
            "title": "Insecure Temporary File in Requests",
            "environment": "Production"
        },
        {
            "id": "CVE-2023-67890",
            "package": "urllib3",
            "severity": "Medium", 
            "title": "CRLF Injection in urllib3",
            "environment": "Development"
        }
    ]

@app.get("/api/logs/{job_id}")
def get_job_logs(job_id: int):
    """Get logs for a specific job"""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/jobs/{job_id}/logs" 
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        return {"logs": response.text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Helper functions
def calculate_duration(run):
    """Calculate duration of a workflow run"""
    if run.get("status") != "completed":
        return None
    
    created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    updated = datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00"))
    duration = (updated - created).total_seconds()
    return duration

def calculate_avg_duration(runs):
    """Calculate average duration of runs"""
    if not runs:
        return 60
    
    total = 0
    count = 0
    for run in runs:
        duration = calculate_duration(run)
        if duration:
            total += duration
            count += 1
    
    return round(total / count, 1) if count > 0 else 60

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000) 
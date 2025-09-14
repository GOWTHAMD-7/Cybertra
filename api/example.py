"""
Simplified example to demonstrate the deployment structure.
This file should work when deployed to Vercel.
"""

# Import necessary modules
from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from bs4 import BeautifulSoup
import httpx
import os
import re
import datetime

# Initialize FastAPI app
app = FastAPI()

# Configure templates - assumes templates are at project root level
templates_dir = os.path.join(os.getcwd(), "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Render the home page"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "timestamp": datetime.datetime.now().isoformat()}

@app.post("/analyze")
async def analyze_url(url: str = Form(...)):
    """Process URL for analysis"""
    # Basic validation
    if not url:
        return JSONResponse(content={"error": "URL cannot be empty"}, status_code=400)
        
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Run basic security analysis
    security_score = 100
    security_concerns = []
    
    if url.startswith('http://'):
        security_concerns.append("Uses insecure HTTP protocol")
        security_score -= 20
    
    # Return a simplified response for testing
    result = {
        "url": url,
        "security_score": security_score,
        "security_concerns": security_concerns if security_concerns else ["No obvious security concerns detected"],
        "webpage_info": {
            "success": True,
            "title": "Test Page",
            "summary": "This is a test summary for debugging purposes.",
            "keywords": ["test", "debug", "vercel", "deployment"]
        }
    }
    
    return JSONResponse(content=result)
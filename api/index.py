from fastapi import FastAPI, Request, Depends, Form
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import sys
import os
import json
from typing import Optional
import re
import datetime

# Add the parent directory to sys.path to import from project files
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the serverless adapter
from serverless_adapters import serverless_scrape_webpage

# Create a new FastAPI app for serverless
app = FastAPI(title="Cybertra – Defending Your Digital Path")

# Set up Jinja2 templates
templates_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
templates = Jinja2Templates(directory=templates_path)

# Home page route
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# URL analysis endpoint
@app.post("/analyze")
async def analyze_url(url: str = Form(...)):
    """
    Analyze a URL for potential security threats and summarize the webpage.
    """
    # Basic URL validation
    if not url:
        return JSONResponse(content={"error": "URL cannot be empty"}, status_code=400)
    
    # Add http:// if not present
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    try:
        # Use the serverless version of the scraper
        webpage_info = await serverless_scrape_webpage(url)
        
        # Simple security check based on URL patterns
        security_concerns = []
        security_score = 100
        
        # Check for HTTP (not HTTPS)
        if url.startswith('http://'):
            security_concerns.append("Uses insecure HTTP protocol instead of HTTPS")
            security_score -= 20
            
        # Check for suspicious keywords in URL
        suspicious_keywords = ['phishing', 'login', 'secure', 'account', 'banking', 'verify']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                security_concerns.append(f"URL contains potentially suspicious keyword: '{keyword}'")
                security_score -= 5
                
        # Check for excessive subdomains
        subdomain_count = len(url.split('//')[1].split('/')[0].split('.')) - 2
        if subdomain_count > 3:
            security_concerns.append(f"URL has an unusually high number of subdomains ({subdomain_count})")
            security_score -= 10
            
        # Check for very long URLs
        if len(url) > 100:
            security_concerns.append(f"URL is unusually long ({len(url)} characters)")
            security_score -= 5
            
        # Compile results
        result = {
            "url": url,
            "analysis_time": datetime.datetime.now().isoformat(),
            "security_score": max(0, security_score),
            "security_concerns": security_concerns if security_concerns else ["No obvious security concerns detected"],
            "webpage_info": webpage_info
        }
        
        return JSONResponse(content=result)
        
    except Exception as e:
        return JSONResponse(
            content={
                "error": f"Error analyzing URL: {str(e)}",
                "url": url
            },
            status_code=500
        )

# This handler is required for Vercel serverless functions
def handler(request, context):
    return app
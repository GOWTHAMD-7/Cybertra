"""
Entry point for the API. Creates the FastAPI app with all routes.
All functionality is defined in this file to avoid import issues.
"""
from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import os
import json
import re
import datetime
import httpx
from bs4 import BeautifulSoup

# Create a new FastAPI app for serverless
app = FastAPI(title="Cybertra – Defending Your Digital Path")

# Set up Jinja2 templates - direct path to ensure proper resolution in Vercel
current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))

async def serverless_scrape_webpage(url: str) -> dict:
    """
    A serverless-friendly version of the webpage scraper that doesn't use Selenium.
    Uses httpx for HTTP requests instead of a full browser.
    """
    try:
        # Use httpx to fetch the page
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
            }
            
            response = await client.get(url, headers=headers)
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "title": "Error",
                    "summary": f"Error accessing webpage. Status code: {response.status_code}",
                    "detailed_summary": f"Unable to access the webpage. The server returned a {response.status_code} status code.",
                    "keywords": [],
                    "content_length": 0,
                    "scraping_blocked": True,
                    "blocking_reason": f"HTTP status code: {response.status_code}"
                }
            
            # Get content
            content = response.text
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Get title
            page_title = soup.title.string if soup.title else "Untitled Page"
            
            # Get meta description
            meta_description = ""
            meta_tag = soup.find("meta", attrs={"name": "description"})
            if meta_tag and meta_tag.get("content"):
                meta_description = meta_tag.get("content")
            
            # Extract text content
            for script in soup(["script", "style", "header", "footer", "nav"]):
                script.extract()
                
            # Get text
            text = soup.get_text(separator=' ', strip=True)
            
            # Clean up text
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            text_content = ' '.join(lines)
            
            # Simple summarization
            sentences = re.split(r'(?<=[.!?])\s+', text_content)
            summary = ' '.join(sentences[:3])
            if len(summary) > 250:
                summary = summary[:250] + "..."
                
            # Extract keywords
            words = re.findall(r'\b[a-zA-Z]{3,15}\b', text_content.lower())
            word_freq = {}
            
            # Common stopwords
            stopwords = {'the', 'and', 'is', 'in', 'to', 'of', 'for', 'with', 'on', 'at'}
            
            for word in words:
                if word not in stopwords and len(word) > 3:
                    word_freq[word] = word_freq.get(word, 0) + 1
                    
            # Get top keywords
            keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:15]
            keywords = [k[0] for k in keywords]
            
            # Basic summary for serverless environment
            detailed_summary = f"This webpage titled '{page_title}' contains information related to {', '.join(keywords[:3])}. "
            detailed_summary += f"The page has approximately {len(text_content)} characters of text content. "
            detailed_summary += f"The main topics appear to include {', '.join(keywords[:5])}."
            
            return {
                "success": True,
                "title": page_title,
                "summary": meta_description or summary,
                "detailed_summary": detailed_summary,
                "keywords": keywords,
                "content_length": len(text_content),
                "scraping_blocked": False,
                "error": None
            }
            
    except Exception as e:
        return {
            "success": False,
            "title": "Error",
            "summary": "Error analyzing webpage content",
            "detailed_summary": f"Error details: {str(e)}",
            "keywords": [],
            "content_length": 0,
            "scraping_blocked": True,
            "blocking_reason": str(e),
            "error": str(e)
        }

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

# Health check endpoint
@app.get("/api/health")
async def health():
    return {"status": "ok"}

# For Vercel serverless deployment
def handler(req, context):
    # Return ASGI app
    return app
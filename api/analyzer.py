"""
URL analyzer in a Vercel-compatible format
"""
from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import re
import httpx
from datetime import datetime
from bs4 import BeautifulSoup

async def analyze_url(url):
    """
    Analyze a URL for security issues and content summary
    """
    # Basic URL validation
    if not url:
        return {"error": "URL cannot be empty"}
    
    # Add http:// if not present
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Fetch webpage content
        async with httpx.AsyncClient(follow_redirects=True) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            response = await client.get(url, headers=headers, timeout=15.0)
            
            # Basic page info
            status_code = response.status_code
            content_type = response.headers.get("content-type", "")
            
            # Parse HTML if possible
            webpage_info = {}
            if "text/html" in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract title
                title = soup.title.string if soup.title else "No title found"
                
                # Extract meta description
                meta_desc = ""
                meta_tag = soup.find("meta", attrs={"name": "description"})
                if meta_tag and meta_tag.get("content"):
                    meta_desc = meta_tag.get("content")
                
                # Extract some text content
                for script in soup(["script", "style"]):
                    script.decompose()
                
                text = soup.get_text(separator=' ', strip=True)
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                text_content = ' '.join(lines)
                
                # Basic summary (first few lines)
                summary = ' '.join(lines[:3]) if lines else ""
                if len(summary) > 200:
                    summary = summary[:200] + "..."
                
                webpage_info = {
                    "title": title,
                    "summary": meta_desc or summary,
                    "content_length": len(text_content)
                }
            else:
                webpage_info = {
                    "title": "Non-HTML content",
                    "summary": f"Content type: {content_type}",
                    "content_length": len(response.content)
                }
        
        # Security analysis
        security_concerns = []
        security_score = 100
        
        # Check for HTTP instead of HTTPS
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
        
        # Check URL length
        if len(url) > 100:
            security_concerns.append(f"URL is unusually long ({len(url)} characters)")
            security_score -= 5
            
        # Compile results
        result = {
            "url": url,
            "analysis_time": datetime.now().isoformat(),
            "security_score": max(0, security_score),
            "security_concerns": security_concerns if security_concerns else ["No obvious security concerns detected"],
            "webpage_info": webpage_info
        }
        
        return result
    
    except Exception as e:
        return {
            "error": f"Error analyzing URL: {str(e)}",
            "url": url
        }

class handler(BaseHTTPRequestHandler):
    async def _process_request(self):
        """Process the incoming request"""
        # Parse URL parameters
        url_components = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(url_components.query)
        
        # Get URL parameter from query string
        url = query_params.get('url', [''])[0]
        
        # Process the URL
        if url:
            result = await analyze_url(url)
        else:
            result = {
                "message": "Welcome to Cybertra URL Analyzer API",
                "usage": "Add ?url=example.com to analyze a URL",
                "status": "ok"
            }
        
        return result
    
    def do_GET(self):
        import asyncio
        
        # Run the async function
        result = asyncio.run(self._process_request())
        
        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())
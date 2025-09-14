"""
This file contains adaptations for serverless environments.
It replaces functionality that requires resources not available
in Vercel's serverless environment.
"""

import json
import httpx
import re
from bs4 import BeautifulSoup

async def serverless_scrape_webpage(url: str) -> dict:
    """
    A serverless-friendly version of the webpage scraper that doesn't use Selenium.
    Uses httpx for HTTP requests instead of a full browser.
    """
    try:
        # Use httpx to fetch the page
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0"
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
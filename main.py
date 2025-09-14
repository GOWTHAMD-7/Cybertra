from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, HttpUrl
from typing import Any, Dict, List
import os
import httpx
import socket
import base64
import time
import asyncio
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime
from dotenv import load_dotenv
import subprocess
import sys
import json
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from concurrent.futures import ThreadPoolExecutor

# Import our AI synthesizer modules
from ai_synthesizer_direct import analyze_url_ai as analyze_url_ai_direct
from ai_synthesizer_openai import analyze_url_ai as analyze_url_ai_openai
from ai_cache import get_cached_ai_response, cache_ai_response

load_dotenv()

app = FastAPI(
    title="URL Sandbox API",
    description="Checks if a URL is malicious using Google Safe Browsing (placeholder).",
    version="0.1.0"
)

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up templates
templates = Jinja2Templates(directory="templates")


# Request model for the /analyze-url endpoint
class URLRequest(BaseModel):
    url: HttpUrl  # Validates that the input is a proper URL

async def unwrap_shortened_url(url: str) -> dict:
    """
    Follows URL redirects to get the final destination URL from shortened URLs.
    Uses HEAD requests to safely retrieve redirect information without downloading content.
    
    Args:
        url: The URL to check for redirection
        
    Returns:
        A dictionary with:
        - original_url: The original URL
        - final_url: The final destination URL after following redirects
        - is_shortened: Whether the original URL was a known URL shortener
        - redirect_chain: List of all URLs in the redirect chain
        - error: Error message if any issues occurred
    """
    # List of known URL shortener domains
    url_shorteners = [
        't.co', 'bit.ly', 'tinyurl.com', 'goo.gl', 'is.gd', 'cli.gs', 'pic.gd',
        'DwarfURL.com', 'ow.ly', 'snurl.com', 'short.to', 'BudURL.com', 'tr.im',
        'Shrinkify.com', 'snipurl.com', 'lnk.co', 'x.co', 'links.net', 'qr.net',
        'tiny.cc', 'bl.ink', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'adf.ly',
        'shorturl.at', 'rb.gy', 'zpr.io', 'v.gd'
    ]
    
    result = {
        "original_url": url,
        "final_url": url,  # Default to original URL
        "is_shortened": False,
        "redirect_chain": [],
        "error": None
    }
    
    try:
        # Parse URL to extract domain
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.lower()
        
        # Remove 'www.' if present
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        
        # Check if this is a known URL shortener
        is_shortener = False
        for shortener in url_shorteners:
            if hostname == shortener or hostname.endswith('.' + shortener):
                is_shortener = True
                result["is_shortened"] = True
                break
        
        # If it's not a known shortener, but we should check for redirects anyway
        # to catch custom domains that redirect
        max_redirects = 10  # Limit to prevent infinite loops
        current_url = url
        redirect_chain = []
        
        # Setup client with redirect handling disabled so we can track them manually
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            for _ in range(max_redirects):
                try:
                    # Send HEAD request to check for redirects without downloading content
                    response = await client.head(current_url, allow_redirects=False)
                    
                    # Add current URL to chain
                    redirect_chain.append(current_url)
                    
                    # Check if we got a redirect status code
                    if response.status_code in (301, 302, 303, 307, 308):
                        # Get the redirect location
                        if 'location' in response.headers:
                            # Create absolute URL if relative
                            next_url = response.headers['location']
                            if not next_url.startswith(('http://', 'https://')):
                                next_url = urljoin(current_url, next_url)
                            
                            # Update current URL and continue
                            current_url = next_url
                            continue
                    
                    # If we reach here, it means no more redirects
                    break
                    
                except httpx.RequestError as e:
                    # Handle timeout or connection errors
                    result["error"] = f"Error following redirect: {str(e)}"
                    break
        
        # Set final results
        result["redirect_chain"] = redirect_chain
        if redirect_chain:
            result["final_url"] = redirect_chain[-1]
            
            # If we detected redirects, mark it as shortened even if not in our list
            if len(redirect_chain) > 1:
                result["is_shortened"] = True
                
        return result
    
    except Exception as e:
        # Handle any unexpected errors
        result["error"] = f"Error processing URL: {str(e)}"
        return result

def is_shared_domain(hostname: str) -> dict:
    """
    Checks if a hostname is a shared/hosting domain where users can create subdomains.
    Also categorizes the type of shared domain and provides risk assessment.
    
    Args:
        hostname: The hostname to check
        
    Returns:
        A dictionary with:
        - is_shared: Boolean indicating if it's a shared domain
        - category: The category of the shared domain (if applicable)
        - risk_level: Risk assessment for this type of shared domain
        - platform: The specific platform detected
    """
    # Categorized shared domain lists
    shared_domains = {
        "cloud_hosting": {
            "domains": [
                'vercel.app', 'netlify.app', 'herokuapp.com', 'onrender.com',
                'surge.sh', 'now.sh', 'workers.dev', 'azurewebsites.net', 'appspot.com',
                'pythonanywhere.com', 'fly.dev', 'deta.app', 'deta.dev', 'railway.app',
                'render.com', 'cyclic.app', 'adaptable.app', 'hop.io', 'koyeb.app',
                'beanstalkapp.com', 'webscript.io', 'elasticbeanstalk.com', 'cloudrun.app',
                'web.app', 'firebaseapp.com', 'site.webpubsub.azure.com'
            ],
            "risk_level": "medium",
            "description": "Cloud hosting platforms where users can deploy web applications."
        },
        "code_hosting": {
            "domains": [
                'github.io', 'gitlab.io', 'repl.co', 'glitch.me', 'codepen.io',
                'codesandbox.io', 'pages.dev', 'gitbook.io', 'gist.github.com',
                'jsfiddle.net', 'stackblitz.io', 'codeply.com', 'neocities.org',
                'gitpod.io', 'cs50.io', 'playcode.io'
            ],
            "risk_level": "medium-low",
            "description": "Code hosting and development platforms with web page capabilities."
        },
        "content_delivery": {
            "domains": [
                'cloudfront.net', 'akamaized.net', 'cloudflare.net', 'fastly.net',
                'edgecast.net', 'cdn77.org', 'cdnjs.com', 'jsdelivr.net',
                'unpkg.com', 'statically.io', 'keycdn.com'
            ],
            "risk_level": "low",
            "description": "Content delivery networks typically used by legitimate organizations."
        },
        "blogging_platforms": {
            "domains": [
                'blogspot.com', 'wordpress.com', 'medium.com', 'tumblr.com',
                'svbtle.com', 'blogger.com', 'weebly.com', 'ghost.io', 'wix.com',
                'substack.com', 'hashnode.dev', 'bearblog.dev', 'notion.site',
                'posthaven.com', 'telegraph.telegraph.co.uk'
            ],
            "risk_level": "medium-low",
            "description": "Blogging and content platforms where users can create their own sites."
        },
        "site_builders": {
            "domains": [
                'wixsite.com', 'squarespace.com', 'webflow.io', 'myshopify.com',
                'godaddysites.com', 'strikingly.com', 'carrd.co', 'tilda.ws',
                'weebly.com', 'jimdosite.com', 'cargo.site', 'bubble.io',
                'webnode.com', 'yolasite.com', 'simdif.com', 'duda.co',
                'wix.to', 'wix.com', 'site123.com', 'square.site', 'shopify.com'
            ],
            "risk_level": "medium",
            "description": "Website builders and e-commerce platforms offering hosted solutions."
        },
        "url_shorteners": {
            "domains": [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs',
                'ow.ly', 'snurl.com', 'short.to', 'tr.im', 'snipurl.com',
                'lnk.co', 'x.co', 'tiny.cc', 'bl.ink', 'buff.ly', 'cutt.ly',
                'rebrand.ly', 'adf.ly', 'shorturl.at', 'rb.gy', 'zpr.io', 'v.gd',
                'tinycc.com', 'y.at', 'snip.ly', 'urlz.fr', 'shrtco.de'
            ],
            "risk_level": "high",
            "description": "URL shorteners commonly used to disguise malicious links."
        },
        "dynamic_dns": {
            "domains": [
                'ddns.net', 'hopto.org', 'no-ip.org', 'no-ip.biz', 'zapto.org',
                'myftp.biz', 'myftp.org', 'duckdns.org', 'dynu.net', 'mooo.com',
                'chickenkiller.com', 'crabdance.com', 'strangled.net', 'servebeer.com',
                'serveblog.net', 'servehalflife.com', 'servehttp.com', 'serveirc.com',
                'serveminecraft.net', 'dynv6.net', 'bounceme.net', 'freedynamicdns.org'
            ],
            "risk_level": "high",
            "description": "Dynamic DNS services often used in malware campaigns."
        },
        "free_domains": {
            "domains": [
                'tk', 'ml', 'ga', 'cf', 'gq', 'co.nf', 'eu.org', 'epizy.com',
                'rf.gd', 'com.de', 'co.vu', 'c1.biz', 'biz.nf', 'eu5.org', '96.lt',
                '6te.net', 'co.nr', 'ueuo.com', 'za.net', 'za.org', 'orgfree.com'
            ],
            "risk_level": "very_high",
            "description": "Free domain providers highly abused for phishing and malware."
        },
        "education": {
            "domains": [
                'edu', 'ac.uk', 'edu.au', 'edu.cn', 'ac.jp', 'edu.sg', 'ac.nz',
                'edu.hk', 'sch.uk', 'k12.il.us', 'school.nz', 'gouv.fr', 'gov.uk'
            ],
            "risk_level": "very_low",
            "description": "Educational and government institutions, generally trustworthy."
        }
    }
    
    result = {
        "is_shared": False,
        "category": None,
        "risk_level": "unknown",
        "platform": None,
        "description": None
    }
    
    # Remove 'www.' if present
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    
    # Check top-level domains for free domains category
    tld = hostname.split('.')[-1]
    if tld in shared_domains["free_domains"]["domains"]:
        result["is_shared"] = True
        result["category"] = "free_domains"
        result["risk_level"] = shared_domains["free_domains"]["risk_level"]
        result["platform"] = tld
        result["description"] = shared_domains["free_domains"]["description"]
        return result
    
    # Check all domains in all categories
    for category, data in shared_domains.items():
        for domain in data["domains"]:
            if hostname.endswith('.' + domain) or hostname == domain:
                result["is_shared"] = True
                result["category"] = category
                result["risk_level"] = data["risk_level"]
                result["platform"] = domain
                result["description"] = data["description"]
                return result
    
    # Check for common hosting patterns
    hosting_patterns = [
        # Format: (regex pattern, category, risk_level, description)
        (r'\.github\.io$', "code_hosting", "medium-low", "GitHub Pages hosting"),
        (r'\.s3\.amazonaws\.com$', "cloud_hosting", "medium", "Amazon S3 public bucket"),
        (r'\.blob\.core\.windows\.net$', "cloud_hosting", "medium", "Azure Blob Storage"),
        (r'\.storage\.googleapis\.com$', "cloud_hosting", "medium", "Google Cloud Storage"),
        (r'\.sharepoint\.com$', "cloud_hosting", "low", "Microsoft SharePoint"),
        (r'\.myportfolio\.com$', "site_builders", "low", "Adobe Portfolio"),
        (r'\.cdn\.ampproject\.org$', "content_delivery", "low", "Google AMP Cache"),
        (r'\.github\.dev$', "code_hosting", "medium-low", "GitHub Codespaces"),
        (r'\.gitlab\.io$', "code_hosting", "medium-low", "GitLab Pages"),
        (r'\.000webhostapp\.com$', "cloud_hosting", "high", "000webhost free hosting"),
        (r'\.freetzi\.com$', "cloud_hosting", "high", "FreeTzi free hosting"),
        (r'\.great-site\.net$', "cloud_hosting", "high", "InfinityFree hosting"),
        (r'-[a-f0-9]{8}\.ngrok\.io$', "cloud_hosting", "high", "Ngrok tunnel"),
        (r'\.loophole\.site$', "cloud_hosting", "high", "Loophole tunnel")
    ]
    
    import re
    for pattern, category, risk, description in hosting_patterns:
        if re.search(pattern, hostname):
            result["is_shared"] = True
            result["category"] = category
            result["risk_level"] = risk
            result["platform"] = re.search(pattern, hostname).group(0)
            result["description"] = description
            return result
    
    return result

def analyze_url_heuristics(url: str) -> list:
    """
    Analyzes a URL string for common phishing tricks and patterns.
    
    Args:
        url: The URL string to analyze
        
    Returns:
        A list of strings describing any red flags found. Empty list if none.
    """
    red_flags = []
    
    # Parse the URL to get its components
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        # Remove 'www.' from hostname if present for better analysis
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        
        # 1. Keyword Stuffing - Check for sensitive keywords
        sensitive_keywords = [
            'login', 'secure', 'account', 'verify', 'bank', 'password',
            'sbi', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix',
            'wallet', 'payment', 'credit', 'signin', 'security', 'update',
            'confirm', 'authorize', 'auth', 'ebay', 'facebook', 'google',
            'instagram', 'docusign', 'dropbox', 'twitter', 'billing', 'chase',
            'bankofamerica', 'wellsfargo', 'citibank', 'coinbase', 'crypto',
            'blockchain', 'bitcoin', 'alert', 'verify', 'invoice', 'access',
            'recover', 'reset', 'validation'
        ]
        
        path_and_params = (parsed.path + parsed.params + parsed.query).lower()
        
        for keyword in sensitive_keywords:
            if keyword in hostname:
                red_flags.append(f"Contains sensitive keyword in domain: '{keyword}'")
            elif keyword in path_and_params:
                red_flags.append(f"Contains sensitive keyword in URL path: '{keyword}'")
        
        # 2. Suspicious TLD - Check for commonly abused TLDs
        suspicious_tlds = [
            '.xyz', '.top', '.info', '.loan', '.zip', '.club', '.work', 
            '.website', '.space', '.online', '.site', '.gq', '.cf', '.ga', 
            '.ml', '.tk', '.pw', '.fun', '.monster', '.icu', '.click', '.link',
            '.app', '.live', '.tech', '.uno', '.stream', '.bid', '.best', '.tokyo',
            '.date', '.today', '.casa', '.cyou', '.rest', '.skin', '.hair', '.men',
            '.quest', '.email', '.digital', '.host', '.bar', '.surf', '.sale', '.uno'
        ]
        
        for tld in suspicious_tlds:
            if hostname.endswith(tld):
                red_flags.append(f"Uses suspicious TLD: '{tld}'")
                break
        
        # 3. Subdomain Count - Check for excessive subdomains
        subdomain_count = hostname.count('.')
        if subdomain_count > 3:
            red_flags.append(f"Has an excessive number of subdomains ({subdomain_count})")
        
        # 4. Domain Length - Excessively long domain names can be suspicious
        if len(hostname) > 30:
            red_flags.append(f"Domain name is unusually long ({len(hostname)} characters)")
        
        # 5. Number/Special Character Substitution - Check for character substitution tricks
        substitution_patterns = [
            ('0', 'o'), ('1', 'l'), ('1', 'i'), ('5', 's'), 
            ('@', 'a'), ('3', 'e'), ('$', 's'), ('4', 'a'),
            ('8', 'b'), ('6', 'g'), ('7', 't'), ('2', 'z')
        ]
        
        # Brand names commonly targeted in phishing
        common_brands = [
            'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix',
            'twitter', 'instagram', 'linkedin', 'youtube', 'gmail', 'outlook', 'icloud',
            'yahoo', 'whatsapp', 'snapchat', 'tiktok', 'spotify', 'reddit', 'pinterest',
            'dropbox', 'onedrive', 'chase', 'bankofamerica', 'wellsfargo', 'citibank',
            'americanexpress', 'mastercard', 'visa', 'coinbase', 'binance', 'blockchain',
            'steam', 'xbox', 'playstation', 'nintendo', 'wordpress', 'shopify', 'etsy'
        ]
        
        for num, char in substitution_patterns:
            if num in hostname:
                for brand in common_brands:
                    modified_brand = brand.replace(char, num)
                    if modified_brand in hostname and brand not in hostname:
                        red_flags.append(f"Possible character substitution: '{num}' for '{char}' (resembling {brand})")
        
        # 6. Check for IP address instead of domain name
        import re
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(hostname):
            red_flags.append("Uses IP address instead of domain name")
        
        # 7. Check for URL shorteners
        url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'tiny.cc',
            'is.gd', 'cli.gs', 'pic.gd', 'ow.ly', 'soo.gd', 'cutt.ly',
            'rebrand.ly', 'adf.ly', 'shorturl.at', 'rb.gy', 'zpr.io', 'v.gd'
        ]
        
        # Improved URL shortener detection to avoid false positives
        # Now checks if the hostname is exactly a shortener or ends with ".shortener.tld"
        for shortener in url_shorteners:
            if hostname == shortener or hostname.endswith('.' + shortener):
                red_flags.append(f"Uses URL shortener: '{shortener}'")
                break
        
        # 8. Check for URL encoding abuse
        if '%' in url and url.count('%') > 3:
            red_flags.append(f"Excessive URL encoding: contains {url.count('%')} percent-encoded characters")
        
        # 9. Check for overly complex URL structure
        if len(url) > 100:
            red_flags.append(f"Excessively long URL ({len(url)} characters)")
        
        # 10. Check for unusual port numbers
        if parsed.port is not None and parsed.port not in [80, 443, 8080, 8443]:
            red_flags.append(f"Uses unusual port number: {parsed.port}")
        
        # 11. Check for large number of dots/special characters
        special_char_count = sum(1 for c in url if not (c.isalnum() or c in '/:.?=&-_'))
        if special_char_count > 10:
            red_flags.append(f"Excessive special characters: {special_char_count} special characters")
        
        # 12. Check for uncommon protocols
        if not parsed.scheme.startswith('http'):
            red_flags.append(f"Uses uncommon protocol: {parsed.scheme}")
        
        # 13. Check for misspelled domains (basic check)
        misspelled_domains = {
            'goggle': 'google', 'facbook': 'facebook', 'facebok': 'facebook', 
            'twiter': 'twitter', 'twittr': 'twitter', 'youtub': 'youtube',
            'paypall': 'paypal', 'paypl': 'paypal', 'gogle': 'google',
            'yhoo': 'yahoo', 'yaho': 'yahoo', 'amzon': 'amazon',
            'aple': 'apple', 'microsft': 'microsoft', 'micorsoft': 'microsoft',
            'linkdin': 'linkedin', 'netflx': 'netflix', 'instgram': 'instagram',
            'whatapp': 'whatsapp', 'whattsapp': 'whatsapp'
        }
        
        for misspelled, correct in misspelled_domains.items():
            if misspelled in hostname and correct not in hostname:
                red_flags.append(f"Possible misspelled domain: '{misspelled}' (should be '{correct}')")
        
        # 14. Check for excessive hyphens
        if hostname.count('-') > 3:
            red_flags.append(f"Excessive hyphens in domain: {hostname.count('-')} hyphens")
        
        # 15. Check for unusual character combinations
        unusual_patterns = ['xn--', '00x', '0x0', '.0.', '.00', '..']
        for pattern in unusual_patterns:
            if pattern in hostname:
                red_flags.append(f"Contains unusual character pattern: '{pattern}'")
        
    except Exception as e:
        red_flags.append(f"Error analyzing URL: {str(e)}")
    
    return red_flags


# Async function to check URL with VirusTotal API
async def check_virustotal(url: str, api_key: str) -> dict:
    """
    Check the URL using VirusTotal API.
    Returns a dictionary with vt_score and creation_date_unix.
    """
    try:
        # First, create a Base64 URL-safe encoded version of the URL
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Set up the API endpoint and headers
        headers = {
            "x-apikey": api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # Try to get analysis first
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        async with httpx.AsyncClient() as client:
            try:
                # First try to get existing analysis
                response = await client.get(endpoint, headers=headers)
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    # URL hasn't been analyzed before, submit it for scanning
                    scan_endpoint = "https://www.virustotal.com/api/v3/urls"
                    payload = f"url={url}"
                    
                    scan_response = await client.post(
                        scan_endpoint, 
                        headers=headers, 
                        content=payload
                    )
                    scan_response.raise_for_status()
                    
                    # Get the analysis ID from the response
                    scan_data = scan_response.json()
                    analysis_id = scan_data.get("data", {}).get("id")
                    
                    if not analysis_id:
                        return {
                            "verdict": "Error", 
                            "message": "Failed to submit URL for analysis"
                        }
                    
                    # Now wait for analysis to complete and get results
                    analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    
                    # Try up to 3 times with a delay between attempts
                    max_attempts = 3
                    for attempt in range(max_attempts):
                        await asyncio.sleep(2)  # Wait for analysis to complete
                        
                        analysis_response = await client.get(
                            analysis_endpoint, 
                            headers={"x-apikey": api_key}
                        )
                        analysis_response.raise_for_status()
                        data = analysis_response.json()
                        
                        status = data.get("data", {}).get("attributes", {}).get("status")
                        if status == "completed":
                            break
                        
                        if attempt == max_attempts - 1:
                            return {
                                "verdict": "Pending", 
                                "message": "VirusTotal analysis is still in progress"
                            }
                else:
                    # Some other error occurred
                    raise
        
        # Extract the malicious detections count
        malicious_count = data.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)
        if malicious_count == 0:
            # Check for "suspicious" results as well
            malicious_count += data.get("data", {}).get("attributes", {}).get("stats", {}).get("suspicious", 0)
        
        # Try to get additional information about the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Get domain information
        domain_endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
        domain_info = {}
        
        try:
            async with httpx.AsyncClient() as client:
                domain_response = await client.get(
                    domain_endpoint, 
                    headers={"x-apikey": api_key}
                )
                domain_response.raise_for_status()
                domain_data = domain_response.json()
                
                # Extract creation date
                creation_date_str = domain_data.get("data", {}).get("attributes", {}).get("creation_date")
                whois_data = domain_data.get("data", {}).get("attributes", {}).get("whois", "")
                creation_date_unix = 0
                
                if creation_date_str:
                    # If directly available in the API response
                    creation_date_unix = int(creation_date_str)
                elif whois_data:
                    # Try to extract from WHOIS data
                    import re
                    
                    # Common date patterns in WHOIS
                    date_patterns = [
                        r"Creation Date: (.+)",
                        r"created: (.+)",
                        r"Created on: (.+)",
                        r"Domain Registration Date: (.+)"
                    ]
                    
                    for pattern in date_patterns:
                        match = re.search(pattern, whois_data)
                        if match:
                            date_str = match.group(1).strip()
                            try:
                                # Try to parse date - this is a simplified approach
                                # Different date formats might require different handling
                                dt = None
                                date_formats = [
                                    "%Y-%m-%dT%H:%M:%SZ",  # ISO format
                                    "%Y-%m-%d %H:%M:%S",   # Common format
                                    "%d-%b-%Y",            # Day-Month-Year
                                    "%d %b %Y",            # Day Month Year
                                ]
                                
                                for fmt in date_formats:
                                    try:
                                        dt = datetime.strptime(date_str, fmt)
                                        break
                                    except ValueError:
                                        continue
                                
                                if dt:
                                    creation_date_unix = int(dt.timestamp())
                                    break
                            except:
                                continue
                
                domain_info = {
                    "creation_date_unix": creation_date_unix
                }
                
        except Exception as e:
            # Failed to get domain info, but we still have URL analysis
            domain_info = {
                "creation_date_unix": 0
            }
        
        return {
            "vt_score": malicious_count,
            "creation_date_unix": domain_info.get("creation_date_unix", 0)
        }
        
    except httpx.HTTPError as e:
        return {
            "verdict": "Error", 
            "message": f"VirusTotal API error: {str(e)}"
        }
    except Exception as e:
        return {
            "verdict": "Error", 
            "message": f"Error checking URL with VirusTotal: {str(e)}"
        }

# Async function to check domain exists via DNS lookup
async def check_domain_exists(url: str) -> dict:
    """
    Check if a domain exists by performing a DNS lookup.
    Returns a verdict dictionary.
    """
    try:
        # Parse the URL to extract the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # If the domain is empty (invalid URL format), return error
        if not domain:
            return {"verdict": "Error", "message": "Invalid URL format"}
        
        # Try to resolve the domain to an IP address
        socket.gethostbyname(domain)
        
        # If we get here, the domain exists
        return {"exists": True}
        
    except socket.gaierror:
        # DNS resolution failed, domain likely doesn't exist
        return {
            "exists": False,
            "verdict": "Non-existent",
            "message": f"The domain '{domain}' does not exist or cannot be resolved."
        }
    except Exception as e:
        return {"verdict": "Error", "message": str(e)}

# Async function to check URL safety using Google Web Risk API
async def check_url_safety(url: str, api_key: str) -> dict:
    """
    Checks the safety of a URL using Google Web Risk API.
    Returns a verdict dictionary.
    """
    endpoint = "https://webrisk.googleapis.com/v1/uris:search"
    params = [
        ("key", api_key),
        ("uri", url),
        ("threatTypes", "MALWARE"),
        ("threatTypes", "SOCIAL_ENGINEERING"),
        ("threatTypes", "UNWANTED_SOFTWARE"),
    ]
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(endpoint, params=params)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as e:
        return {"verdict": "Error", "message": str(e)}

    # Interpret the response
    if "threat" in data and data["threat"]:
        threat_type = data["threat"].get("threatTypes", ["Unknown"])[0]
        return {
            "verdict": "Dangerous",
            "threat_type": threat_type
        }
    else:
        return {
            "verdict": "Safe"
        }

async def scrape_and_summarize_webpage(url: str) -> dict:
    """
    Scrape a webpage using Selenium and generate a summary of its content.
    For safe URLs, generates a more comprehensive summary using Gemini API when available.
    
    Args:
        url: The URL to scrape and summarize
        
    Returns:
        A dictionary with the summary and metadata
    """
    # Define stopwords here to avoid the "referenced before assignment" error
    stopwords = {
        'a', 'an', 'the', 'and', 'or', 'but', 'if', 'because', 'as', 'what', 'which', 
        'this', 'that', 'these', 'those', 'then', 'just', 'so', 'than', 'such', 'both', 
        'through', 'about', 'for', 'is', 'of', 'while', 'during', 'to', 'from', 'in', 
        'into', 'after', 'since', 'until', 'by', 'with', 'without', 'under', 'over', 
        'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why', 
        'how', 'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 
        'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very',
        'can', 'will', 'should', 'now', 'using', 'used', 'use', 'uses', 'like', 'even',
        'may', 'also', 'many', 'much', 'been', 'being', 'have', 'has', 'had', 'its', 'it',
        'us', 'we', 'you', 'they', 'them', 'our', 'your', 'their', 'his', 'her', 'him',
        'she', 'he', 'me', 'my', 'myself', 'yourself', 'himself', 'herself', 'itself',
        'who', 'whom', 'whose', 'was', 'were', 'are', 'am', 'been', 'say', 'says', 'said',
        'one', 'two', 'three', 'four', 'five', 'make', 'made', 'know', 'knows', 'knew',
        'known', 'see', 'sees', 'saw', 'seen', 'look', 'looks', 'looking', 'looked',
        'come', 'comes', 'coming', 'came', 'get', 'gets', 'getting', 'got', 'go', 'goes',
        'going', 'went', 'take', 'takes', 'taking', 'took', 'given', 'took', 'want',
        'wants', 'wanted', 'need', 'needs', 'needed', 'let', 'lets', 'feel', 'feels',
        'felt', 'try', 'tries', 'tried', 'call', 'calls', 'called', 'ask', 'asks', 'asked',
        'find', 'finds', 'found', 'show', 'shows', 'shown', 'showed', 'work', 'works',
        'worked', 'working', 'job'
    }
    
    print(f"Started Chrome WebDriver for URL: {url}")
    try:
        # Setup Chrome options with enhanced settings for better scraping
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")  # Hide automation
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
        
        # Start a Chrome WebDriver with extended timeout
        with ThreadPoolExecutor() as executor:
            # Run WebDriver setup in a separate thread to avoid blocking
            future = executor.submit(
                lambda: webdriver.Chrome(
                    service=Service(ChromeDriverManager().install()),
                    options=chrome_options
                )
            )
            driver = future.result()
        
        # Set page load timeout - increased for better handling of slow sites
        driver.set_page_load_timeout(20)
        
        # Navigate to the URL with retry mechanism
        max_retries = 3
        content = ""
        page_title = ""
        page_source = ""
        scraping_blocked = False
        
        for attempt in range(max_retries):
            try:
                driver.get(url)
                
                # Allow JavaScript to load content (wait a bit more)
                time.sleep(3)
                
                # Get the page source
                page_source = driver.page_source
                
                # Get page title
                page_title = driver.title
                
                # Check for anti-scraping mechanisms
                block_indicators = [
                    "Just a moment", "CloudFlare", "checking your browser", 
                    "Access Denied", "captcha", "Robot Challenge",
                    "Please enable JavaScript", "Please enable Cookies",
                    "Attention Required", "DDoS protection", "Security Challenge",
                    "human verification", "Bot Protection", "rate limit exceeded",
                    "enable JavaScript", "browser check", "loading"
                ]
                
                for indicator in block_indicators:
                    if indicator.lower() in page_source.lower() or indicator.lower() in page_title.lower():
                        if attempt < max_retries - 1:
                            print(f"Detected possible scraping protection: {indicator}. Retrying...")
                            time.sleep(2)  # Wait a bit longer before retry
                            continue
                        else:
                            # If all retries detect protection, mark as blocked
                            scraping_blocked = True
                            print(f"Scraping appears to be blocked after {max_retries} attempts.")
                
                break  # Success or final attempt, exit retry loop
                
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"Error on attempt {attempt+1}: {str(e)}. Retrying...")
                    time.sleep(2)  # Wait before retry
                    continue
                else:
                    # If all retries fail with errors, mark as blocked
                    scraping_blocked = True
                    print(f"All scraping attempts failed with errors: {str(e)}")
        
        # Close the browser
        driver.quit()
        
        # If scraping was blocked, return a specific message
        if scraping_blocked or not page_source:
            return {
                "success": True,
                "title": page_title or "Access Restricted",
                "summary": "This webpage restricts automated access. Content cannot be previewed.",
                "detailed_summary": "This site uses anti-bot protection that prevents our system from viewing its content. This often happens with pages that use Cloudflare or similar services to block automated access. To view the content, you would need to visit the site directly.",
                "keywords": ["restricted", "protected", "access", "blocked"],
                "content_length": 0,
                "scraping_blocked": True,
                "error": None
            }
        
        # Parse the HTML with BeautifulSoup
        soup = BeautifulSoup(page_source, 'html.parser')
        
        # Extract metadata
        meta_description = ""
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if tag.get('name') == 'description' or tag.get('property') == 'og:description':
                meta_description = tag.get('content', '')
                if meta_description:
                    break
        
        # Extract main content text with improved cleaning
        # Remove script, style, and other non-content tags
        for tag in soup(["script", "style", "header", "footer", "nav", "aside", "noscript", "iframe"]):
            tag.extract()
        
        # Get text with better whitespace handling
        lines = []
        for element in soup.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li']):
            text = element.get_text(strip=True)
            if text and len(text) > 15:  # Only include meaningful text
                lines.append(text)
        
        # If we couldn't extract structured content, fall back to all text
        if not lines:
            text = soup.get_text(separator=' ', strip=True)
            lines = [line.strip() for line in text.splitlines() if line.strip()]
        
        content = ' '.join(lines)
        
        # Check if we have meaningful content
        if len(content) < 100:
            # If content is too short, it might be a sign of blocking or a non-content page
            return {
                "success": True,
                "title": page_title or "Limited Content",
                "summary": "This webpage provides very limited content for automated access.",
                "detailed_summary": "This site either has very little text content or restricts what can be accessed programmatically. The available content is insufficient for a meaningful summary.",
                "keywords": ["limited", "content", "restricted"],
                "content_length": len(content),
                "scraping_blocked": True,
                "error": None
            }
        
        # Get content length for stats
        content_length = len(content)
        
        # Simple summarization first (as fallback)
        short_summary = ""
        detailed_summary = ""
        
        # Simple summarization: first try to use meta description
        if meta_description:
            short_summary = meta_description
        else:
            # If no meta description, extract first 3 sentences or 250 characters
            sentences = re.split(r'(?<=[.!?])\s+', content)
            short_summary = ' '.join(sentences[:3])
            if len(short_summary) > 250:
                short_summary = short_summary[:250] + "..."
        
        # Try to generate detailed summary using Gemini API if available
        gemini_key = os.getenv("GEMINI_API_KEY", "")
        if gemini_key and gemini_key.strip() and gemini_key != "your_gemini_api_key_here":
            try:
                # Limit content length for API request
                content_for_summary = content
                if len(content_for_summary) > 10000:  # Limit for API request
                    content_for_summary = content_for_summary[:10000] + "..."
                
                # Prepare API request
                api_url = "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent"
                headers = {
                    "Content-Type": "application/json"
                }
                
                prompt = f"""
                Summarize the following webpage content in 5-6 clear, concise sentences.
                
                IMPORTANT INSTRUCTIONS:
                1. Create a coherent summary that explains what this page is about
                2. For event pages, describe what the event is, when/where it's happening, and its main purpose
                3. For fragmented content, try to understand the context and structure it logically
                4. Focus on identifying the main purpose of the page and key information
                5. If it appears to be an organization or institution page, explain what they do
                6. Connect fragmented pieces of information into a meaningful narrative
                7. Use phrases like "This page appears to be about..." or "This seems to be a..."
                
                Title: {page_title}
                
                Content:
                {content_for_summary}
                
                Create a coherent 5-6 sentence summary that makes sense of this content, even if the scraped text is fragmented.
                """
                
                params = {
                    "key": gemini_key
                }
                
                payload = {
                    "contents": [{
                        "parts": [{
                            "text": prompt
                        }]
                    }],
                    "generationConfig": {
                        "temperature": 0.1,
                        "maxOutputTokens": 400
                    }
                }
                
                # Make API request with async httpx
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        api_url,
                        params=params,
                        headers=headers,
                        json=payload
                    )
                    
                    if response.status_code == 200:
                        api_response = response.json()
                        
                        # Extract the summary from the API response
                        if "candidates" in api_response and api_response["candidates"]:
                            candidate = api_response["candidates"][0]
                            if "content" in candidate and "parts" in candidate["content"]:
                                for part in candidate["content"]["parts"]:
                                    if "text" in part:
                                        detailed_summary = part["text"].strip()
                                        print(f"Generated summary: {detailed_summary[:100]}...")
                                        break
            
            except Exception as e:
                print(f"Error generating detailed summary with Gemini API: {str(e)}")
                # Continue with basic summary if Gemini fails
        
        # If we couldn't get a Gemini summary, create a simple fallback summary
        if not detailed_summary:
            # Create a better fallback summary for fragmented content
            
            # Try to identify key patterns in the content
            event_pattern = re.search(r'(?i)(?:event|hackathon|conference|workshop|seminar|webinar|summit|meetup|competition)', content)
            location_pattern = re.search(r'(?i)(?:at|in|venue|location|place|campus)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})', content)
            date_pattern = re.search(r'(?i)(?:on|date|scheduled for|starts on|begins on)\s+([A-Z][a-z]+\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+\d{4})?)', content)
            org_pattern = re.search(r'(?i)(?:organized by|hosted by|presented by|conducted by)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})', content)
            
            summary_parts = []
            
            # Extract the title or main topic
            if page_title and len(page_title) > 3:
                summary_parts.append(f"This webpage appears to be about {page_title}.")
            else:
                # Try to identify what type of page this is
                if event_pattern:
                    summary_parts.append(f"This webpage appears to be about a {event_pattern.group(0)}.")
                else:
                    # Use first sentence if it's reasonably long
                    sentences = re.split(r'(?<=[.!?])\s+', content)
                    if sentences and len(sentences[0]) > 30:
                        summary_parts.append(sentences[0])
                    else:
                        summary_parts.append("This webpage contains information that appears to be fragmented.")
            
            # Add information about the organization if found
            if org_pattern:
                summary_parts.append(f"It is {org_pattern.group(0)}.")
            
            # Add location information if found
            if location_pattern:
                summary_parts.append(f"It takes place {location_pattern.group(0)}.")
            
            # Add date information if found
            if date_pattern:
                summary_parts.append(f"It is scheduled {date_pattern.group(0)}.")
            
            # Extract keywords for content hints
            words = re.findall(r'\b[a-zA-Z]{3,15}\b', content.lower())
            word_freq = {}
            for word in words:
                if word not in stopwords and len(word) > 3:
                    word_freq[word] = word_freq.get(word, 0) + 1
            
            # Get top keywords
            top_keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]
            top_keywords = [k[0] for k in top_keywords]
            
            # Add keyword summary
            if top_keywords:
                summary_parts.append(f"The main topics include {', '.join(top_keywords)}.")
            
            # Add a general closing statement
            summary_parts.append("The page contains various sections with information related to these topics.")
            
            # Create the final summary
            detailed_summary = ' '.join(summary_parts)
            
            # Ensure we don't have too many sentences
            sentences = re.split(r'(?<=[.!?])\s+', detailed_summary)
            if len(sentences) > 6:
                detailed_summary = ' '.join(sentences[:6])
                
            # Clean up the final summary
            detailed_summary = detailed_summary.replace("  ", " ").strip()
            
            # If everything failed, just use a simple default summary
            if not detailed_summary or len(detailed_summary) < 50:
                detailed_summary = f"This page titled '{page_title}' appears to contain information related to {', '.join(top_keywords[:3])}. The content structure makes it difficult to generate a more detailed summary."
            
            # Limit to a reasonable length
            if len(detailed_summary) > 500:
                detailed_summary = detailed_summary[:500] + "..."
        
        # Extract top keywords (improved algorithm)
        words = re.findall(r'\b[a-zA-Z]{3,15}\b', content.lower())
        word_freq = {}
        
        # Count word frequencies excluding stopwords
        for word in words:
            if word not in stopwords and len(word) > 3:  # Only include words longer than 3 chars
                word_freq[word] = word_freq.get(word, 0) + 1
        
        # Get top 15 keywords
        keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:15]
        keywords = [k[0] for k in keywords]
        
        return {
            "success": True,
            "title": page_title,
            "summary": short_summary,
            "detailed_summary": detailed_summary,
            "keywords": keywords,
            "content_length": content_length,
            "scraping_blocked": False,
            "error": None
        }
        
    except Exception as e:
        print(f"Error in Selenium: {str(e)}")
        
        # Check if the error is related to CloudFlare or similar protection
        error_msg = str(e).lower()
        if "cloudflare" in error_msg or "captcha" in error_msg or "challenge" in error_msg:
            print("CloudFlare or similar protection detected.")
            return {
                "success": False,
                "title": "Access Restricted",
                "summary": "This webpage restricts automated access. Content cannot be previewed.",
                "detailed_summary": "The website uses anti-bot protection like CloudFlare that prevents automated access.",
                "keywords": [],
                "content_length": 0,
                "scraping_blocked": True,
                "blocking_reason": "The website uses anti-bot protection that prevents automated access."
            }
        
        # Handle other specific errors
        if "ERR_NAME_NOT_RESOLVED" in str(e):
            print("Unable to scrape this website. Blocked by domain protection or network error.")
            return {
                "success": False,
                "title": "Connection Error",
                "summary": "Unable to connect to this website.",
                "detailed_summary": "The domain could not be resolved or the website is blocking automated access.",
                "keywords": [],
                "content_length": 0,
                "scraping_blocked": True,
                "blocking_reason": "Domain could not be resolved or is blocking automated access."
            }
        
        # Generic error case
        return {
            "success": False,
            "title": "Error",
            "summary": "Unable to analyze this webpage.",
            "detailed_summary": f"Error details: {str(e)}",
            "keywords": [],
            "content_length": 0,
            "scraping_blocked": True,
            "blocking_reason": str(e),
            "error": str(e)
        }

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """
    Serve the home page with the URL checking form
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze-url")
async def analyze_url(request: URLRequest):
    """
    Analyze the given URL for safety using our enhanced five-step workflow:
    
    Step 0: Link Unwrapper - Detect and follow URL shorteners to get the final destination
    Step 1: Free Pre-Filter (DNS Check) - Verify domain exists
    Step 2: Primary Threat Intel (Google API) - Check against known threats
    Step 3: Full Deep Dive - Run VirusTotal API and heuristic analysis in parallel
    Step 4: Final Rule-Based Decision - Apply different logic for shared vs custom domains
    
    Returns a structured response with the complete analysis results.
    """
    from datetime import datetime
    import asyncio
    
    original_url_str = str(request.url)
    current_time = str(datetime.now())
    
    # STEP 0: LINK UNWRAPPER - Follow redirects from URL shorteners
    # -----------------------------------------------------------
    print(f"Step 0: Unwrapping shortened URL if needed: {original_url_str}")
    unwrap_result = await unwrap_shortened_url(original_url_str)
    
    # Use the final URL for all subsequent analysis
    url_str = unwrap_result["final_url"]
    
    # Add information about unwrapping to be included in the response later
    url_info = {
        "original_url": original_url_str,
        "final_url": url_str,
        "is_shortened": unwrap_result["is_shortened"],
        "redirect_chain": unwrap_result["redirect_chain"]
    }
    
    if unwrap_result["error"]:
        print(f"Warning: Error during URL unwrapping: {unwrap_result['error']}")
        # Continue with original URL if there was an error
    
    # STEP 1: FREE PRE-FILTER (DNS CHECK)
    # ----------------------------------
    print(f"Step 1: Performing DNS check for {url_str}")
    domain_check = await check_domain_exists(url_str)
    
    # If there was an error checking the domain
    if domain_check.get("verdict") == "Error":
        raise HTTPException(status_code=400, detail=domain_check.get("message", "Error checking domain."))
    
    # If the domain doesn't exist, return immediately with "Invalid" verdict
    if not domain_check.get("exists", False):
        return {
            "url": url_str,
            "analysis": {
                "verdict": "Invalid 🚫",
                "safe": False,
                "exists": False
            },
            "timestamp": current_time,
            "service": "DNS Lookup",
            "message": domain_check.get("message", "The domain does not exist or cannot be resolved."),
            "recommended_action": "Avoid accessing this non-existent domain."
        }
    
    # STEP 2: PRIMARY THREAT INTEL CHECK (GOOGLE API)
    # ----------------------------------------------
    print(f"Step 2: Checking Google Web Risk API for {url_str}")
    google_api_key = os.getenv("GOOGLE_API_KEY")
    if not google_api_key:
        raise HTTPException(status_code=500, detail="Google API key not configured.")
    
    google_result = await check_url_safety(url_str, google_api_key)
    if google_result.get("verdict") == "Error":
        raise HTTPException(status_code=502, detail=google_result.get("message", "Google API call failed."))
    
    # If Google says it's dangerous, return immediately with "Dangerous" verdict
    if google_result.get("verdict") == "Dangerous":
        enhanced_response = {
            "url": url_str,
            "analysis": {
                "verdict": "Dangerous 🚨",
                "safe": False,
                "exists": True,
                "threat_details": {
                    "type": google_result.get("threat_type"),
                    "severity": "High" if google_result.get("threat_type") in ["MALWARE", "SOCIAL_ENGINEERING"] else "Medium"
                }
            },
            "timestamp": current_time,
            "service": "Google Web Risk API",
            "message": "Flagged by Google's Real-Time Blacklist",
            "recommended_action": "Block access to this URL"
        }
        
        # Generate AI explanation if enabled
        try:
            if os.getenv("ENABLE_AI", "false").lower() == "true":
                # Run heuristic analysis for AI (needed for context)
                heuristic_flags = analyze_url_heuristics(url_str)
                enhanced_response["analysis"]["heuristic_flags"] = heuristic_flags
                
                # Generate AI explanation
                await generate_ai_explanation(url_str, enhanced_response)
        except Exception as e:
            print(f"AI analysis error: {str(e)}")
        
        return enhanced_response
    
    # STEP 3: FULL DEEP DIVE (Only if Google says "Safe")
    # -------------------------------------------------
    print(f"Step 3: Performing deep dive analysis for {url_str}")
    
    # Run both investigations in parallel for maximum speed
    vt_result = {"verdict": "Skipped", "vt_score": 0, "creation_date_unix": 0}
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    async def run_investigations():
        nonlocal vt_result
        
        # Investigation A: VirusTotal API (if key is available)
        if vt_api_key and vt_api_key != "your_virustotal_api_key_here":
            vt_result = await check_virustotal(url_str, vt_api_key)
        
        # Investigation B: Heuristic Analysis
        return analyze_url_heuristics(url_str)
    
    # Run both investigations and wait for results
    heuristic_flags = await run_investigations()
    
    # Extract domain information
    parsed_url = urlparse(url_str)
    hostname = parsed_url.netloc.lower()
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    
    # Extract VirusTotal data
    vt_score = vt_result.get("vt_score", 0)
    creation_date_unix = vt_result.get("creation_date_unix", 0)
    domain_age_days = 0
    
    if creation_date_unix > 0:
        current_unix = time.time()
        domain_age_days = int((current_unix - creation_date_unix) / (60 * 60 * 24))
    
    # Determine if this is a shared domain and get details
    shared_domain_info = is_shared_domain(hostname)
    is_shared = shared_domain_info["is_shared"]
    shared_domain_category = shared_domain_info["category"]
    shared_domain_risk = shared_domain_info["risk_level"]
    shared_domain_platform = shared_domain_info["platform"]
    shared_domain_description = shared_domain_info["description"]
    
    # STEP 4: FINAL RULE-BASED DECISION ENGINE
    # ---------------------------------------
    print(f"Step 4: Making final decision for {url_str} (Shared domain: {is_shared}, Category: {shared_domain_category})")
    
    # Initialize with default "Safe" verdict
    enhanced_response = {
        "url": url_str,
        "url_unwrapping": {
            "original_url": url_info["original_url"],
            "final_url": url_info["final_url"],
            "is_shortened": url_info["is_shortened"],
            "redirect_chain": url_info["redirect_chain"] if url_info["is_shortened"] else []
        },
        "analysis": {
            "verdict": "Safe ✅",
            "safe": True,
            "exists": True,
            "vt_detections": vt_score,
            "domain_age_days": domain_age_days,
            "heuristic_flags": heuristic_flags,
            "is_shared_domain": is_shared,
            "shared_domain_details": {
                "category": shared_domain_category,
                "risk_level": shared_domain_risk,
                "platform": shared_domain_platform,
                "description": shared_domain_description
            } if is_shared else None
        },
        "timestamp": current_time,
        "service": "Multi-layer Analysis"
    }
    
    # Logic Branch A: SHARED DOMAIN
    if is_shared:
        # Consider the risk level of the shared domain type
        if shared_domain_risk == "very_high" or shared_domain_risk == "high":
            # High-risk shared domains are immediately suspicious
            if vt_score > 0:
                # Check A.1: VirusTotal flagged it and it's on a high-risk platform
                enhanced_response["analysis"]["verdict"] = "Dangerous 🚨"
                enhanced_response["analysis"]["safe"] = False
                enhanced_response["message"] = f"Flagged by {vt_score} security vendors on a high-risk platform ({shared_domain_platform})"
                enhanced_response["recommended_action"] = "Block access to this URL"
            else:
                # Check A.2: Not flagged but on a high-risk platform
                enhanced_response["analysis"]["verdict"] = "Caution ⚠️"
                enhanced_response["analysis"]["safe"] = False
                enhanced_response["message"] = f"Using a high-risk hosting platform ({shared_domain_platform})"
                enhanced_response["recommended_action"] = "Exercise caution when accessing this URL"
        elif vt_score > 0:
            # Check A.3: VirusTotal flagged it
            enhanced_response["analysis"]["verdict"] = "Dangerous 🚨"
            enhanced_response["analysis"]["safe"] = False
            enhanced_response["message"] = f"Flagged by {vt_score} security vendors"
            enhanced_response["recommended_action"] = "Block access to this URL"
        elif len(heuristic_flags) > 0:
            # Check A.4: Heuristic flags are present
            enhanced_response["analysis"]["verdict"] = "Caution ⚠️"
            enhanced_response["analysis"]["safe"] = False
            enhanced_response["message"] = f"Suspicious characteristics on a shared platform ({shared_domain_platform})"
            enhanced_response["recommended_action"] = "Exercise caution when accessing this URL"
        elif shared_domain_category == "url_shorteners":
            # Check A.5: It's a URL shortener but not redirecting anywhere suspicious
            enhanced_response["analysis"]["verdict"] = "Caution ⚠️"
            enhanced_response["analysis"]["safe"] = False
            enhanced_response["message"] = "URL shortener detected - destination appears clean but exercise caution"
            enhanced_response["recommended_action"] = "Exercise caution as URL shorteners can be changed later"
        elif shared_domain_risk == "medium":
            # Check A.6: Medium risk platforms deserve a note
            enhanced_response["message"] = f"Hosted on a shared platform ({shared_domain_platform}), appears legitimate"
            enhanced_response["recommended_action"] = "No issues detected, but be aware this is on a shared hosting platform"
    
    # Logic Branch B: CUSTOM DOMAIN
    else:
        if vt_score > 0:
            # Check B.1: VirusTotal flagged it
            enhanced_response["analysis"]["verdict"] = "Dangerous 🚨"
            enhanced_response["analysis"]["safe"] = False
            enhanced_response["message"] = f"Flagged by {vt_score} security vendors"
            enhanced_response["recommended_action"] = "Block access to this URL"
        elif domain_age_days < 30 and domain_age_days > 0 and len(heuristic_flags) > 0:
            # Check B.2: New domain with suspicious characteristics
            enhanced_response["analysis"]["verdict"] = "Dangerous 🚨"
            enhanced_response["analysis"]["safe"] = False
            enhanced_response["message"] = f"Brand-new, suspicious website (only {domain_age_days} days old)"
            enhanced_response["recommended_action"] = "Block access to this URL"
        elif len(heuristic_flags) > 0:
            # Check B.3: Heuristic flags but not a new domain
            enhanced_response["analysis"]["verdict"] = "Caution ⚠️"
            enhanced_response["analysis"]["safe"] = False
            enhanced_response["message"] = "Contains suspicious indicators"
            enhanced_response["recommended_action"] = "Exercise caution when accessing this URL"
        elif domain_age_days < 7 and domain_age_days > 0:
            # Check B.4: Very new domain, even without suspicious characteristics
            enhanced_response["analysis"]["verdict"] = "Caution ⚠️"
            enhanced_response["analysis"]["safe"] = False
            enhanced_response["message"] = f"Very new domain (only {domain_age_days} days old)"
            enhanced_response["recommended_action"] = "New domains deserve extra scrutiny"
    
    # Generate AI-powered explanation for the verdict
    await generate_ai_explanation(url_str, enhanced_response)
    
    # Scrape and summarize the webpage content for all URLs (safe, cautious, and dangerous)
    # This helps users understand what's on the page without visiting it
    summary_result = await scrape_and_summarize_webpage(url_str)
    if summary_result["success"]:
        enhanced_response["webpage_summary"] = {
            "title": summary_result["title"],
            "summary": summary_result["summary"],
            "detailed_summary": summary_result.get("detailed_summary", ""),
            "keywords": summary_result["keywords"],
            "content_length": summary_result["content_length"],
            "safety_status": enhanced_response["analysis"]["verdict"].split()[0],  # Safe, Caution, or Dangerous
            "scraping_blocked": False
        }
    elif "scraping_blocked" in summary_result and summary_result["scraping_blocked"]:
        enhanced_response["webpage_summary"] = {
            "title": summary_result.get("title", "Access Restricted"),
            "summary": "This webpage restricts automated access. Content cannot be previewed.",
            "detailed_summary": summary_result.get("blocking_reason", "The website uses anti-bot protection that prevents automated access."),
            "keywords": [],
            "content_length": 0,
            "safety_status": enhanced_response["analysis"]["verdict"].split()[0],
            "scraping_blocked": True
        }
    
    return enhanced_response

async def generate_ai_explanation(url_str: str, enhanced_response: dict):
    """
    Generate an AI-powered explanation for the verdict.
    This function is extracted to keep the main function cleaner.
    
    Args:
        url_str: The URL being analyzed
        enhanced_response: The response object to update with AI analysis
    """
    try:
        # Get AI settings from environment
        ai_enabled = os.getenv("ENABLE_AI", "false").lower() == "true"
        openai_key = os.getenv("OPENAI_API_KEY", "")
        gemini_key = os.getenv("GEMINI_API_KEY", "")
        api_fallback_mode = os.getenv("API_FALLBACK_MODE", "false").lower() == "true"
        use_cache = os.getenv("USE_CACHE", "true").lower() == "true"
        
        if not ai_enabled:
            return
        
        # Get basic analysis data
        verdict = enhanced_response["analysis"]["verdict"]
        vt_score = enhanced_response["analysis"].get("vt_detections", 0)
        domain_age_days = enhanced_response["analysis"].get("domain_age_days", 0)
        heuristic_flags = enhanced_response["analysis"].get("heuristic_flags", [])
        
        # First, check if we have a cached response
        if use_cache:
            cached_response = get_cached_ai_response(url_str, verdict, vt_score, domain_age_days)
            if cached_response:
                print("Using cached AI analysis")
                enhanced_response["ai_analysis"] = cached_response
                return
        
        # Prepare shared domain information for AI context
        shared_domain_info = ""
        if enhanced_response["analysis"].get("is_shared_domain", False):
            details = enhanced_response["analysis"].get("shared_domain_details", {})
            if details:
                shared_domain_info = f"""
                Shared Domain Information:
                - Platform: {details.get('platform', 'Unknown')}
                - Category: {details.get('category', 'Unknown')}
                - Risk Level: {details.get('risk_level', 'Unknown')}
                - Description: {details.get('description', 'Unknown')}
                """
        
        # Track if we've tried available APIs
        tried_gemini = False
        tried_openai = False
        ai_result = None
        
        # If OpenAI key is available and not empty, try it first (more reliable)
        if openai_key and openai_key.strip() and openai_key != "sk-demo123456789abcdefghijklmnopqrstuvwxyz0123456789":
            print("Using OpenAI for AI analysis...")
            ai_result = await analyze_url_ai_openai(
                url_str, verdict, vt_score, domain_age_days, heuristic_flags, shared_domain_info
            )
            tried_openai = True
            
            # If successful, we're done
            if ai_result.get("verdict") != "ERROR":
                enhanced_response["ai_analysis"] = ai_result
                if use_cache:
                    cache_ai_response(url_str, verdict, vt_score, domain_age_days, ai_result)
                return
        
        # Try Gemini if OpenAI wasn't available or failed
        if gemini_key and gemini_key.strip():
            print("Using Gemini for AI analysis...")
            ai_result = await analyze_url_ai_direct(
                url_str, verdict, vt_score, domain_age_days, heuristic_flags, shared_domain_info
            )
            tried_gemini = True
            
            # If successful, we're done
            if ai_result.get("verdict") != "ERROR":
                enhanced_response["ai_analysis"] = ai_result
                if use_cache:
                    cache_ai_response(url_str, verdict, vt_score, domain_age_days, ai_result)
                return
        
        # If we're in fallback mode and haven't tried OpenAI yet, try it as fallback
        if api_fallback_mode and not tried_openai and openai_key and openai_key.strip():
            print("Falling back to OpenAI after Gemini failure...")
            ai_result = await analyze_url_ai_openai(
                url_str, verdict, vt_score, domain_age_days, heuristic_flags, shared_domain_info
            )
            
            # If successful, we're done
            if ai_result.get("verdict") != "ERROR":
                enhanced_response["ai_analysis"] = ai_result
                if use_cache:
                    cache_ai_response(url_str, verdict, vt_score, domain_age_days, ai_result)
                return
        
        # If all API calls failed or weren't available, use rule-based fallback
        print("All AI APIs failed or unavailable, using rule-based fallback")
        fallback_verdict = generate_rule_based_fallback(
            url_str, verdict, vt_score, domain_age_days, heuristic_flags,
            enhanced_response["analysis"].get("is_shared_domain", False),
            enhanced_response["analysis"].get("shared_domain_details", {})
        )
        
        enhanced_response["ai_analysis"] = fallback_verdict
        
    except Exception as e:
        # If AI analysis fails, continue without it
        print(f"AI analysis error: {str(e)}")
        enhanced_response["ai_analysis"] = {
            "verdict": "ERROR",
            "explanation": f"Error generating AI analysis: {str(e)}"
        }

def generate_rule_based_fallback(
    url: str,
    verdict: str,
    vt_score: int,
    domain_age_days: int,
    heuristic_flags: list,
    is_shared_domain: bool,
    shared_domain_details: dict
) -> dict:
    """
    Generate a detailed rule-based fallback verdict when AI analysis fails.
    This function creates a more comprehensive explanation than the basic
    rule-based verdicts in the AI synthesizers.
    
    Args:
        url: The URL being analyzed
        verdict: The existing verdict (Safe/Caution/Dangerous)
        vt_score: Number of detections from VirusTotal
        domain_age_days: Age of the domain in days
        heuristic_flags: List of suspicious patterns detected in the URL
        is_shared_domain: Whether the domain is a shared hosting platform
        shared_domain_details: Details about the shared domain
        
    Returns:
        Dictionary with verdict and detailed explanation
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.lower()
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    
    # Build the explanation based on all available data
    explanation_parts = []
    
    # Add verdict-based explanation
    if verdict == "Dangerous":
        explanation_parts.append("This URL has been identified as potentially dangerous based on multiple security indicators.")
    elif verdict == "Caution":
        explanation_parts.append("This URL requires caution based on some suspicious indicators, though it's not definitively malicious.")
    else:
        explanation_parts.append("This URL appears to be safe based on our security analysis.")
    
    # Add VirusTotal information
    if vt_score > 0:
        explanation_parts.append(f"It has been flagged by {vt_score} security vendors on VirusTotal as potentially malicious.")
    else:
        explanation_parts.append("No security vendors on VirusTotal have flagged this URL.")
    
    # Add domain age information
    if domain_age_days > 0:
        if domain_age_days < 7:
            explanation_parts.append(f"The domain is very new (only {domain_age_days} days old), which is often a characteristic of phishing websites.")
        elif domain_age_days < 30:
            explanation_parts.append(f"The domain is relatively new ({domain_age_days} days old), which sometimes warrants extra caution.")
        elif domain_age_days < 90:
            explanation_parts.append(f"The domain was created {domain_age_days} days ago.")
        else:
            explanation_parts.append(f"The domain has been established for some time ({domain_age_days} days), which is a positive signal.")
    
    # Add heuristic flags information
    if heuristic_flags and len(heuristic_flags) > 0:
        if len(heuristic_flags) >= 3:
            explanation_parts.append(f"Multiple suspicious patterns ({len(heuristic_flags)}) were detected in this URL, including:")
        else:
            explanation_parts.append(f"Some suspicious patterns were detected in this URL:")
        
        # Add a sample of the heuristic flags (max 3)
        sample_flags = heuristic_flags[:3]
        for flag in sample_flags:
            explanation_parts.append(f"- {flag}")
        
        if len(heuristic_flags) > 3:
            explanation_parts.append(f"- Plus {len(heuristic_flags) - 3} additional suspicious indicators")
    else:
        explanation_parts.append("No suspicious patterns were detected in this URL.")
    
    # Add shared domain information
    if is_shared_domain:
        platform = shared_domain_details.get("platform", "Unknown")
        category = shared_domain_details.get("category", "Unknown")
        risk_level = shared_domain_details.get("risk_level", "Unknown")
        description = shared_domain_details.get("description", "")
        
        explanation_parts.append(f"This URL is hosted on a shared platform ({platform}) categorized as {category}.")
        
        if risk_level in ["high", "very_high"]:
            explanation_parts.append(f"This type of shared platform has a {risk_level} risk profile and is frequently abused for malicious purposes.")
        elif risk_level == "medium":
            explanation_parts.append(f"This type of shared platform has a moderate risk profile as it can sometimes be used for malicious purposes.")
        else:
            explanation_parts.append(f"This type of shared platform has a {risk_level} risk profile.")
        
        if description:
            explanation_parts.append(f"{description}")
    
    # Add recommendation based on verdict
    if verdict == "Dangerous":
        explanation_parts.append("Recommendation: Avoid visiting this URL as it may pose a security risk to your device or data.")
    elif verdict == "Caution":
        explanation_parts.append("Recommendation: Exercise caution when visiting this URL and avoid sharing sensitive information.")
    else:
        explanation_parts.append("Recommendation: This URL appears safe to visit based on our analysis.")
    
    # Add AI service notice
    explanation_parts.append("Note: This analysis was generated by our rule-based system as our AI service is currently at capacity.")
    
    # Join all parts with spaces
    final_explanation = " ".join(explanation_parts)
    
    return {
        "verdict": verdict,
        "explanation": final_explanation
    }

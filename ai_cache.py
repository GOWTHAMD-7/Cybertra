"""
AI Response Cache

This module provides a simple caching mechanism for AI responses
to help with rate limiting. When an API rate limit is reached,
we can use cached responses for similar URLs.
"""

import os
import json
import time
import hashlib
from typing import Dict, Any, Optional

# Cache settings
CACHE_DIR = os.path.join(os.path.dirname(__file__), "ai_cache")
CACHE_TTL = 60 * 60 * 24  # 24 hours in seconds
MAX_CACHE_ENTRIES = 1000

# Ensure cache directory exists
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

def _get_cache_key(url: str, verdict: str, vt_score: int, domain_age_days: int) -> str:
    """
    Generate a cache key from the URL and key attributes.
    
    Args:
        url: The URL being analyzed
        verdict: The current verdict
        vt_score: VirusTotal detection count
        domain_age_days: Age of the domain in days
        
    Returns:
        A string hash that can be used as a cache key
    """
    # Create a string representation of the key attributes
    key_str = f"{url}|{verdict}|{vt_score}|{domain_age_days}"
    
    # Generate a hash of the key string
    return hashlib.md5(key_str.encode()).hexdigest()

def get_cached_ai_response(
    url: str, 
    verdict: str, 
    vt_score: int, 
    domain_age_days: int
) -> Optional[Dict[str, Any]]:
    """
    Check if we have a cached AI response for similar analysis parameters.
    
    Args:
        url: The URL being analyzed
        verdict: The current verdict
        vt_score: VirusTotal detection count
        domain_age_days: Age of the domain in days
        
    Returns:
        The cached response if found and valid, None otherwise
    """
    cache_key = _get_cache_key(url, verdict, vt_score, domain_age_days)
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    # Check if cache file exists
    if not os.path.exists(cache_file):
        return None
    
    try:
        # Read the cache file
        with open(cache_file, "r") as f:
            cached_data = json.load(f)
        
        # Check if cache is still valid (not expired)
        if time.time() - cached_data.get("timestamp", 0) > CACHE_TTL:
            # Cache is expired, remove it
            os.remove(cache_file)
            return None
        
        return cached_data.get("response")
    
    except Exception as e:
        print(f"Error reading cache: {str(e)}")
        return None

def cache_ai_response(
    url: str, 
    verdict: str, 
    vt_score: int, 
    domain_age_days: int, 
    response: Dict[str, Any]
) -> None:
    """
    Cache an AI response for future use.
    
    Args:
        url: The URL being analyzed
        verdict: The current verdict
        vt_score: VirusTotal detection count
        domain_age_days: Age of the domain in days
        response: The AI response to cache
    """
    try:
        # Don't cache error responses
        if response.get("verdict") == "ERROR":
            return
        
        cache_key = _get_cache_key(url, verdict, vt_score, domain_age_days)
        cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
        
        # Prepare cache data
        cache_data = {
            "timestamp": time.time(),
            "url": url,
            "verdict": verdict,
            "vt_score": vt_score,
            "domain_age_days": domain_age_days,
            "response": response
        }
        
        # Write the cache file
        with open(cache_file, "w") as f:
            json.dump(cache_data, f)
            
        # Manage cache size
        _cleanup_cache()
        
    except Exception as e:
        print(f"Error writing cache: {str(e)}")

def _cleanup_cache() -> None:
    """
    Clean up the cache directory if it contains too many entries.
    Removes the oldest entries first.
    """
    try:
        # Get all cache files
        cache_files = [os.path.join(CACHE_DIR, f) for f in os.listdir(CACHE_DIR) 
                      if f.endswith(".json")]
        
        # If we have too many cache files, remove the oldest ones
        if len(cache_files) > MAX_CACHE_ENTRIES:
            # Sort files by modification time (oldest first)
            cache_files.sort(key=os.path.getmtime)
            
            # Remove the oldest files
            for i in range(len(cache_files) - MAX_CACHE_ENTRIES):
                os.remove(cache_files[i])
                
    except Exception as e:
        print(f"Error cleaning up cache: {str(e)}")
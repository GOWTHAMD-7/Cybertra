import os
import json
import asyncio
import httpx
from typing import List, Dict, Any

def generate_ai_synthesizer_prompt(
    url: str,
    google_verdict: str,
    vt_score: int,
    domain_age_days: int,
    heuristic_flags: List[str],
    shared_domain_info: str = ""
) -> str:
    """
    Generates a prompt for the AI synthesizer using the template and the collected data.
    
    Args:
        url: The URL that was analyzed
        google_verdict: The verdict from Google Safe Browsing API
        vt_score: The number of detections from VirusTotal
        domain_age_days: The age of the domain in days
        heuristic_flags: List of heuristic analysis flags
        shared_domain_info: Information about shared domain hosting (if any)
        
    Returns:
        A formatted prompt string ready to be sent to the AI model
    """
    # Read the template
    template_path = os.path.join(os.path.dirname(__file__), "ai_synthesizer_prompt.txt")
    with open(template_path, "r") as file:
        template = file.read()
    
    # Format the heuristic flags into a readable format
    if heuristic_flags and len(heuristic_flags) > 0:
        formatted_flags = "\n".join([f"- {flag}" for flag in heuristic_flags])
    else:
        formatted_flags = "None detected"
    
    # Fill in the placeholders
    prompt = template.replace("{{URL}}", url)
    prompt = prompt.replace("{{GOOGLE_VERDICT}}", google_verdict)
    prompt = prompt.replace("{{VT_SCORE}}", str(vt_score))
    prompt = prompt.replace("{{DOMAIN_AGE_DAYS}}", str(domain_age_days))
    prompt = prompt.replace("{{HEURISTIC_FLAGS}}", formatted_flags)
    
    # Add shared domain info if available
    if "{{SHARED_DOMAIN_INFO}}" in template:
        prompt = prompt.replace("{{SHARED_DOMAIN_INFO}}", shared_domain_info if shared_domain_info else "Shared Domain Info: Not a shared domain")
    else:
        # If the template doesn't have the placeholder, append it to the end
        if shared_domain_info:
            prompt += f"\n\n{shared_domain_info}"
    
    return prompt

async def generate_verdict_with_gemini(
    url: str,
    analysis_data: Dict[str, Any]
) -> Dict[str, str]:
    """
    Takes the URL analysis data and creates a human-readable verdict using the Gemini API.
    
    Args:
        url: The URL that was analyzed
        analysis_data: Dictionary containing the analysis results
        
    Returns:
        A dictionary with 'verdict' and 'explanation' keys
    """
    # Extract the necessary data from the analysis results
    google_verdict = analysis_data.get("analysis", {}).get("verdict", "Unknown")
    vt_score = analysis_data.get("analysis", {}).get("vt_detections", 0)
    domain_age_days = analysis_data.get("analysis", {}).get("domain_age_days", 0)
    heuristic_flags = analysis_data.get("analysis", {}).get("heuristic_flags", [])
    
    # Generate the prompt
    prompt = generate_ai_synthesizer_prompt(
        url, 
        google_verdict, 
        vt_score, 
        domain_age_days, 
        heuristic_flags
    )
    
    # Get API key from environment
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {
            "verdict": "ERROR",
            "explanation": "Gemini API key not configured"
        }
    
    # Use direct REST API approach which is most reliable
    try:
        # Try different API endpoints and models until one works
        endpoints_to_try = [
            {
                "url": f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={api_key}",
                "model": "gemini-pro"
            },
            {
                "url": f"https://generativelanguage.googleapis.com/v1/models/gemini-1.0-pro:generateContent?key={api_key}",
                "model": "gemini-1.0-pro"
            },
            {
                "url": f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:generateContent?key={api_key}",
                "model": "gemini-1.5-pro"
            }
        ]
        
        last_error = None
        generated_text = None
        
        for endpoint_info in endpoints_to_try:
            try:
                endpoint = endpoint_info["url"]
                model = endpoint_info["model"]
                print(f"Trying endpoint for model {model}...")
                
                payload = {
                    "contents": [
                        {
                            "parts": [
                                {
                                    "text": prompt
                                }
                            ]
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.2,
                        "topP": 0.8,
                        "topK": 40,
                        "maxOutputTokens": 1024
                    }
                }
                
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        timeout=30.0
                    )
                    
                    if response.status_code != 200:
                        print(f"API for {model} returned status code {response.status_code}: {response.text}")
                        last_error = f"API returned status code {response.status_code}: {response.text}"
                        continue
                    
                    result = response.json()
                    print(f"Received response from Gemini API for {model}!")
                    
                    # Extract the generated text from the response
                    generated_text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    
                    if generated_text:
                        print(f"Successfully got response from model {model}")
                        break
            except Exception as e:
                print(f"Error with endpoint {endpoint_info['model']}: {str(e)}")
                last_error = str(e)
        
        if not generated_text:
            return {
                "verdict": "ERROR",
                "explanation": f"Failed to get a response from any Gemini API endpoint. Last error: {last_error}"
            }
        
        # Extract verdict (should be in the format "FINAL VERDICT: SAFE/CAUTION/DANGEROUS")
        verdict_line = ""
        for line in generated_text.splitlines():
            if "VERDICT" in line and ("SAFE" in line or "CAUTION" in line or "DANGEROUS" in line):
                verdict_line = line
                break
        
        if "SAFE" in verdict_line:
            verdict = "SAFE"
        elif "CAUTION" in verdict_line:
            verdict = "CAUTION"
        elif "DANGEROUS" in verdict_line:
            verdict = "DANGEROUS"
        else:
            verdict = "UNKNOWN"
        
        # The explanation should be a paragraph after the verdict
        explanation = ""
        capture_explanation = False
        for line in generated_text.splitlines():
            if verdict in line and "VERDICT" in line:
                capture_explanation = True
                continue
            
            if capture_explanation and line.strip():
                explanation = line.strip()
                break
        
        if not explanation:
            # If we couldn't find a clear explanation paragraph, use everything after the verdict
            parts = generated_text.split(verdict_line, 1)
            if len(parts) > 1:
                explanation = parts[1].strip()
        
        return {
            "verdict": verdict,
            "explanation": explanation
        }
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error calling Gemini API: {str(e)}")
        print(f"Error details: {error_details}")
        
        # Provide a more helpful error message
        error_msg = str(e)
        if "404" in error_msg and "not found" in error_msg:
            return {
                "verdict": "ERROR",
                "explanation": "The specified Gemini model is not available. Please check your API key permissions or try a different model."
            }
        elif "403" in error_msg:
            return {
                "verdict": "ERROR",
                "explanation": "Access to the Gemini API was denied. Please verify your API key is correct and has proper permissions."
            }
        elif "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
            # Handle rate limiting specifically
            # Error 429 means "Too Many Requests" - we've hit a rate limit
            # RESOURCE_EXHAUSTED is the specific error code Gemini returns for quota limits
            return {
                "verdict": "ERROR",
                "explanation": "Gemini API rate limit exceeded. The API quota has been exhausted. Please try again later or use the OpenAI fallback."
            }
        else:
            return {
                "verdict": "ERROR",
                "explanation": f"Error calling Gemini API: {str(e)}"
            }

async def analyze_url_ai(
    url: str,
    google_verdict: str,
    vt_score: int,
    domain_age_days: int,
    heuristic_flags: List[str],
    shared_domain_info: str = ""
) -> Dict[str, Any]:
    """
    Main function to analyze a URL using Gemini AI synthesis.
    
    Args:
        url: The URL being analyzed
        google_verdict: Verdict from Google Web Risk API (Safe/Dangerous)
        vt_score: Number of detections from VirusTotal (0 if none)
        domain_age_days: Age of the domain in days (0 if unknown)
        heuristic_flags: List of suspicious patterns detected in the URL
        shared_domain_info: Information about shared domain hosting (if any)
        
    Returns:
        A dictionary containing the verdict and explanation
    """
    # Generate the AI synthesis using Gemini
    analysis_data = {
        "analysis": {
            "verdict": google_verdict,
            "vt_detections": vt_score,
            "domain_age_days": domain_age_days,
            "heuristic_flags": heuristic_flags
        }
    }
    
    # Create a prompt with shared domain info
    prompt = generate_ai_synthesizer_prompt(
        url,
        google_verdict,
        vt_score,
        domain_age_days,
        heuristic_flags,
        shared_domain_info
    )
    
    # Get API key from environment
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {
            "verdict": "ERROR",
            "explanation": "Gemini API key not configured"
        }
    
    # Try the same approach as generate_verdict_with_gemini but with our prompt
    try:
        # Try different API endpoints and models until one works
        endpoints_to_try = [
            {
                "url": f"https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key={api_key}",
                "model": "gemini-pro"
            },
            {
                "url": f"https://generativelanguage.googleapis.com/v1/models/gemini-1.0-pro:generateContent?key={api_key}",
                "model": "gemini-1.0-pro"
            },
            {
                "url": f"https://generativelanguage.googleapis.com/v1/models/gemini-1.5-pro:generateContent?key={api_key}",
                "model": "gemini-1.5-pro"
            }
        ]
        
        last_error = None
        generated_text = None
        
        for endpoint_info in endpoints_to_try:
            try:
                endpoint = endpoint_info["url"]
                model = endpoint_info["model"]
                print(f"Trying endpoint for model {model}...")
                
                payload = {
                    "contents": [
                        {
                            "parts": [
                                {
                                    "text": prompt
                                }
                            ]
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.2,
                        "topP": 0.8,
                        "topK": 40,
                        "maxOutputTokens": 1024
                    }
                }
                
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        timeout=30.0
                    )
                    
                    if response.status_code != 200:
                        print(f"API for {model} returned status code {response.status_code}: {response.text}")
                        last_error = f"API returned status code {response.status_code}: {response.text}"
                        continue
                    
                    result = response.json()
                    print(f"Received response from Gemini API for {model}!")
                    
                    # Extract the generated text from the response
                    generated_text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    
                    if generated_text:
                        print(f"Successfully got response from model {model}")
                        break
            except Exception as e:
                print(f"Error with endpoint {endpoint_info['model']}: {str(e)}")
                last_error = str(e)
        
        if not generated_text:
            return {
                "verdict": "ERROR",
                "explanation": f"Failed to get a response from any Gemini API endpoint. Last error: {last_error}"
            }
        
        # Extract verdict (should be in the format "FINAL VERDICT: SAFE/CAUTION/DANGEROUS")
        verdict_line = ""
        for line in generated_text.splitlines():
            if "VERDICT" in line and ("SAFE" in line or "CAUTION" in line or "DANGEROUS" in line):
                verdict_line = line
                break
        
        if "SAFE" in verdict_line:
            verdict = "SAFE"
        elif "CAUTION" in verdict_line:
            verdict = "CAUTION"
        elif "DANGEROUS" in verdict_line:
            verdict = "DANGEROUS"
        else:
            verdict = "UNKNOWN"
        
        # The explanation should be a paragraph after the verdict
        explanation = ""
        capture_explanation = False
        for line in generated_text.splitlines():
            if verdict in line and "VERDICT" in line:
                capture_explanation = True
                continue
            
            if capture_explanation and line.strip():
                explanation = line.strip()
                break
        
        if not explanation:
            # If we couldn't find a clear explanation paragraph, use everything after the verdict
            parts = generated_text.split(verdict_line, 1)
            if len(parts) > 1:
                explanation = parts[1].strip()
        
        return {
            "verdict": verdict,
            "explanation": explanation
        }
    
    except Exception as e:
        # First, check if this is a rate limit error (429)
        error_msg = str(e)
        
        # If it's a rate limit error, fall back to rule-based verdict
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
            print("Detected Gemini API rate limit error, falling back to rule-based verdict")
            return generate_rule_based_verdict_local(
                google_verdict,
                vt_score,
                domain_age_days,
                heuristic_flags
            )
        
        # Fallback to rule-based verdict for any other error
        return generate_rule_based_verdict_local(
            google_verdict,
            vt_score,
            domain_age_days,
            heuristic_flags
        )

def generate_rule_based_verdict_local(
    google_verdict: str, 
    vt_score: int, 
    domain_age_days: int, 
    heuristic_flags: List[str]
) -> Dict[str, Any]:
    """
    Generate a rule-based verdict when AI synthesis fails.
    
    Returns:
        A dictionary containing the verdict and explanation
    """
    # Count the number of heuristic flags
    flag_count = len(heuristic_flags)
    
    # Make a decision based on the collected data
    if google_verdict == "Dangerous":
        return {
            "verdict": "Dangerous",
            "explanation": "This URL has been identified as dangerous by Google's Web Risk API, which maintains a list of known malicious websites. You should avoid visiting this site as it may harm your device or attempt to steal your information."
        }
    elif vt_score > 0:
        return {
            "verdict": "Dangerous",
            "explanation": f"This URL has been flagged by {vt_score} security vendors on VirusTotal as potentially malicious. It's recommended to avoid this website to protect your security."
        }
    elif domain_age_days > 0 and domain_age_days < 7 and flag_count > 0:
        return {
            "verdict": "Dangerous",
            "explanation": f"This domain was created only {domain_age_days} days ago and contains suspicious patterns typical of phishing websites. New domains with suspicious characteristics are commonly used in phishing attacks."
        }
    elif domain_age_days > 0 and domain_age_days < 30 and flag_count > 0:
        return {
            "verdict": "Caution",
            "explanation": f"This domain is relatively new ({domain_age_days} days old) and contains some suspicious patterns. While not definitively malicious, you should be careful when visiting this site or providing any personal information."
        }
    elif flag_count >= 3:
        return {
            "verdict": "Caution",
            "explanation": "This URL contains multiple suspicious patterns commonly found in deceptive websites. While no security vendors have flagged it yet, exercise caution when visiting this site."
        }
    elif flag_count > 0:
        return {
            "verdict": "Caution",
            "explanation": "This URL contains some characteristics that are sometimes associated with suspicious websites. No security vendors have flagged it, but it's always good to be cautious with unfamiliar websites."
        }
    else:
        return {
            "verdict": "Safe",
            "explanation": "This URL shows no signs of being malicious. It has passed checks from major security services and doesn't contain suspicious patterns typically found in harmful websites."
        }

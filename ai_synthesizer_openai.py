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
    Generate a prompt for the AI synthesizer based on the collected URL data.
    
    Args:
        url: The URL being analyzed
        google_verdict: Verdict from Google Web Risk API (Safe/Dangerous)
        vt_score: Number of detections from VirusTotal (0 if none)
        domain_age_days: Age of the domain in days (0 if unknown)
        heuristic_flags: List of suspicious patterns detected in the URL
        shared_domain_info: Information about shared domain hosting (if any)
        
    Returns:
        A formatted prompt string for the AI model
    """
    # Format the heuristic flags as a bulleted list
    heuristic_flags_text = "\n".join([f"- {flag}" for flag in heuristic_flags]) if heuristic_flags else "None detected"
    
    # Create the prompt using the template
    try:
        template_path = os.path.join(os.path.dirname(__file__), "ai_synthesizer_prompt.txt")
        with open(template_path, "r") as f:
            prompt_template = f.read()
    except Exception as e:
        # Fallback to a simple prompt if template file isn't available
        prompt_template = """
        Analyze this URL for security threats:
        URL: {{URL}}
        Google Web Risk verdict: {{GOOGLE_VERDICT}}
        VirusTotal detections: {{VT_SCORE}}
        Domain age (days): {{DOMAIN_AGE_DAYS}}
        Suspicious patterns detected:
        {{HEURISTIC_FLAGS}}
        {{SHARED_DOMAIN_INFO}}
        
        Based on this data, provide a verdict (Safe, Caution, or Dangerous) and explain your reasoning.
        Format your response as:
        VERDICT: [Your verdict]
        [Your explanation]
        """
    
    # Replace placeholders with actual values
    prompt = prompt_template.replace("{{URL}}", url)
    prompt = prompt.replace("{{GOOGLE_VERDICT}}", google_verdict)
    prompt = prompt.replace("{{VT_SCORE}}", str(vt_score))
    prompt = prompt.replace("{{DOMAIN_AGE_DAYS}}", str(domain_age_days))
    prompt = prompt.replace("{{HEURISTIC_FLAGS}}", heuristic_flags_text)
    
    # Add shared domain info if available
    if "{{SHARED_DOMAIN_INFO}}" in prompt_template:
        prompt = prompt.replace("{{SHARED_DOMAIN_INFO}}", shared_domain_info if shared_domain_info else "Shared Domain Info: Not a shared domain")
    else:
        # If the template doesn't have the placeholder, append it to the end
        if shared_domain_info:
            prompt += f"\n\n{shared_domain_info}"
    
    return prompt

async def generate_verdict_with_openai(prompt: str) -> Dict[str, Any]:
    """
    Generate a verdict using the OpenAI API.
    
    Args:
        prompt: The formatted prompt for the AI model
        
    Returns:
        A dictionary containing the verdict and explanation
    """
    # Get the OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {
            "verdict": "ERROR",
            "explanation": "OpenAI API key not configured. Please set the OPENAI_API_KEY environment variable."
        }
        
    try:
        # Prepare the API request to OpenAI
        endpoint = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        # Prepare the message payload
        payload = {
            "model": "gpt-3.5-turbo",  # Can be replaced with gpt-4 for better results
            "messages": [
                {"role": "system", "content": "You are a helpful cybersecurity analyst providing URL safety assessments."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 300
        }
        
        # Make the API request
        async with httpx.AsyncClient() as client:
            response = await client.post(endpoint, json=payload, headers=headers, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            
        # Extract the verdict and explanation
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # Parse the AI's response to extract verdict and explanation
        verdict_line = ""
        explanation = ""
        
        lines = content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith("Verdict:") or line.startswith("VERDICT:"):
                verdict_line = line.replace("Verdict:", "").replace("VERDICT:", "").strip()
            elif not verdict_line and (
                "verdict:" in line.lower() or 
                "assessment:" in line.lower() or
                "safe" in line.lower() or 
                "caution" in line.lower() or 
                "dangerous" in line.lower()
            ):
                # Try to extract verdict if not in the expected format
                if "safe" in line.lower():
                    verdict_line = "Safe"
                elif "caution" in line.lower():
                    verdict_line = "Caution"
                elif "dangerous" in line.lower():
                    verdict_line = "Dangerous"
        
        # Find the explanation paragraph - assume it's after the verdict
        explanation_started = False
        explanation_lines = []
        
        for line in lines:
            if line.startswith("Explanation:") or (verdict_line and not explanation_started):
                explanation_started = True
                if line.startswith("Explanation:"):
                    explanation_lines.append(line.replace("Explanation:", "").strip())
                else:
                    explanation_lines.append(line.strip())
            elif explanation_started and line.strip():
                explanation_lines.append(line.strip())
        
        explanation = " ".join(explanation_lines).strip()
        
        # Fallback if we couldn't parse the format properly
        if not verdict_line:
            if "safe" in content.lower():
                verdict_line = "Safe"
            elif "caution" in content.lower():
                verdict_line = "Caution"
            elif "dangerous" in content.lower():
                verdict_line = "Dangerous"
            else:
                verdict_line = "Caution" # Default to caution if unclear
        
        if not explanation:
            explanation = content  # Use the whole response as explanation
        
        return {
            "verdict": verdict_line,
            "explanation": explanation
        }
    
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401 or e.response.status_code == 403:
            return {
                "verdict": "ERROR",
                "explanation": "Access to the OpenAI API was denied. Please verify your API key is correct and has proper permissions."
            }
        elif e.response.status_code == 429:
            return {
                "verdict": "ERROR",
                "explanation": "OpenAI API rate limit exceeded. Please try again later or use a different API key."
            }
        else:
            return {
                "verdict": "ERROR",
                "explanation": f"Error calling OpenAI API: {str(e)}"
            }
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error calling OpenAI API: {str(e)}\n{error_details}")
        return {
            "verdict": "ERROR",
            "explanation": f"Error calling OpenAI API: {str(e)}"
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
    Main function to analyze a URL using AI synthesis.
    Tries multiple AI providers if available.
    
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
    # Generate the prompt
    prompt = generate_ai_synthesizer_prompt(
        url, 
        google_verdict, 
        vt_score, 
        domain_age_days, 
        heuristic_flags,
        shared_domain_info
    )
    
    # Try OpenAI
    result = await generate_verdict_with_openai(prompt)
    if result.get("verdict") != "ERROR":
        return result
            
    # Fallback to rule-based verdict if AI fails
    return generate_rule_based_verdict(
        google_verdict, 
        vt_score, 
        domain_age_days, 
        heuristic_flags
    )

def generate_rule_based_verdict(
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

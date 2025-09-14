import os
import json
import asyncio
import httpx
from typing import List, Dict, Any
import google.generativeai as genai

def generate_ai_synthesizer_prompt(
    url: str,
    google_verdict: str,
    vt_score: int,
    domain_age_days: int,
    heuristic_flags: List[str]
) -> str:
    """
    Generates a prompt for the AI synthesizer using the template and the collected data.
    
    Args:
        url: The URL that was analyzed
        google_verdict: The verdict from Google Safe Browsing API
        vt_score: The number of detections from VirusTotal
        domain_age_days: The age of the domain in days
        heuristic_flags: List of heuristic analysis flags
        
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
    
    try:
        # Configure the Gemini API with the API key
        genai.configure(api_key=api_key)
        
        # Print available models for debugging
        available_models = []
        try:
            available_models = [model.name for model in genai.list_models()]
            print("Available models:", available_models)
        except Exception as e:
            print(f"Error listing models: {e}")
        
        # Try to select an appropriate model with fallbacks
        model_name = None
        for candidate in ['gemini-1.5-pro', 'gemini-pro', 'gemini-1.0-pro']:
            if candidate in available_models:
                model_name = candidate
                break
        
        # If we still don't have a model, use the default
        if not model_name:
            print("No specific model found, using default")
            model_name = 'gemini-1.5-pro'  # Default to this and let the API handle errors
        
        print(f"Using model: {model_name}")
        
        try:
            # Create a GenerativeModel instance
            model = genai.GenerativeModel(model_name)
            
            # Generate the content
            response = await asyncio.to_thread(
                model.generate_content,
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.2,
                    top_p=0.8,
                    top_k=40,
                    max_output_tokens=1024,
                )
            )
            
            # Get the generated text
            generated_text = response.text
            
        except Exception as sdk_error:
            # If the SDK approach fails, try direct REST API
            print(f"SDK approach failed: {sdk_error}, trying REST API...")
            import httpx
            
            # Fallback to direct REST API call
            api_version = "v1"  # Try v1 instead of v1beta
            model_id = "gemini-pro"  # This seems most widely available
            
            endpoint = f"https://generativelanguage.googleapis.com/{api_version}/models/{model_id}:generateContent?key={api_key}"
            
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
                    raise Exception(f"API returned status code {response.status_code}: {response.text}")
                
                result = response.json()
                generated_text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        
        if not generated_text:
            return {
                "verdict": "ERROR",
                "explanation": "Failed to get a response from Gemini API"
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
        else:
            return {
                "verdict": "ERROR",
                "explanation": f"Error calling Gemini API: {str(e)}"
            }

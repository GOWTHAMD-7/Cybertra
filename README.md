# Cybertra - Defending Your Digital Path

## Overview
Cybertra is a comprehensive security tool that analyzes URLs for potential threats using multiple security checks and AI-powered analysis.

## Key Features
- Multi-layered URL analysis using Google Web Risk API, VirusTotal, and heuristic pattern detection
- AI-powered verdict synthesis using either OpenAI or Google Gemini models
- Fallback mechanisms to ensure reliable operation even when AI services are unavailable
- Clear, human-readable explanations of security verdicts
- Webpage content summarization for safer browsing
- QR code scanner for analyzing links embedded in QR codes

## AI Synthesis Architecture
The system employs a multi-tier AI strategy:

1. **Primary AI**: OpenAI's GPT models (if API key is available)
2. **Secondary AI**: Google's Gemini models (if API key is available) 
3. **Fallback System**: Rule-based analysis that mimics AI reasoning

This ensures the system remains operational even when facing API rate limits or service outages.

## Environment Variables
```
# API Keys
GOOGLE_API_KEY=your_google_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Enable AI Analysis
ENABLE_AI=true

# Gemini API Key
GEMINI_API_KEY=your_gemini_api_key

# OpenAI API Key (Optional - leave empty to use Gemini)
OPENAI_API_KEY=your_openai_api_key
```

## Running the Application
```
# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload
```

## Deployment

### Vercel Deployment
This project is configured for deployment on Vercel:

1. Connect your GitHub repository to Vercel
2. Set the necessary environment variables in the Vercel dashboard
3. Deploy with the following settings:
   - Framework Preset: Other
   - Build Command: None (automatically handled)
   - Output Directory: /vercel/output
   - Install Command: pip install -r requirements.txt

### Other Platforms
The application can also be deployed on:
- Heroku (use a Procfile)
- AWS Lambda (with additional configuration)
- Google Cloud Run (containerized)

## Handling Rate Limits
The system has been enhanced to handle rate limit errors from both the OpenAI and Gemini APIs. If a rate limit is encountered:

1. The system will attempt to use the alternative AI provider
2. If both providers are rate-limited, it will fall back to rule-based analysis
3. Clear error messages will be provided in the API response

## Rule-Based Analysis
When AI services are unavailable, the system uses a sophisticated rule-based algorithm that considers:
- Google Web Risk API verdict
- VirusTotal detection count
- Domain age
- Number and types of heuristic flags detected

This ensures reasonable security verdicts are still provided even without AI services.

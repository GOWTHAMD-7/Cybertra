from fastapi import FastAPI, Request
import sys
import os

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the app from main.py
try:
    from main import app as main_app
    app = main_app
except ImportError as e:
    # Fallback to a simple app if there's an import error
    app = FastAPI()
    
    @app.get("/")
    async def root():
        return {"message": "Cybertra API - Deployment Mode"}
    
    @app.get("/api/health")
    async def health():
        return {"status": "ok", "message": "Deployment mode active"}
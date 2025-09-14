from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from datetime import datetime

app = FastAPI()

@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return JSONResponse({
        "status": "ok",
        "version": "1.0.0",
        "name": "Cybertra - Defending Your Digital Path",
        "timestamp": datetime.now().isoformat(),
        "environment": "Vercel"
    })

def handler(request, context):
    return app
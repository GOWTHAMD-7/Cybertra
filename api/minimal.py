"""
Minimal API entry point for Vercel deployment
"""
from fastapi import FastAPI

# Create app
app = FastAPI()

@app.get("/")
async def read_root():
    """Basic root endpoint"""
    return {"message": "Cybertra API is running!"}

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok"}

# Handler for Vercel
def handler(req, context):
    return app
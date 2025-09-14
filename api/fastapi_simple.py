"""
FastAPI version of the serverless function for Vercel
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

# Initialize FastAPI app
app = FastAPI()

@app.get("/")
async def read_root():
    """Root endpoint returning a simple welcome message"""
    return {"message": "Welcome to Cybertra – Defending Your Digital Path!"}

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok"}

# Create a handler that Vercel can use
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            "message": "Welcome to Cybertra – Defending Your Digital Path!",
            "version": "1.0.0",
            "path": self.path,
            "status": "ok"
        }
        
        import json
        self.wfile.write(json.dumps(response).encode())
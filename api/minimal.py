"""
Minimal API entry point for Vercel deployment
"""
from http.server import BaseHTTPRequestHandler
import json

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response_data = {
            "message": "Cybertra API is running!",
            "status": "ok",
            "path": self.path
        }
        
        self.wfile.write(json.dumps(response_data).encode())
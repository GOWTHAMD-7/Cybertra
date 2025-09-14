# Cybertra – Defending Your Digital Path

## Debugging Vercel Deployment Issues

If you're seeing a "This Serverless Function has crashed" error when deploying to Vercel, here are some steps to troubleshoot:

### 1. Start with Minimal API

We've included a minimal API version in `api/minimal.py` that only has basic endpoints. This can help identify if the issue is with the core FastAPI setup or with more complex code.

1. Update `vercel.json` to point to the minimal API:
```json
{
  "version": 2,
  "builds": [
    {
      "src": "api/minimal.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "/api/minimal.py"
    }
  ]
}
```

2. Deploy and check if this minimal version works.

### 2. Common Issues with FastAPI on Vercel

#### Handler Function Format

Ensure the handler function has the correct format:

```python
def handler(req, context):
    return app
```

#### Imports and Dependencies

- Use simple imports that don't rely on file structure
- Ensure all dependencies are explicitly listed in `requirements.txt`
- Use compatible versions that work with Vercel's Python runtime

#### File Structure

Vercel expects a specific file structure for serverless functions:

```
api/
  __init__.py
  index.py
  health.py
  ...
```

### 3. Vercel Function Logs

Always check the Vercel Function Logs for detailed error messages:

1. Go to your Vercel dashboard
2. Select your project
3. Go to "Functions" tab
4. Click on the function that's failing
5. Check the logs for detailed error information

### 4. Progressive Enhancement

If the minimal API works, progressively add features back until you identify what's causing the issue:

1. Start with just the root endpoint
2. Add template rendering
3. Add form handling
4. Add HTTP client functionality
5. Add more complex features

### 5. Use Vercel Dev for Local Testing

Install and use Vercel CLI to test locally:

```bash
npm install -g vercel
vercel dev
```

This will simulate the Vercel environment locally and can help identify issues before deployment.

### 6. Additional Resources

- [Vercel Python Runtime Documentation](https://vercel.com/docs/functions/runtimes/python)
- [FastAPI on Vercel Guide](https://vercel.com/guides/deploying-fastapi-with-vercel)
- [Serverless Python Functions](https://vercel.com/docs/concepts/functions/serverless-functions/runtimes/python)
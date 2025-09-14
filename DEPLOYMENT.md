# Deploying Cybertra to Vercel

This guide will help you deploy the Cybertra application to Vercel.

## Prerequisites

1. A [Vercel](https://vercel.com) account
2. [Git](https://git-scm.com/downloads) installed on your local machine
3. [GitHub](https://github.com) account (for source control)

## Step 1: Push your code to GitHub

1. Create a new repository on GitHub
2. Initialize Git in your project folder (if not already done):
   ```
   git init
   ```
3. Add all files to Git:
   ```
   git add .
   ```
4. Commit the files:
   ```
   git commit -m "Initial commit"
   ```
5. Add your GitHub repository as a remote:
   ```
   git remote add origin https://github.com/your-username/your-repo-name.git
   ```
6. Push the code to GitHub:
   ```
   git push -u origin main
   ```

## Step 2: Deploy to Vercel

### Option 1: Deploy from the Vercel Dashboard

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click "Add New" > "Project"
3. Select your GitHub repository
4. Configure the project:
   - Framework Preset: Other
   - Root Directory: ./
   - Build Command: Leave default
   - Output Directory: Leave default
5. Add Environment Variables:
   - Copy variables from `.env.sample` to Vercel's environment variables section
   - Add your actual API keys
6. Click "Deploy"

### Option 2: Deploy using Vercel CLI

1. Install Vercel CLI:
   ```
   npm install -g vercel
   ```
2. Log in to Vercel:
   ```
   vercel login
   ```
3. Navigate to your project directory and run:
   ```
   vercel
   ```
4. Follow the prompts to configure your project
5. After deployment, you can update environment variables:
   ```
   vercel env add GOOGLE_API_KEY
   ```

## Step 3: Verify Deployment

1. Once deployed, Vercel will provide you with a URL for your application
2. Visit the URL to ensure the application is working correctly
3. Test the URL analysis functionality to confirm it works in the deployed environment

## Troubleshooting

### Common Issues

1. **Missing Dependencies**: Ensure all required packages are in `requirements.txt`
2. **Environment Variables**: Verify all required environment variables are set in Vercel
3. **Build Errors**: Check the build logs in Vercel for specific error messages
4. **API Timeouts**: Serverless functions have execution time limits (10-60 seconds on Vercel)

### If You Encounter Problems

1. Check the Function Logs in Vercel dashboard
2. Verify Python version compatibility (using Python 3.9 as specified in runtime.txt)
3. Test locally with [Vercel CLI](https://vercel.com/docs/cli) using `vercel dev`
4. Consider optimizing heavy operations for serverless environments

## Updating Your Deployment

To update your deployment after making changes:

1. Commit your changes to Git:
   ```
   git add .
   git commit -m "Update description"
   git push
   ```
2. Vercel will automatically deploy the new version if you've set up automatic deployments

## Additional Resources

- [Vercel Python Documentation](https://vercel.com/docs/functions/runtimes/python)
- [FastAPI on Vercel](https://vercel.com/guides/deploying-fastapi-with-vercel)
- [Environment Variables in Vercel](https://vercel.com/docs/projects/environment-variables)
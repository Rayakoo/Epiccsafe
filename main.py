import os
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scan import router as scan_router
from auth import router as auth_router
from admin import router as admin_router
from reports import router as reports_router

app = FastAPI(
    title="EpiccSafe API",
    description="API for URL scanning and user authentication",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS - allow frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://epiccsafe.vercel.app",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan_router, prefix="")          # scan endpoints at root: /scan
app.include_router(auth_router)                     # auth endpoints at /auth
app.include_router(admin_router)                    # admin endpoints at /admin
app.include_router(reports_router)                  # reports endpoints at /reports

# Optional: health check
@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy", 
        "service": "EpiccSafe API",
        "version": "1.0.0"
    }
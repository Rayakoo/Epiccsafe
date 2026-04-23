from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
import supabase_client as auth

app = FastAPI(
    title="Supabase Auth API",
    description="API for user authentication and management using Supabase",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Security scheme for extracting token from Authorization header
security = HTTPBearer()

# Pydantic models for request/response
class SignUpRequest(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=6, description="User's password (minimum 6 characters)")
    data: Optional[dict] = Field(default=None, description="Additional user metadata")

class SignInRequest(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")

class UserResponse(BaseModel):
    id: str = Field(..., description="Unique user identifier")
    email: EmailStr = Field(..., description="User's email address")
    created_at: str = Field(..., description="Timestamp when user was created")
    updated_at: Optional[str] = Field(default=None, description="Timestamp when user was last updated")

class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token for authentication")
    token_type: str = Field(default="bearer", description="Type of token")
    user: UserResponse = Field(..., description="User information")

# Dependency to get current user from token
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Verify the JWT token with Supabase
        user_response = auth.supabase.auth.get_user(token)
        if user_response.user:
            return user_response.user
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Routes
@app.get("/", tags=["Health"])
async def root():
    """Root endpoint to check if server is healthy"""
    return {"status": "server is healthy"}

@app.post("/signup", response_model=TokenResponse, tags=["Authentication"])
async def signup(request: SignUpRequest):
    """
    Register a new user account
    
    - **email**: User's email address
    - **password**: User's password (minimum 6 characters)
    - **data**: Optional additional user metadata
    """
    result = auth.sign_up(request.email, request.password, request.data)
    if not result or not result.user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create user account"
        )
    
    # Extract user data for response
    user_data = result.user
    user_response = UserResponse(
        id=user_data.id,
        email=user_data.email,
        created_at=user_data.created_at,
        updated_at=user_data.updated_at
    )
    
    return TokenResponse(
        access_token=result.session.access_token if result.session else "",
        user=user_response
    )

@app.post("/signin", response_model=TokenResponse, tags=["Authentication"])
async def signin(request: SignInRequest):
    """
    Authenticate user and return access token
    
    - **email**: User's email address
    - **password**: User's password
    
    Returns access token and user information if successful
    """
    result = auth.sign_in(request.email, request.password)
    if not result or not result.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_data = result.user
    user_response = UserResponse(
        id=user_data.id,
        email=user_data.email,
        created_at=user_data.created_at,
        updated_at=user_data.updated_at
    )
    
    return TokenResponse(
        access_token=result.session.access_token if result.session else "",
        user=user_response
    )

@app.post("/signout", tags=["Authentication"])
async def signout(current_user: dict = Depends(get_current_user)):
    """
    Sign out the current authenticated user
    
    Requires valid Bearer token in Authorization header
    """
    success = auth.sign_out()
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to sign out"
        )
    return {"message": "Successfully signed out"}

@app.get("/me", response_model=UserResponse, tags=["Authentication"])
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get current authenticated user information
    
    Requires valid Bearer token in Authorization header
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at
    )

# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Check if the API and its dependencies are healthy
    
    Returns service status information
    """
    return {
        "status": "healthy", 
        "service": "Supabase Auth API",
        "version": "1.0.0"
    }

# To run: uvicorn main:app --reload
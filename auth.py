from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
import supabase_client as auth

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()

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
    created_at: datetime = Field(..., description="Timestamp when user was created")
    updated_at: Optional[datetime] = Field(default=None, description="Timestamp when user was last updated")

class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token for authentication")
    token_type: str = Field(default="bearer", description="Type of token")
    user: UserResponse = Field(..., description="User information")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
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

@router.post("/signup", response_model=TokenResponse)
async def signup(request: SignUpRequest):
    """
    Register a new user account and create admin record
    """
    try:
        result = auth.sign_up(request.email, request.password, request.data)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Signup error: {str(e)}")
    if not result or not getattr(result, "user", None):
        err_msg = result.get("error") if isinstance(result, dict) else "Unknown error"
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Unable to create user account: {err_msg}")
    user_data = result.user
    # Insert admin record using service role
    try:
        admin_data = {
            "id": user_data.id,
            "email": user_data.email,
            "name": request.data.get("name") if request.data else None,
            "password_hash": "",  # password handled by Supabase auth
        }
        # Remove None values
        admin_data = {k: v for k, v in admin_data.items() if v is not None}
        auth.supabase_admin.table("admins").insert(admin_data).execute()
    except Exception as e:
        # Log error but don't fail signup? For simplicity we raise.
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to create admin record: {str(e)}")
    # Convert Supabase timestamp strings to datetime objects
    created_at = datetime.fromisoformat(user_data.created_at.replace("Z", "+00:00"))
    updated_at = None
    if user_data.updated_at:
        updated_at = datetime.fromisoformat(user_data.updated_at.replace("Z", "+00:00"))
    user_response = UserResponse(
        id=user_data.id,
        email=user_data.email,
        created_at=created_at,
        updated_at=updated_at
    )
    access_token = result.session.access_token if result.session else ""
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_response
    )

@router.post("/signin", response_model=TokenResponse)
async def signin(request: SignInRequest):
    """
    Authenticate user and return access token
    """
    try:
        result = auth.sign_in(request.email, request.password)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Signin error: {str(e)}")
    if not result or not getattr(result, "user", None):
        err_msg = result.get("error") if isinstance(result, dict) else "Invalid email or password"
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=err_msg,
                            headers={"WWW-Authenticate": "Bearer"})
    user_data = result.user
    # Convert timestamps
    created_at = datetime.fromisoformat(user_data.created_at.replace("Z", "+00:00"))
    updated_at = None
    if user_data.updated_at:
        updated_at = datetime.fromisoformat(user_data.updated_at.replace("Z", "+00:00"))
    user_response = UserResponse(
        id=user_data.id,
        email=user_data.email,
        created_at=created_at,
        updated_at=updated_at
    )
    access_token = result.session.access_token if result.session else ""
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_response
    )

@router.post("/signout")
async def signout(current_user: dict = Depends(get_current_user)):
    """
    Sign out the current authenticated user
    """
    try:
        success = auth.sign_out()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Signout error: {str(e)}")
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Unable to sign out")
    return {"message": "Successfully signed out"}

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get current authenticated user information
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at
    )
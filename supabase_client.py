import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Supabase client
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

# Create Supabase client for regular operations (uses anon key)
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Create Supabase admin client for operations requiring service role
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


def sign_up(email: str, password: str, data: dict = None):
    """
    Register a new user with email and password
    
    Args:
        email (str): User's email address
        password (str): User's password
        data (dict, optional): Additional user data to store in user.metadata
        
    Returns:
        dict: Response from Supabase containing user and session data
        None: If registration fails
    """
    try:
        user_data = data or {}
        if "role" not in user_data:
            user_data["role"] = "admin"
        
        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": user_data
            }
        })
        return response
    except Exception as e:
        print(f"Error during signup: {e}")
        return {"error": str(e)}


def create_admin(admin_data: dict):
    """
    Create a new admin record in the admins table
    
    Args:
        admin_data (dict): Admin data with id, email, name, etc.
        
    Returns:
        dict: Response from Supabase
        None: If creation fails
    """
    try:
        response = supabase_admin.table("admins").insert({
            "id": admin_data.get("id"),
            "email": admin_data.get("email"),
            "name": admin_data.get("name", ""),
        }).execute()
        return response
    except Exception as e:
        print(f"Error creating admin: {e}")
        return None


def is_admin(user_id: str):
    """
    Check if a user is an admin
    
    Args:
        user_id (str): User ID to check
        
    Returns:
        bool: True if user is admin, False otherwise
    """
    try:
        response = supabase_admin.table("admins").select("id").eq("id", user_id).execute()
        return len(response.data) > 0
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False


def sign_in(email: str, password: str):
    """
    Authenticate user with email and password
    
    Args:
        email (str): User's email address
        password (str): User's password
        
    Returns:
        dict: Response from Supabase containing user and session data
        None: If authentication fails
    """
    try:
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        return response
    except Exception as e:
        print(f"Error during signin: {e}")
        return None


def sign_out(token: str = None):
    """
    Sign out the current user
    
    Args:
        token (str, optional): User's JWT token. If provided, will sign out that specific session.
        
    Returns:
        bool: True if sign out successful, False otherwise
    """
    try:
        if token:
            # Set the session with the provided token and then sign out
            supabase.auth.set_session(token, "", "")
        supabase.auth.sign_out()
        return True
    except Exception as e:
        print(f"Error during signout: {e}")
        return False


def sign_out_user(user_id: str):
    """
    Sign out a user by revoking all sessions (admin operation)
    
    Args:
        user_id (str): User ID to sign out
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Use admin API to sign out user (revoke all sessions)
        supabase_admin.auth.admin.sign_out(user_id)
        return True
    except Exception as e:
        # If admin sign_out not available, try alternative
        print(f"Error during admin signout: {e}")
        return False


def get_user():
    """
    Get the current authenticated user
    
    Returns:
        dict: User object if authenticated
        None: If not authenticated or error occurs
    """
    try:
        user = supabase.auth.get_user()
        return user
    except Exception as e:
        print(f"Error getting user: {e}")
        return None


def update_user(data: dict):
    """
    Update the current user's data
    
    Args:
        data (dict): User data to update
        
    Returns:
        dict: Response from Supabase
        None: If update fails
    """
    try:
        response = supabase.auth.update_user(data)
        return response
    except Exception as e:
        print(f"Error updating user: {e}")
        return None


def reset_password_email(email: str):
    """
    Send a password reset email to the specified email address
    
    Args:
        email (str): User's email address
        
    Returns:
        dict: Response from Supabase
        None: If sending reset email fails
    """
    try:
        response = supabase.auth.reset_password_email(email)
        return response
    except Exception as e:
        print(f"Error sending password reset email: {e}")
        return None


def verify_otp(email: str, token: str, type: str = "signup"):
    """
    Verify OTP for email authentication
    
    Args:
        email (str): User's email address
        token (str): OTP token received via email
        type (str): Type of verification (signup, signin, recovery, etc.)
        
    Returns:
        dict: Response from Supabase
        None: If verification fails
    """
    try:
        response = supabase.auth.verify_otp({
            "email": email,
            "token": token,
            "type": type
        })
        return response
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return None


# Example usage
if __name__ == "__main__":
    # Example: Sign up a new user
    print("=== Supabase Auth Example ===")
    
    # Sign up
    # result = sign_up("test@example.com", "securepassword123", {"full_name": "Test User"})
    # if result:
    #     print("Signup successful:", result.user)
    # else:
    #     print("Signup failed")
    
    # Sign in
    # result = sign_in("test@example.com", "securepassword123")
    # if result:
    #     print("Signin successful:", result.user)
    # else:
    #     print("Signin failed")
    
    # Get current user
    # user = get_user()
    # if user:
    #     print("Current user:", user.user)
    # else:
    #     print("No user authenticated")
    
    # Sign out
    # if sign_out():
    #     print("Signed out successfully")
    # else:
    #     print("Sign out failed")
    
    print("Example code is commented out. Uncomment to test.")
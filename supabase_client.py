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
        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": data or {}
            }
        })
        return response
    except Exception as e:
        print(f"Error during signup: {e}")
        return None


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


def sign_out():
    """
    Sign out the current user
    
    Returns:
        bool: True if sign out successful, False otherwise
    """
    try:
        supabase.auth.sign_out()
        return True
    except Exception as e:
        print(f"Error during signout: {e}")
        return None


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
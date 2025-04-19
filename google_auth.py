import json
import os
import base64
from urllib.parse import urlparse

import requests
from flask import Blueprint, redirect, request, url_for, session, flash
from flask_login import login_user, logout_user, current_user, login_required
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from oauthlib.oauth2 import WebApplicationClient
from db_setup import db, logger
from models import User

# Configuration
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly', 'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

# These are the deployed app redirect URIs to try
# At least one of these must match what's in Google Cloud Console for authentication to work
POSSIBLE_REDIRECT_URIS = [
    "https://goqmail.xyz/google_login/callback",  # Production domain
]

# Set environment variable for use by the auth flow
DEFAULT_REDIRECT_URI = POSSIBLE_REDIRECT_URIS[0]
os.environ['OAUTH_REDIRECT_URI'] = DEFAULT_REDIRECT_URI
print(f"Setting OAUTH_REDIRECT_URI to {DEFAULT_REDIRECT_URI}")
print(
    f"IMPORTANT: Please add this exact URI to your Google Cloud Console: {DEFAULT_REDIRECT_URI}"
)

REDIRECT_URI = None  # Will be set dynamically

google_auth = Blueprint("google_auth", __name__)


@google_auth.route("/google_login")
def google_login():
    """Start the Google OAuth flow."""
    # Check if Google OAuth credentials are available
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    if not client_id or not client_secret:
        flash(
            "Google OAuth credentials are not configured. Please add GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET to the environment variables.",
            "danger")
        return redirect(url_for("index"))

    # Set up the OAuth flow with the client secrets
    try:
        # Create a simple direct config without using a file
        redirect_uri = "https://goqmail.xyz/google_login/callback"
        
        # Create flow directly without the client secrets file
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": client_id,
                    "project_id": "",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_secret": client_secret,
                    "redirect_uris": [redirect_uri]
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        # Generate the authorization URL without a state parameter
        authorization_url = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent')[0]
        
        print(f"DEBUG - Authorization URL: {authorization_url}")
        
        # Store the flow in the session for later use
        print("DEBUG - Simple OAuth flow started without state parameter")
        
        # Redirect to the Google authorization URL
        return redirect(authorization_url)

    except Exception as e:
        flash(f"Error starting Google login: {str(e)}", "danger")
        print(f"DEBUG - Error in google_login: {str(e)}")
        return redirect(url_for("index"))


@google_auth.route("/google_login/callback")
def callback():
    """Handle the OAuth callback with absolutely minimal processing."""
    # Check if there was an error in the callback
    error = request.args.get('error')
    if error:
        # Just report the error and redirect
        flash(f"Authorization failed: {error}", "danger")
        return redirect(url_for("index"))

    # Get the authorization code from the callback - the only thing we really need
    code = request.args.get("code")
    
    if not code:
        flash("No authorization code received from Google.", "danger")
        return redirect(url_for("index"))
        
    print(f"DEBUG - Authorization code received: {code[:5]}...")
    
    # We'll use a fixed redirect URI that must match what's in Google Console
    redirect_uri = "https://goqmail.xyz/google_login/callback"
    
    try:
        # Get client ID and client secret from environment variables
        client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
        client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
        
        # Create a flow directly (no dependency on stored REDIRECT_URI)
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": client_id,
                    "project_id": "",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_secret": client_secret,
                    "redirect_uris": [redirect_uri]
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        # Use the authorization response
        full_auth_response_url = request.url
        print(f"DEBUG - Full auth response URL: {full_auth_response_url}")
        
        # Fetch the token
        flow.fetch_token(authorization_response=full_auth_response_url)
        
        # Get the credentials from the flow
        credentials = flow.credentials

        # Store credentials in the session (only the necessary parts)
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        # Get user info
        user_info = get_user_info(credentials)
        user_email = user_info.get('email')
        user_name = user_info.get(
            'name',
            user_email.split('@')[0] if user_email else 'Unknown')
        profile_pic = user_info.get('picture')

        # Store in session
        session['user_email'] = user_email
        session['user_name'] = user_name

        # Check if user exists in database, if not create
        user = User.query.filter_by(email=user_email).first()
        if not user:
            # Create new user
            user = User(username=user_name,
                        email=user_email,
                        profile_pic=profile_pic)
            db.session.add(user)
            db.session.commit()

        # Login user with Flask-Login
        login_user(user)

        flash(f"Successfully logged in as {user_email}", "success")
        return redirect(url_for("fetch_google_emails"))

    except Exception as e:
        flash(f"Error during authentication: {str(e)}", "danger")
        return redirect(url_for("index"))


def get_oauth_flow():
    """Create and configure the OAuth flow."""
    # Determine the redirect URI based on the environment
    global REDIRECT_URI

    # Check if a specific redirect URI is provided in environment variables
    manual_redirect_uri = os.environ.get('OAUTH_REDIRECT_URI')
    if manual_redirect_uri:
        REDIRECT_URI = manual_redirect_uri
        print(
            f"DEBUG - Using manually configured redirect URI: {REDIRECT_URI}")
    elif not REDIRECT_URI:
        replit_domain = os.environ.get(
            'REPLIT_DOMAINS')  # Note: it's DOMAINS with an 'S'
        if replit_domain:
            # Use the exact domain from environment
            # If it contains multiple domains (comma-separated), take the first one
            if ',' in replit_domain:
                replit_domain = replit_domain.split(',')[0].strip()

            # Use all possible variations of the redirect URI to increase compatibility
            deployed_domain = replit_domain

            # Get the current protocol from request if available
            use_https = True  # Default to HTTPS for deployed environments

            REDIRECT_URI = f"https://{deployed_domain}/google_login/callback"
            print(f"DEBUG - Using redirect URI: {REDIRECT_URI}")
            print(
                f"DEBUG - Please make sure one of these URIs is configured in Google Cloud Console:"
            )
            print(f"DEBUG - 1. {REDIRECT_URI}")
            print(f"DEBUG - 2. http://{deployed_domain}/google_login/callback")
        else:
            # Fallback to localhost
            REDIRECT_URI = "http://localhost:5000/google_login/callback"
            print(
                "DEBUG - No Replit domain found, using localhost redirect URI")
            print(
                "DEBUG - For local testing, add this URI to Google Cloud Console OAuth configuration:"
            )

    # Get client ID and client secret from environment variables
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    # Validate that we have the required credentials
    if not client_id or not client_secret:
        raise ValueError(
            "Google OAuth credentials missing. Please set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET environment variables."
        )

    # Only create client_secret.json if it doesn't exist
    if not os.path.exists(CLIENT_SECRETS_FILE):
        client_config = {
            "web": {
                "client_id": client_id,
                "project_id": "",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url":
                "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": client_secret,
                "redirect_uris": [REDIRECT_URI]
            }
        }
        with open(CLIENT_SECRETS_FILE, 'w') as f:
            json.dump(client_config, f)

    # Create the flow
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE,
                                         scopes=SCOPES,
                                         redirect_uri=REDIRECT_URI)

    return flow


def create_flow_with_uri(redirect_uri):
    """
    Create an OAuth flow with a specific redirect URI.
    This is useful when the actual callback URI differs from what was expected.
    
    Args:
        redirect_uri: The actual redirect URI to use
        
    Returns:
        An OAuth flow configured with the specified redirect URI
    """
    # Get client ID and client secret from environment variables
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    # Validate that we have the required credentials
    if not client_id or not client_secret:
        raise ValueError(
            "Google OAuth credentials missing. Please set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET environment variables."
        )

    # Create a custom client config with the specific redirect URI
    client_config = {
        "web": {
            "client_id": client_id,
            "project_id": "",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url":
            "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": client_secret,
            "redirect_uris": [redirect_uri]
        }
    }

    # Write this to a temporary file
    temp_client_secret_file = f"{CLIENT_SECRETS_FILE}.temp"
    with open(temp_client_secret_file, 'w') as f:
        json.dump(client_config, f)

    # Create the flow with this specific redirect URI
    flow = Flow.from_client_secrets_file(temp_client_secret_file,
                                         scopes=SCOPES,
                                         redirect_uri=redirect_uri)

    # Clean up the temporary file
    try:
        os.remove(temp_client_secret_file)
    except:
        pass

    return flow


def get_user_info(credentials):
    """Get the user's information using the given credentials."""
    try:
        # Build the service
        service = build('oauth2', 'v2', credentials=credentials)

        # Get the user's info
        user_info = service.userinfo().get().execute()
        return user_info

    except Exception as e:
        print(f"Error getting user info: {str(e)}")
        return {}


def get_credentials_from_session():
    """Retrieve and validate credentials from the session."""
    if 'credentials' not in session:
        return None

    # Get the credentials from the session
    creds_data = session['credentials']

    # Create credentials object
    return Credentials(token=creds_data['token'],
                       refresh_token=creds_data['refresh_token'],
                       token_uri=creds_data['token_uri'],
                       client_id=creds_data['client_id'],
                       client_secret=creds_data['client_secret'],
                       scopes=creds_data['scopes'])


def fetch_gmail_messages(max_results=10):
    """Fetch the user's Gmail messages using stored credentials."""
    credentials = get_credentials_from_session()
    if not credentials:
        return None, "Not authenticated with Google"

    try:
        # Build the Gmail API service
        service = build('gmail', 'v1', credentials=credentials)

        # Get a list of messages
        results = service.users().messages().list(
            userId='me', maxResults=max_results).execute()
        messages = results.get('messages', [])

        if not messages:
            return [], "No messages found"

        # Fetch details for each message
        emails = []
        for message in messages:
            msg = service.users().messages().get(userId='me',
                                                 id=message['id'],
                                                 format='full').execute()

            # Extract email details
            headers = msg['payload']['headers']
            subject = ""
            sender = ""
            date = ""

            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'From':
                    sender = header['value']
                elif header['name'] == 'Date':
                    date = header['value']

            # Get the body of the message
            body = ""
            if 'parts' in msg['payload']:
                for part in msg['payload']['parts']:
                    if part['mimeType'] == 'text/plain':
                        data = part['body'].get('data', '')
                        if data:
                            body += base64.urlsafe_b64decode(data).decode(
                                'utf-8', errors='replace')
            else:
                data = msg['payload']['body'].get('data', '')
                if data:
                    body += base64.urlsafe_b64decode(data).decode(
                        'utf-8', errors='replace')

            # Add the email to the list
            emails.append({
                'id': msg['id'],
                'subject': subject,
                'from': sender,
                'date': date,
                'body': body,
            })

        return emails, None

    except Exception as e:
        return None, f"Error fetching Gmail messages: {str(e)}"

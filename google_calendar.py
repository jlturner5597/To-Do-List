"""
Google Calendar Integration Module
Handles OAuth 2.0 flow and Calendar API operations
"""

import os
import json
from datetime import datetime, timedelta

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Google Calendar API scope
SCOPES = ['https://www.googleapis.com/auth/calendar.events']

# Environment variables for OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:5000/api/google/callback')


def get_client_config():
    """Build OAuth client config from environment variables."""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return None
    
    return {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [GOOGLE_REDIRECT_URI]
        }
    }


def create_auth_flow(state=None):
    """Create OAuth flow for authorization."""
    client_config = get_client_config()
    if not client_config:
        raise ValueError("Google OAuth credentials not configured")
    
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI
    )
    
    if state:
        flow.state = state
    
    return flow


def get_authorization_url():
    """Generate the Google OAuth authorization URL."""
    flow = create_auth_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    return authorization_url, state


def exchange_code_for_tokens(code, state=None):
    """Exchange authorization code for access/refresh tokens."""
    flow = create_auth_flow(state)
    flow.fetch_token(code=code)
    credentials = flow.credentials
    
    return {
        'access_token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': json.dumps(list(credentials.scopes)) if credentials.scopes else None,
        'expiry': credentials.expiry.isoformat() if credentials.expiry else None
    }


def build_credentials_from_tokens(token_data):
    """Build Credentials object from stored token data."""
    expiry = None
    if token_data.get('expiry'):
        expiry_str = token_data['expiry']
        if isinstance(expiry_str, str):
            # Handle ISO format with or without microseconds
            try:
                expiry = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
            except ValueError:
                expiry = datetime.strptime(expiry_str, '%Y-%m-%dT%H:%M:%S.%f')
        else:
            expiry = expiry_str
    
    scopes = token_data.get('scopes')
    if isinstance(scopes, str):
        scopes = json.loads(scopes)
    
    return Credentials(
        token=token_data['access_token'],
        refresh_token=token_data.get('refresh_token'),
        token_uri=token_data.get('token_uri', 'https://oauth2.googleapis.com/token'),
        client_id=token_data.get('client_id', GOOGLE_CLIENT_ID),
        client_secret=token_data.get('client_secret', GOOGLE_CLIENT_SECRET),
        scopes=scopes,
        expiry=expiry
    )


def get_calendar_service(credentials):
    """Build Google Calendar API service."""
    return build('calendar', 'v3', credentials=credentials)


def create_calendar_event(credentials, title, start_datetime, description=None, duration_minutes=60):
    """
    Create a new event on the user's primary Google Calendar.
    
    Args:
        credentials: Google OAuth credentials
        title: Event title
        start_datetime: Start time as ISO string or datetime object
        description: Optional event description
        duration_minutes: Event duration in minutes (default 60)
    
    Returns:
        Created event ID or None on failure
    """
    try:
        service = get_calendar_service(credentials)
        
        # Parse start datetime
        if isinstance(start_datetime, str):
            start = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
        else:
            start = start_datetime
        
        end = start + timedelta(minutes=duration_minutes)
        
        event = {
            'summary': title,
            'start': {
                'dateTime': start.isoformat(),
                'timeZone': 'UTC',
            },
            'end': {
                'dateTime': end.isoformat(),
                'timeZone': 'UTC',
            },
        }
        
        if description:
            event['description'] = description
        
        created_event = service.events().insert(calendarId='primary', body=event).execute()
        return created_event.get('id')
    
    except HttpError as error:
        print(f"Error creating calendar event: {error}")
        return None
    except Exception as error:
        print(f"Unexpected error creating calendar event: {error}")
        return None


def update_calendar_event(credentials, event_id, title=None, start_datetime=None, description=None, duration_minutes=60):
    """
    Update an existing event on Google Calendar.
    
    Args:
        credentials: Google OAuth credentials
        event_id: ID of the event to update
        title: New event title (optional)
        start_datetime: New start time (optional)
        description: New description (optional)
        duration_minutes: Event duration in minutes
    
    Returns:
        True on success, False on failure
    """
    try:
        service = get_calendar_service(credentials)
        
        # Get existing event
        event = service.events().get(calendarId='primary', eventId=event_id).execute()
        
        if title:
            event['summary'] = title
        
        if start_datetime:
            if isinstance(start_datetime, str):
                start = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
            else:
                start = start_datetime
            
            end = start + timedelta(minutes=duration_minutes)
            
            event['start'] = {
                'dateTime': start.isoformat(),
                'timeZone': 'UTC',
            }
            event['end'] = {
                'dateTime': end.isoformat(),
                'timeZone': 'UTC',
            }
        
        if description is not None:
            event['description'] = description
        
        service.events().update(calendarId='primary', eventId=event_id, body=event).execute()
        return True
    
    except HttpError as error:
        print(f"Error updating calendar event: {error}")
        return False
    except Exception as error:
        print(f"Unexpected error updating calendar event: {error}")
        return False


def delete_calendar_event(credentials, event_id):
    """
    Delete an event from Google Calendar.
    
    Args:
        credentials: Google OAuth credentials
        event_id: ID of the event to delete
    
    Returns:
        True on success, False on failure
    """
    try:
        service = get_calendar_service(credentials)
        service.events().delete(calendarId='primary', eventId=event_id).execute()
        return True
    
    except HttpError as error:
        # 404 means event already deleted, which is fine
        if error.resp.status == 404:
            return True
        print(f"Error deleting calendar event: {error}")
        return False
    except Exception as error:
        print(f"Unexpected error deleting calendar event: {error}")
        return False


def revoke_credentials(credentials):
    """
    Revoke Google OAuth credentials.
    
    Args:
        credentials: Google OAuth credentials to revoke
    
    Returns:
        True on success, False on failure
    """
    try:
        import requests
        requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': credentials.token},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )
        return True
    except Exception as error:
        print(f"Error revoking credentials: {error}")
        return False


def is_configured():
    """Check if Google Calendar integration is configured."""
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

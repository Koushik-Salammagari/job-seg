"""This module provides example tools for web scraping and search functionality.

It includes a basic Tavily search function (as an example)

These tools are intended as free examples to get started. For production use,
consider implementing more robust and specialized tools tailored to your needs.
"""

from typing import Any, Callable, List, Optional, cast

from langchain_community.tools.tavily_search import TavilySearchResults
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import InjectedToolArg
from typing_extensions import Annotated

# Tool to call GMAIL and get the latest email
import os.path
import base64
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from react_agent.configuration import Configuration

# Google Sheets API imports
import os
import pickle
import google.auth
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# If modifying these SCOPES, delete the file token.pickle or token.json
SCOPES_SHEETS = ['https://www.googleapis.com/auth/spreadsheets']

# Instructions: Delete the existing 'token.json' file located in 'src/react_agent/' and rerun the code. This will trigger the authentication flow to generate a new token with the updated scopes.

# Your spreadsheet ID (from the URL of the Google Sheet)
SPREADSHEET_ID = '1gNaA3Wm-IuApYaUprwjLQ5OQFXa4e0xqDZwDBxyQb5w'
RANGE_NAME = 'Sheet1!A1'  # Example: writing to cell A1

async def search(
    query: str, *, config: Annotated[RunnableConfig, InjectedToolArg]
) -> Optional[list[dict[str, Any]]]:
    """
    Performs a web search using the Tavily search engine.

    Args:
        query (str): The search query string.
        config (RunnableConfig): Configuration for the search.

    Returns:
        Optional[list[dict[str, Any]]]: A list of search results.
    """
    configuration = Configuration.from_runnable_config(config)
    wrapped = TavilySearchResults(max_results=configuration.max_search_results)
    result = await wrapped.ainvoke({"query": query})
    return cast(list[dict[str, Any]], result)



# Scope: read-only access to Gmail
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_gmail_service():
    """
    Authenticates and returns a Gmail API service instance.

    This function ensures that the user is authenticated and retrieves
    the necessary credentials to interact with Gmail.

    Returns:
        googleapiclient.discovery.Resource: The authenticated Gmail API service.
    """
    logger.debug("Initializing Gmail service.")
    creds = None
    token_path = 'src/react_agent/token_gmail.json'
    credentials_path = 'src/react_agent/credentials.json'

    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            try:
                creds = flow.run_local_server(port=0)
            except Exception:
                print("Could not locate a runnable browser. Please authenticate manually.")
                auth_url, _ = flow.authorization_url(prompt='consent')
                print(f"Please visit this URL to authorize the application: {auth_url}")
                try:
                    code = input("Enter the authorization code: ")
                    creds = flow.fetch_token(code=code)
                except EOFError:
                    raise Exception("Unable to read input. Ensure the program is running in an interactive environment or provide the authorization code programmatically.")
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
    logger.debug("Gmail service initialized successfully.")
    return build('gmail', 'v1', credentials=creds)

def extract_body(msg_data):
    if not msg_data or "payload" not in msg_data:
        print("⚠️ No payload found in the message data.")
        return None

    print(f"🔍 Processing message with payload mimeType: {msg_data['payload'].get('mimeType', 'Unknown')}")

    if msg_data["payload"]["mimeType"] == "text/plain":
        try:
            body = base64.b64decode(msg_data["payload"]["body"]["data"]).decode("utf-8")
            print("✅ Extracted plain text body.")
            return body
        except Exception as e:
            print(f"❌ Error decoding plain text body: {e}")
            return None
    elif msg_data["payload"]["mimeType"] == "text/html":
        try:
            body = base64.b64decode(msg_data["payload"]["body"]["data"]).decode("utf-8")
            print("✅ Extracted HTML body.")
            return body
        except Exception as e:
            print(f"❌ Error decoding HTML body: {e}")
            return None
    elif msg_data["payload"]["mimeType"] in ["multipart/mixed", "multipart/alternative"]:
        print(f"📦 Processing {msg_data['payload']['mimeType']} payload.")
        parts = msg_data["payload"].get("parts", [])
        # Prefer text/plain, fallback to text/html
        plain_text = None
        html_text = None

        for part in parts:
            part_mime = part.get("mimeType")
            data = part.get("body", {}).get("data")
            if data:
                decoded = base64.urlsafe_b64decode(data).decode("utf-8")
                if part_mime == "text/plain" and not plain_text:
                    plain_text = decoded
                elif part_mime == "text/html" and not html_text:
                    html_text = decoded

        if plain_text or html_text:
            print(f"✅ Extracted body from {msg_data['payload']['mimeType']} payload.")
        else:
            print(f"⚠️ No suitable part found in {msg_data['payload']['mimeType']} payload.")
        return plain_text or html_text
    else:
        print(f"⚠️ Unsupported mimeType: {msg_data['payload']['mimeType']}")

    return None



def read_emails():
    """
    Reads the latest email from the user's Gmail account.

    This function retrieves the latest email message using the Gmail API
    and returns its body content.

    Returns:
        str: The body of the latest email message.
    """
    logger.debug("Starting to read emails.")
    try:
        service = get_gmail_service()
        results = service.users().messages().list(userId='me', maxResults=5).execute()
        messages = results.get('messages', [])

        if not messages:
            logger.warning("No messages found.")
            return []
        
        bodies = []
        
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            body = extract_body(msg_data)
            if body:
                bodies.append(body)

        logger.debug("Successfully read emails: %s", bodies)
        return bodies

    except EOFError:
        raise Exception("An unexpected error occurred: Unable to read input. Ensure the program is running in an interactive environment.")
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Error: {e}. Ensure 'token.json' and 'credentials.json' are present in the correct directory.")
    except Exception as e:
        logger.error("Error reading emails: %s", e)
        raise Exception(f"An unexpected error occurred: {e}")

def get_sheets_service():
    """
    Authenticates and returns a Google Sheets API service instance.

    This function ensures that the user is authenticated and retrieves
    the necessary credentials to interact with Google Sheets.

    Returns:
        googleapiclient.discovery.Resource: The authenticated Sheets API service.
    """
    creds = None
    token_path = 'src/react_agent/token.json'
    credentials_path = 'src/react_agent/credentials.json'

    if os.path.exists(token_path):
        creds = google.oauth2.credentials.Credentials.from_authorized_user_file(token_path, SCOPES_SHEETS)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES_SHEETS)
            try:
                creds = flow.run_local_server(port=0)
            except Exception:
                print("Could not locate a runnable browser. Please authenticate manually.")
                auth_url, _ = flow.authorization_url(prompt='consent')
                print(f"Please visit this URL to authorize the application: {auth_url}")
                code = input("Enter the authorization code: ")
                creds = flow.fetch_token(code=code)
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
    return build('sheets', 'v4', credentials=creds)

def add_data_to_sheet(values: list):
    """
    Adds data to a specified Google Sheet.

    This function writes the provided data to the specified range in the
    Google Sheet identified by SPREADSHEET_ID and RANGE_NAME.

    Args:
        values (list): A list of lists containing the data to be written to the sheet.

    Returns:
        None
    """
    logger.debug("Adding data to Google Sheet: %s", values)
    # Ensure the function signature matches the docstring
    service = get_sheets_service()
    body = {
        'values': values
    }
    result = service.spreadsheets().values().append(
        spreadsheetId=SPREADSHEET_ID,
        range=RANGE_NAME,
        valueInputOption='RAW',
        insertDataOption='INSERT_ROWS',
        body=body
    ).execute()
    logger.debug("Data added to Google Sheet successfully.")
    print(f"{result.get('updates', {}).get('updatedCells', 0)} cells updated.")

# Example usage


TOOLS: List[Callable[..., Any]] = [search, read_emails, add_data_to_sheet]




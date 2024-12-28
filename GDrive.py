from typing import Optional
from pydrive.auth import AuthenticationError, AuthenticationRejected, GoogleAuth, InvalidCredentialsError, RefreshError
from pydrive.drive import GoogleDrive, GoogleDriveFile
from pydrive.files import ApiRequestError
from pydrive.settings import InvalidConfigError
import requests
import json
from pathlib import Path
import argparse

def is_authenticated(gauth: GoogleAuth) -> bool:
    """Check if the user is authenticated with Google
        Args:
            gauth(GoogleAuth): GoogleAuth object

        Returns:
            bool: True if the user is authenticated, False otherwise
    """
    return gauth.credentials is not None and not gauth.access_token_expired

def create_shareable_link(gauth: GoogleAuth, file: GoogleDriveFile) -> str:
    """Create a shareable link for a given file
        Args:
            gauth(GoogleAuth): GoogleAuth object
            file(GoogleDriveFile): GoogleDriveFile object

        Returns:
            link(str): Shareable link for the file

    """
    if not is_authenticated(gauth):
        print("Failed to create a shareable link. User is not authenticated")
        return ""

    access_token = gauth.credentials.access_token
    file_id = file['id']
    url = 'https://www.googleapis.com/drive/v3/files/' + file_id + '/permissions?supportsAllDrives=true'
    headers = {'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
    payload = {'type': 'anyone', 'value': 'anyone', 'role': 'reader'}
    try:
        _ = requests.post(url, data=json.dumps(payload), headers=headers)
    except requests.exceptions.RequestException as e:
        print(f"Failed to create shareable link: {e}")
        return ""
    link = file['alternateLink']
    return link

def authenticate_google(gauth: GoogleAuth) -> bool:
    """Authenticate with Google
    It prompts the user to authenticate with Google if the credentials are not
    found or expired.
    Once authenticated, it saves the credentials to a file.

        Args:
            gauth(GoogleAuth): GoogleAuth object
    """
    # Tell the user to obtain the client_secrets.json file
    if not Path("client_secrets.json").exists():
        print("""
            The required client_secrets.json file is missing in the current directory.
            You can obtain the file by following the instructions at:
            https://support.google.com/cloud/answer/6158849?hl=en
        """)
        return False

    # Try to load saved client credentials
    gauth.LoadCredentialsFile("mycreds.txt")

    if gauth.credentials is None:
        try:
            gauth.GetFlow()
            gauth.flow.params.update({'access_type': 'offline'})
            gauth.flow.params.update({'approval_prompt': 'force'})
        except InvalidConfigError as e:
            print(f"Failed to get flow: {e}")
            return False

        try:
            gauth.LocalWebserverAuth()
        except (AuthenticationRejected, AuthenticationError) as e:
            print(f"Failed to authenticate: {e}")
            return False

    elif gauth.access_token_expired:
        try:
            gauth.Refresh()
        except RefreshError as e:
            print(f"Failed to refresh token: {e}")
            return False
    else:
        try:
            gauth.Authorize()
        except AuthenticationError as e:
            print(f"Failed to authorize: {e}")
            return False

    # Save the current credentials to a file
    try:
        gauth.SaveCredentialsFile("mycreds.txt")
    except (InvalidConfigError, InvalidCredentialsError) as e:
        print(f"Failed to save credentials: {e}")
        return False

    return True

def upload_file_to_drive(drive: GoogleDrive, content: Path) -> Optional[GoogleDriveFile]:
    """Upload a file to Google Drive
        Args:
            drive(GoogleDrive): GoogleDrive object
            content(Path): Path object of the file to upload

        Returns:
            file(Optional[GoogleDriveFile]): GoogleDriveFile object of the uploaded file
            or None if the file was not uploaded successfully
    """
    if not is_authenticated(drive.auth):
        print("Failed to upload file. User is not authenticated")
        return None

    if not content.exists():
        print(f"File {content} does not exist")
        return None

    file = drive.CreateFile({'title': content.name})
    if not file.uploaded:
        print(f"Failed to create file: {file}")
        return None

    file.SetContentFile(content)

    try:
        file.Upload()
    except ApiRequestError as e:
        print(f"Failed to upload file: {e}")
        return None

    return file

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Upload file to Google Drive')
    parser.add_argument('-f', '--file', type=Path, required=True, help='File to upload')
    return parser.parse_args()

def main():
    gauth = GoogleAuth()
    drive = GoogleDrive(gauth)
    args = parse_args()

    if not authenticate_google(gauth):
        print("Failed to authenticate with Google")
        return

    file = upload_file_to_drive(drive, args.file)
    if file is None:
        print(f"Failed to upload {args.file.name}")
        return

    link = create_shareable_link(gauth, file)
    if link == "":
        print(f"Failed to create shareable link for {args.file.name}")
        return

    print(f"[+] Successfully uploaded {args.file.name} to {link}")

if __name__ == '__main__':
    main()

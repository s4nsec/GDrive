import os
from typing import Optional
from pydrive2.auth import AuthenticationError, AuthenticationRejected, GoogleAuth, InvalidCredentialsError, RefreshError
from pydrive2.drive import GoogleDrive, GoogleDriveFile
from pydrive2.files import ApiRequestError
from pydrive2.settings import InvalidConfigError
import requests
import json
from pathlib import Path
import argparse

DEFAULT_OAUTH_SCOPE = "https://www.googleapis.com/auth/drive.file"
DEFAULT_CREDENTIALS_FILE = Path.home() / ".config" / "gdrive" / "credentials.json"
LEGACY_CREDENTIALS_FILE = Path("mycreds.txt")


def resolve_client_secrets_path(cli_path: Path | None) -> Path | None:
    if cli_path:
        return cli_path.expanduser()

    env_path = os.getenv("GDRIVE_CLIENT_SECRETS")
    if env_path:
        return Path(env_path).expanduser()

    return None


def resolve_credentials_path(cli_path: Path | None) -> Path:
    if cli_path:
        return cli_path.expanduser()

    env_path = os.getenv("GDRIVE_CREDENTIALS_FILE")
    if env_path:
        return Path(env_path).expanduser()

    return DEFAULT_CREDENTIALS_FILE


def ensure_secure_credentials_path(credentials_path: Path) -> bool:
    try:
        credentials_path.parent.mkdir(parents=True, exist_ok=True)
        credentials_path.parent.chmod(0o700)
    except OSError as e:
        print(f"Failed to prepare credentials directory: {e}")
        return False

    if not credentials_path.exists():
        return True

    try:
        credentials_path.chmod(0o600)
    except OSError as e:
        print(f"Failed to secure credentials file permissions: {e}")
        return False

    return True


def load_stored_credentials(gauth: GoogleAuth, credentials_path: Path) -> None:
    if credentials_path.exists():
        gauth.LoadCredentialsFile(str(credentials_path))
        return

    if LEGACY_CREDENTIALS_FILE.exists():
        print("Using legacy credentials from mycreds.txt. They will be migrated to the secure credentials path.")
        gauth.LoadCredentialsFile(str(LEGACY_CREDENTIALS_FILE))


def is_authenticated(gauth: GoogleAuth | None) -> bool:
    """Check if the user is authenticated with Google
        Args:
            gauth(GoogleAuth): GoogleAuth object

        Returns:
            bool: True if the user is authenticated, False otherwise
    """
    if not gauth:
        return False

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
        response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=15)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to create shareable link: {e}")
        return ""

    if 'alternateLink' not in file:
        print("Failed to create shareable link: missing alternate link in upload response")
        return ""

    link = file['alternateLink']
    return link

def authenticate_google(gauth: GoogleAuth, client_secrets_path: Path, credentials_path: Path) -> bool:
    """Authenticate with Google
    It prompts the user to authenticate with Google if the credentials are not
    found or expired.
    Once authenticated, it saves the credentials to a file.

        Args:
            gauth(GoogleAuth): GoogleAuth object
    """
    # Tell the user to obtain the client_secrets.json file
    if not client_secrets_path.exists():
        print("""
            The required client secrets file is missing.
            You can obtain the file by following the instructions at:
            https://support.google.com/cloud/answer/6158849?hl=en
        """)
        return False

    gauth.settings["client_config_file"] = str(client_secrets_path)
    gauth.settings["oauth_scope"] = [DEFAULT_OAUTH_SCOPE]

    # Try to load saved client credentials
    load_stored_credentials(gauth, credentials_path)

    if gauth.credentials is None:
        try:
            gauth.GetFlow()
            gauth.flow.params.update({'access_type': 'offline'})
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
        gauth.SaveCredentialsFile(str(credentials_path))
        credentials_path.chmod(0o600)
    except (InvalidConfigError, InvalidCredentialsError) as e:
        print(f"Failed to save credentials: {e}")
        return False
    except OSError as e:
        print(f"Failed to secure credentials file permissions: {e}")
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
    parser.add_argument(
        '--client-secrets',
        type=Path,
        default=None,
        help='Path to OAuth client secrets JSON file (or set GDRIVE_CLIENT_SECRETS)',
    )
    parser.add_argument(
        '--credentials-file',
        type=Path,
        default=None,
        help='Path to saved OAuth credentials (or set GDRIVE_CREDENTIALS_FILE)',
    )
    parser.add_argument(
        '--public-link',
        action='store_true',
        help='Create a public shareable link. Default behavior keeps uploaded files private.',
    )
    return parser.parse_args()

def main():
    args = parse_args()

    client_secrets_path = resolve_client_secrets_path(args.client_secrets)
    if not client_secrets_path:
        print("Missing client secrets path. Use --client-secrets or set GDRIVE_CLIENT_SECRETS.")
        return

    credentials_path = resolve_credentials_path(args.credentials_file)
    if not ensure_secure_credentials_path(credentials_path):
        return

    gauth = GoogleAuth()
    drive = GoogleDrive(gauth)

    if not authenticate_google(gauth, client_secrets_path, credentials_path):
        print("Failed to authenticate with Google")
        return

    file = upload_file_to_drive(drive, args.file)
    if file is None:
        print(f"Failed to upload {args.file.name}")
        return

    if not args.public_link:
        print(f"[+] Successfully uploaded {args.file.name}. File remains private by default.")
        return

    print("[!] Public link requested. Applying 'anyone with link can read' permission.")
    link = create_shareable_link(gauth, file)
    if link == "":
        print(f"Failed to create shareable link for {args.file.name}")
        return

    print(f"[+] Successfully uploaded {args.file.name} to {link}")

if __name__ == '__main__':
    main()

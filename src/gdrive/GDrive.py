import os
import click
from pydrive2.auth import (
    AuthenticationError,
    AuthenticationRejected,
    GoogleAuth,
    InvalidCredentialsError,
    RefreshError,
)
from pydrive2.drive import GoogleDrive, GoogleDriveFile
from pydrive2.files import ApiRequestError
from pydrive2.settings import InvalidConfigError
import requests
import json
from pathlib import Path

DEFAULT_OAUTH_SCOPE = "https://www.googleapis.com/auth/drive.file"
DEFAULT_CREDENTIALS_FILE = Path.home() / ".config" / "gdrive" / "credentials.json"


def resolve_client_secrets_path() -> Path | None:
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
        click.echo(f"Failed to prepare credentials directory: {e}", err=True)
        return False

    if not credentials_path.exists():
        return True

    try:
        credentials_path.chmod(0o600)
    except OSError as e:
        click.echo(f"Failed to secure credentials file permissions: {e}", err=True)
        return False

    return True


def load_stored_credentials(gauth: GoogleAuth, credentials_path: Path) -> None:
    if credentials_path.exists():
        gauth.LoadCredentialsFile(str(credentials_path))
        return


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
        click.echo(
            "Failed to create a shareable link. User is not authenticated", err=True
        )
        return ""

    access_token = gauth.credentials.access_token
    file_id = file["id"]
    url = (
        "https://www.googleapis.com/drive/v3/files/"
        + file_id
        + "/permissions?supportsAllDrives=true"
    )
    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json",
    }
    payload = {"type": "anyone", "value": "anyone", "role": "reader"}
    try:
        response = requests.post(
            url, data=json.dumps(payload), headers=headers, timeout=15
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        click.echo(f"Failed to create shareable link: {e}", err=True)
        return ""

    if "alternateLink" not in file:
        click.echo(
            "Failed to create shareable link: missing alternate link in upload response",
            err=True,
        )
        return ""

    link = file["alternateLink"]
    return link


def authenticate_google(
    gauth: GoogleAuth, client_secrets_path: Path, credentials_path: Path
) -> bool:
    """Authenticate with Google
    It prompts the user to authenticate with Google if the credentials are not
    found or expired.
    Once authenticated, it saves the credentials to a file.

        Args:
            gauth(GoogleAuth): GoogleAuth object
    """
    if not client_secrets_path.exists():
        click.echo(
            """
            The required client secrets file is missing.
            You can obtain the file by following the instructions at:
            https://support.google.com/cloud/answer/6158849?hl=en
        """,
            err=True,
        )
        return False

    gauth.settings["client_config_file"] = str(client_secrets_path)
    gauth.settings["oauth_scope"] = [DEFAULT_OAUTH_SCOPE]

    load_stored_credentials(gauth, credentials_path)

    if gauth.credentials is None:
        try:
            gauth.GetFlow()
            gauth.flow.params.update({"access_type": "offline"})
        except InvalidConfigError as e:
            click.echo(f"Failed to get flow: {e}", err=True)
            return False

        try:
            gauth.LocalWebserverAuth()
        except (AuthenticationRejected, AuthenticationError) as e:
            click.echo(f"Failed to authenticate: {e}", err=True)
            return False

    elif gauth.access_token_expired:
        try:
            gauth.Refresh()
        except RefreshError as e:
            click.echo(f"Failed to refresh token: {e}", err=True)
            return False
    else:
        try:
            gauth.Authorize()
        except AuthenticationError as e:
            click.echo(f"Failed to authorize: {e}", err=True)
            return False

    try:
        gauth.SaveCredentialsFile(str(credentials_path))
        credentials_path.chmod(0o600)
    except (InvalidConfigError, InvalidCredentialsError) as e:
        click.echo(f"Failed to save credentials: {e}", err=True)
        return False
    except OSError as e:
        click.echo(f"Failed to secure credentials file permissions: {e}", err=True)
        return False

    return True


def upload_file_to_drive(drive: GoogleDrive, content: Path) -> GoogleDriveFile | None:
    """Upload a file to Google Drive
    Args:
        drive(GoogleDrive): GoogleDrive object
        content(Path): Path object of the file to upload

    Returns:
        file(Optional[GoogleDriveFile]): GoogleDriveFile object of the uploaded file
        or None if the file was not uploaded successfully
    """
    if not is_authenticated(drive.auth):
        click.echo("Failed to upload file. User is not authenticated", err=True)
        return None

    if not content.exists():
        click.echo(f"File {content} does not exist", err=True)
        return None

    file = drive.CreateFile({"title": content.name})
    file.SetContentFile(content)

    try:
        file.Upload()
    except ApiRequestError as e:
        click.echo(f"Failed to upload file: {e}", err=True)
        return None

    return file


def download_file_from_drive(
    drive: GoogleDrive, file_id: str, output_path: Path | None
) -> Path | None:
    """Download a file from Google Drive by file ID.
    Args:
        drive(GoogleDrive): GoogleDrive object
        file_id(str): Google Drive file ID
        output_path(Path | None): Destination path

    Returns:
        Path | None: Downloaded file path or None on failure
    """
    if not is_authenticated(drive.auth):
        click.echo("Failed to download file. User is not authenticated", err=True)
        return None

    file = drive.CreateFile({"id": file_id})
    try:
        file.FetchMetadata(fields="title,originalFilename")
    except ApiRequestError as e:
        click.echo(f"Failed to fetch file metadata: {e}", err=True)
        return None

    destination = output_path
    if not destination:
        file_name = file.get("title") or file.get("originalFilename")
        if not file_name:
            click.echo(
                "Failed to determine output filename. Use --output to specify a path",
                err=True,
            )
            return None
        destination = Path(file_name)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        click.echo(f"Failed to prepare output directory: {e}", err=True)
        return None

    try:
        file.GetContentFile(str(destination))
    except ApiRequestError as e:
        click.echo(f"Failed to download file: {e}", err=True)
        return None
    except OSError as e:
        click.echo(f"Failed to write downloaded file: {e}", err=True)
        return None

    return destination


def initialize_drive(
    credentials_file: Path | None,
) -> tuple[GoogleAuth, GoogleDrive] | None:
    client_secrets_path = resolve_client_secrets_path()
    if not client_secrets_path:
        click.echo("Missing client secrets path. Set GDRIVE_CLIENT_SECRETS.", err=True)
        return None

    credentials_path = resolve_credentials_path(credentials_file)
    if not ensure_secure_credentials_path(credentials_path):
        return None

    gauth = GoogleAuth()
    drive = GoogleDrive(gauth)

    if not authenticate_google(gauth, client_secrets_path, credentials_path):
        click.echo("Failed to authenticate with Google", err=True)
        return None

    return gauth, drive


@click.group(help="Upload and download files with Google Drive")
@click.option(
    "--credentials-file",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Path to saved OAuth credentials (or set GDRIVE_CREDENTIALS_FILE)",
)
@click.pass_context
def main(ctx: click.Context, credentials_file: Path | None) -> None:
    ctx.ensure_object(dict)
    ctx.obj["credentials_file"] = credentials_file


@click.command(help="Upload a file to Google Drive")
@click.option(
    "-f",
    "--file",
    "file_path",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="File to upload",
)
@click.option(
    "--public-link",
    is_flag=True,
    help="Create a public shareable link. Default behavior keeps uploaded files private.",
)
@click.pass_context
def upload(ctx: click.Context, file_path: Path, public_link: bool) -> None:
    initialized = initialize_drive(ctx.obj["credentials_file"])
    if not initialized:
        return

    gauth, drive = initialized

    file = upload_file_to_drive(drive, file_path)
    if not file:
        click.echo(f"Failed to upload {file_path.name}", err=True)
        return

    if not public_link:
        click.echo(
            f"[+] Successfully uploaded {file_path.name}. File remains private by default."
        )
        return

    click.echo(
        "[!] Public link requested. Applying 'anyone with link can read' permission."
    )
    link = create_shareable_link(gauth, file)
    if not link:
        click.echo(f"Failed to create shareable link for {file_path.name}", err=True)
        return

    click.echo(f"[+] Successfully uploaded {file_path.name} to {link}")


@click.command(help="Download a file from Google Drive")
@click.option("--file-id", required=True, help="Google Drive file ID to download")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Destination path for the downloaded file. Defaults to the remote filename in the current directory.",
)
@click.pass_context
def download(ctx: click.Context, file_id: str, output: Path | None) -> None:
    initialized = initialize_drive(ctx.obj["credentials_file"])
    if initialized is None:
        return

    _, drive = initialized

    destination = download_file_from_drive(drive, file_id, output)
    if not destination:
        click.echo(f"Failed to download file with ID {file_id}", err=True)
        return

    click.echo(f"[+] Successfully downloaded file with ID {file_id} to {destination}")


main_cli = main
main_cli.add_command(upload)
main_cli.add_command(download)


if __name__ == "__main__":
    main()

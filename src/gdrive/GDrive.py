import os
from pathlib import Path

import click
from pydrive2.auth import (
    AuthenticationError,
    AuthenticationRejected,
    GoogleAuth,
    InvalidCredentialsError,
    RefreshError,
)
from pydrive2.drive import GoogleDrive
from pydrive2.settings import InvalidConfigError

from gdrive.downloadutils import download_file_from_drive
from gdrive.uploadutils import create_shareable_link, upload_file_to_drive

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

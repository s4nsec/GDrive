from pathlib import Path

import click
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from pydrive2.files import ApiRequestError


def is_authenticated(gauth: GoogleAuth | None) -> bool:
    if not gauth:
        return False

    return gauth.credentials is not None and not gauth.access_token_expired


def download_file_from_drive(
    drive: GoogleDrive, file_id: str, output_path: Path | None
) -> Path | None:
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

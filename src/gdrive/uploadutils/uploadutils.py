import json
from pathlib import Path

import click
import requests
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive, GoogleDriveFile
from pydrive2.files import ApiRequestError


def is_authenticated(gauth: GoogleAuth | None) -> bool:
    if not gauth:
        return False

    return gauth.credentials is not None and not gauth.access_token_expired


def create_shareable_link(gauth: GoogleAuth, file: GoogleDriveFile) -> str:
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

    return file["alternateLink"]


def upload_file_to_drive(drive: GoogleDrive, content: Path) -> GoogleDriveFile | None:
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

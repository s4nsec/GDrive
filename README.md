# GDrive

Simple CLI for uploading files to Google Drive.

## Google OAuth Setup (Required)

1. In Google Cloud Console, enable the Google Drive API for your project.
2. Configure the OAuth consent screen.
3. Add your Google account email under **Test users**.
4. Create an OAuth 2.0 Client ID with application type **Desktop app** and download the JSON file.

## Authentication

- Set `GDRIVE_CLIENT_SECRETS` to your OAuth client secrets JSON path.
- Credentials are saved by default at `~/.config/gdrive/credentials.json`.
  Override with `--credentials-file` or `GDRIVE_CREDENTIALS_FILE`.

```bash
export GDRIVE_CLIENT_SECRETS=/path/to/client_secrets.json
```

## Installation

Install the CLI as a tool:

```bash
uv tool install .
```

Upgrade the installed tool after pulling changes:

```bash
uv tool upgrade gdrive
```

Run the tool directly:

```bash
gdrive --help
```

Notes:

- OAuth client secrets path is provided at runtime via `GDRIVE_CLIENT_SECRETS`.

## Usage

### Upload

```bash
gdrive upload --file /path/to/local/file
```

Files are private by default. To explicitly create a public link:

```bash
gdrive upload --file /path/to/local/file --public-link
```

### Download

Download by file ID only:

```bash
gdrive download --file-id 1AbCdEfGhIjKlMnOpQrStUvWxYz
```

Specify a destination path with `--output`:

```bash
gdrive download --file-id 1AbCdEfGhIjKlMnOpQrStUvWxYz --output /path/to/save/file
```

## Troubleshooting

- `Access blocked: project has not completed the Google verification process`:
  add your email as a test user in the OAuth consent screen.
- `Invalid client secrets file Missing property "redirect_uris" in a client type of "web"`:
  use a **Desktop app** OAuth client JSON, not a Web client JSON.

More details: https://stackoverflow.com/questions/75454425/access-blocked-project-has-not-completed-the-google-verification-process

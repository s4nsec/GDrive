# GDrive

Simple CLI for uploading files to Google Drive.

## Google OAuth Setup (Required)

1. In Google Cloud Console, enable the Google Drive API for your project.
2. Configure the OAuth consent screen.
3. Add your Google account email under **Test users**.
4. Create an OAuth 2.0 Client ID with application type **Desktop app** and download the JSON file.

## Authentication

- Provide OAuth client secrets with `--client-secrets /path/to/client_secrets.json`
  or set `GDRIVE_CLIENT_SECRETS`.
- Credentials are saved by default at `~/.config/gdrive/credentials.json`.
  Override with `--credentials-file` or `GDRIVE_CREDENTIALS_FILE`.

## Usage

```bash
gdrive --file /path/to/local/file --client-secrets /path/to/client_secrets.json
```

```bash
uv run gdrive --file /path/to/local/file --client-secrets /path/to/client_secrets.json
```

Files are private by default. To explicitly create a public link:

```bash
gdrive --file /path/to/local/file --client-secrets /path/to/client_secrets.json --public-link
```

## Troubleshooting

- `Access blocked: project has not completed the Google verification process`:
  add your email as a test user in the OAuth consent screen.
- `Invalid client secrets file Missing property "redirect_uris" in a client type of "web"`:
  use a **Desktop app** OAuth client JSON, not a Web client JSON.

More details: https://stackoverflow.com/questions/75454425/access-blocked-project-has-not-completed-the-google-verification-process

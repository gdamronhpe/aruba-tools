# ClearPass Certificate Manager (Web)

This tool provides a lightweight web UI for viewing and replacing ClearPass certificates across cluster members, plus importing CA/intermediate certificates from a PKCS#12 file.

## Requirements

- Python 3.8+ (recommended)
- Network access from your machine to the ClearPass API and from ClearPass back to this host (for PKCS#12 download)

Python packages:

- `flask`
- `requests`
- `python-dateutil`
- `cryptography`

Install deps:

```bash
python -m pip install flask requests python-dateutil cryptography
```

## Run

```bash
python clearpass/cert_manager/CPPM_CertMgr_Web.py
```

The app binds to `0.0.0.0:5000` and will open a browser to a LAN-accessible URL.

## ClearPass API Client Setup

You need an API token for a ClearPass user or API client with permissions to:

- Read cluster servers
- Read server certificates
- Replace server certificates
- Add CA/intermediate certificates to the trust list

Typical setup flow in ClearPass Policy Manager:

1. Create an API client (or a service account) in the ClearPass admin UI.
2. Grant it the API roles/permissions needed for the certificate endpoints above.
3. Generate an access token (or client credentials token).
4. Paste the token into the UI's **Token** field when connecting.

Notes:

- This UI uses the token you provide and calls ClearPass endpoints such as:
  - `GET /api/cluster/server`
  - `GET /api/server-cert/name/{server_uuid}/{service_name}`
  - `PUT /api/server-cert/name/{server_uuid}/{service_name}`
  - `POST /api/cert-trust-list`
- If you use client ID/secret instead of a static token, ensure the client can obtain tokens from `POST /api/oauth`.

If you're unsure where to create API clients or which roles to assign, follow your organization’s ClearPass API documentation and security guidelines.

## Operational Notes

- ClearPass must be able to reach the PKCS#12 file URL hosted by this tool.
- If ClearPass cannot reach your machine, place the PKCS#12 file on a reachable HTTP server and paste that URL into the UI.
- This is intended for development/ops use; run behind a proper WSGI server for production usage.

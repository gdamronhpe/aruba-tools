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

## Windows EXE (Single File)

Use PyInstaller to create a single-file executable:

```powershell
.\clearpass\cert_manager\build_exe.ps1
```

Output will be:

```
clearpass\cert_manager\dist\CPPM_CertMgr_Web.exe
```

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

Some users already have an API client; others need to create both the Operator Profile and API client first.

### If you already have an API client with proper permissions

1. Open the existing API client in ClearPass.
2. Generate or copy the access token.
3. Paste the token into the UI's **Token** field.

     ![Get API Token](screenshots/generate-token.jpg)

### If you need to create the Operator Profile and API client

If you're unsure about creating API clients, follow your organization's security guidelines.

1. Create an Operator Profile for **Platform Certificate Manager**.

     ![Operator Profile - Platform Certificate Manager](screenshots/operator-profile-platform-certificate-manager.jpg)

2. Assign the required permissions.

     ![Operator Profile Permissions - API Services](screenshots/permissions-api-services.jpg)

     ![Operator Profile Permissions - Platform](screenshots/permissions-platform.jpg)

     ![Operator Profile Permissions - Policy Manager](screenshots/permissions-policy-manager.jpg)

3. Create a new API client and associate it with that operator profile.

     ![Create API Client](screenshots/create-api-client.jpg)

     ![Create API Client](screenshots/create-api-client-secret.jpg)

4. Generate the access token.

     ![Get API Token](screenshots/generate-token.jpg)

5. Paste the token into the UI's **Token** field.

## Token Privileges Check

On connect, the UI verifies the token has the required privileges by calling:

```
GET /api/oauth/privileges
```

The token must include these privileges:

```
#admin_restore
%cppm_cert_trust_list
%cppm_certificates
?api_index
?cppm_config
?platform
apigility
```

If any are missing, the connection will fail and the UI will list the missing items.

## Operational Notes

- Step 2 in the UI is **Upload & Host**.
- Step 3 is **Trust List** (import CA/intermediates).
- Step 4 is **Replace** (apply the hosted PKCS#12 to selected services).
- ClearPass must be able to reach the PKCS#12 file URL hosted by this tool.
- If ClearPass cannot reach your machine, place the PKCS#12 file on a reachable HTTP server and paste that URL into the UI.
- This is intended for development/ops use; run behind a proper WSGI server for production usage.

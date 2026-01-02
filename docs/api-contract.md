# API Contract (Crisp)

Base URL: `/fido2`

Common headers:
- `Content-Type: application/json`
- `rp_id` (optional): overrides the default RP ID

## Registration
### POST /registration/options
Request (web):
```json
{
  "username": "jane.doe",
  "displayName": "Jane Doe",
  "attestation": "none",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "preferred",
    "userVerification": "preferred",
    "requireResidentKey": false
  },
  "extensions": {"credProps": true}
}
```

Response:
```json
{
  "status": "ok",
  "errorMessage": "",
  "rp": {"id": "example.com", "name": "RP Server", "origin": "https://example.com"},
  "user": {"id": "...base64url...", "name": "jane.doe", "displayName": "Jane Doe"},
  "challenge": "...base64url...",
  "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
  "timeout": 60000,
  "attestation": "none",
  "excludeCredentials": [],
  "extensions": {"credProps": true}
}
```

### POST /registration/result
Request (web):
```json
{
  "id": "credential-id",
  "rawId": "...base64url...",
  "type": "public-key",
  "response": {
    "attestationObject": "...base64url...",
    "clientDataJSON": "...base64url...",
    "transports": ["internal"]
  }
}
```

Response:
```json
{
  "status": "ok",
  "errorMessage": ""
}
```

## Authentication
### POST /authentication/options
Request (web):
```json
{
  "userVerification": "preferred"
}
```

Response:
```json
{
  "status": "ok",
  "errorMessage": "",
  "rpId": "example.com",
  "challenge": "...base64url...",
  "timeout": 60000,
  "userVerification": "preferred",
  "allowCredentials": [
    {"id": "...base64url...", "type": "public-key"}
  ],
  "registeredPasskeys": [
    {"username": "jane.doe", "credentialId": "...base64url..."}
  ]
}
```

### POST /authentication
Request (web):
```json
{
  "id": "credential-id",
  "type": "public-key",
  "response": {
    "authenticatorData": "...base64url...",
    "clientDataJSON": "...base64...",
    "signature": "...base64url...",
    "userHandle": "...base64url..."
  },
  "serverPublicKeyCredential": {
    "extensions": {}
  }
}
```

Response:
```json
{
  "status": "ok",
  "errorMessage": ""
}
```

## UI
### GET /ui
Returns the static passkey test UI.

## Example requests for mobile
### Registration (mobile)
```json
{
  "username": "jane.doe",
  "displayName": "Jane Doe",
  "attestation": "none",
  "authenticatorSelection": {
    "residentKey": "required",
    "userVerification": "required"
  },
  "extensions": {"credProps": true}
}
```

### Authentication (mobile)
```json
{
  "userVerification": "required"
}
```

## Common error cases
- `User not found` during authentication options (if username is supplied and unknown).
- `Invalid Challenge` when the ceremony state is missing/expired.
- `Failed to parse authentication data` or `Failed to validate authentication data` for malformed assertions.
- `Registration request must have an ID` for invalid registration payloads.

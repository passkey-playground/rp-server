# Registration Ceremony (Attestation)

Goal: bind a new passkey to a user and store the credential + metadata server-side.

## Sequence (options -> client -> attestation -> verify -> persist)
1. Options request
   - Client calls `POST /fido2/registration/options` with `username`, `displayName`, and selection preferences.
   - Server creates/loads the user, builds RP config, and generates a challenge.
   - Server stores state: `challenge`, `user`, `rp`, and ceremony settings (Redis).
2. Client create()
   - Browser calls `navigator.credentials.create({ publicKey })` with options.
   - Authenticator produces a new credential (attestation object + client data).
3. Attestation submission
   - Client POSTs attestation payload to `POST /fido2/registration/result`.
4. Verification
   - Server parses attestation, looks up state via challenge, and verifies:
     - Origin + RP ID match
     - Challenge matches
     - User presence/verification requirements
5. Persist
   - Server persists user and credential record.
   - Credential metadata stored: `credentialId`, `rpId`, transports, authenticator data, attestation statement, and client data.

## Minimal success criteria
- Challenge roundtrip matches
- Origin and RP ID are correct
- Attestation verifies with WebAuthn4J
- Credential is persisted and linked to RP + user

## Common failure points
- Missing or mismatched RP ID / origin
- Challenge not found in Redis
- Credential ID not base64url
- User not found or displayName missing

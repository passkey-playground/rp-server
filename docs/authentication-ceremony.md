# Authentication Ceremony (Assertion)

Goal: prove possession of an existing passkey and validate the assertion.

## Sequence (options -> client -> assertion -> verify -> session)
1. Options request
   - Client calls `POST /fido2/authentication/options`.
   - The RP ID is used to discover eligible credentials (no username required).
   - Server generates a challenge and stores ceremony state (Redis).
2. Client get()
   - Browser calls `navigator.credentials.get({ publicKey })`.
   - Without `allowCredentials`, the browser prompts the user to pick a passkey.
3. Assertion submission
   - Client POSTs assertion payload to `POST /fido2/authentication`.
4. Verification
   - Server parses assertion, looks up challenge, and validates:
     - Origin + RP ID
     - Challenge
     - Signature + authenticator data
5. Session
   - On success, server can issue a session/token (future extension).

## Minimal success criteria
- Challenge roundtrip matches
- Origin and RP ID are correct
- Assertion verifies for stored credential

## Common failure points
- Challenge not found in Redis
- Credential not found for RP
- Signature mismatch (stale or wrong credential)
- User verification policy mismatch

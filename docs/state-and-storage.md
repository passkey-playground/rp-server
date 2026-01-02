# Where State Lives

This server keeps short-lived ceremony state in Redis and long-lived credential/user records in Postgres.

## Redis (ceremony state)
Stored for the duration of a ceremony (challenge key):
- `challenge` (primary lookup key)
- `rp` (origin, rpId)
- `user` (id, username, displayName)
- `authenticatorSelection`
- `timeout`

Where it is used:
- Registration verification uses the challenge to load `SessionBO`.
- Authentication verification uses the challenge to load `SessionBO`.

## Postgres (long-lived)
### Users
- `USER` table stores: user id, username, displayName.

### Credentials
- `CREDENTIALS2` stores:
  - `external_id_raw` (base64url credentialId)
  - `username` and `user_id`
  - `rp_id` (internal RP id)
  - `authenticator_data`, `attestation_statement`, `collected_client_data`, `transports`

### Relying Parties
- `RELYING_PARTIES` stores RP metadata: rpId, origin, name.

## Mapping notes
- `userHandle` (from assertions) should map to a user in the DB.
- `signCount` is not yet tracked; add it when you need replay protection.
- `transports` are stored as serialized data from the authenticator.

## Cleanup strategy
- Redis entries are ephemeral; set a TTL if you need strict cleanup.
- Credentials are long-lived; implement revocation or deletion if needed.

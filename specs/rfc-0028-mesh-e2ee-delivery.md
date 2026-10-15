# RFC-0028: Mesh E2EE Delivery and Replay Protection

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `server.py` mesh envelope, `providers/mesh_security.py` |
| Related | RFC-0019, RFC-0021, RFF-0002 |
| Version Target | v7.0.0 |

## Abstract

Specify and test the classical E2EE envelope used by mesh messaging, including address-bound key derivation, ephemeral-key metadata, store-and-forward retry behavior, and replay rejection.

## Wire Format

Every encrypted message carries `e2ee`, `e2ee_version`, `from_addr`, `eph_pub`, `nonce`, `timestamp`, and authenticated ciphertext. Key derivation binds sender address, recipient address, protocol version, and message purpose. Receivers reject malformed or unauthenticated envelopes; the original ciphertext is never displayed as plaintext.

## Design

- ECDH P-256 ephemeral key per message with HKDF-SHA256 and AES-256-GCM.
- Verify decryption from the ephemeral public key; a static sender key is not a prerequisite when the envelope is valid.
- Persist only encrypted payloads in the delivery queue. Retry re-encrypts from process-protected pending plaintext only while the originating process is alive; restart behavior must be documented and fail closed.
- Monotonic sender nonces and bounded timestamp skew reject replays and stale messages. Duplicate and out-of-order delivery policy is explicit.
- `send-raw` is a distinct opt-in API/CLI action and is labelled unencrypted in response/history.

## API Changes

`POST /cpip/mesh/send` returns `e2ee: true` only after successful encryption; missing keys or failed encryption return a non-2xx response. `GET /cpip/mesh/inbox` includes `e2ee_decrypted` and a stable decryption-error reason.

## Acceptance Criteria

- Two independent node identities pass direct, queued, retry, restart, and decrypt round trips.
- Wrong key, altered ciphertext, invalid version, duplicate nonce, stale timestamp, and missing ephemeral key fail closed.
- Tests prove there is no plaintext fallback in the default send path.
- Legacy protocol behavior is explicitly version-gated; no implicit downgrade is accepted.

## Limitations

This RFC does not claim post-quantum mesh negotiation, post-quantum signatures, or a double ratchet. Those remain separate work under RFC-0019.

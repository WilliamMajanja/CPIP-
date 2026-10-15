# RFF-0002: Reliable Secure Messaging Across Mesh and Air-Gap Links

| Field | Value |
|-------|-------|
| Status | Proposed |
| Component | `server.py`, `providers/mesh.py`, `providers/airgap.py`, CLI/TUI/dashboard |
| Related | RFC-0028, RFC-0033 |
| Version Target | v7.0.0 |

## User need

Users need a message to remain encrypted and authenticated from send through store-and-forward delivery, or receive a clear failure. A queued retry must not change the wire format or silently fall back to plaintext. Air-gap transfers need framing and integrity checks so payloads can be reassembled safely.

## Desired outcome

- E2EE success/failure is explicit in API responses and message history.
- Retries refresh ephemeral encryption consistently; receivers can decrypt the documented envelope.
- Plaintext transmission is available only through an explicit raw-send option.
- QR transfers authenticate frames, detect missing/duplicate/reordered frames, and reject corrupted payloads.

## Acceptance criteria

1. Two-node round-trip tests cover direct delivery, queued delivery, retries, wrong keys, altered ciphertext, replay, and missing recipient keys.
2. The default send path never returns `sent` or `queued` if E2EE encryption failed.
3. Wire-format versions are negotiated or rejected; no implicit downgrade is allowed.
4. QR encode/decode tests cover one-frame and multi-frame files, truncation, reordering, and tampering.
5. An unavailable physical channel is reported unavailable rather than simulated as a completed send.

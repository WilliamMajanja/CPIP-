# RFC-0033: Framed QR Air-Gap Transfer

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/airgap.py`, `providers/rfc_api.py`, CLI/dashboard |
| Related | RFC-0015, RFC-0024, RFC-0028, RFF-0002 |
| Version Target | v7.0.0 |

## Abstract

Specify a real, dependency-optional QR file/message transfer mode for disconnected devices. QR encoding is a transport only; encryption and authentication come from the secure message envelope.

## Frame Format

Each frame carries protocol version, transfer ID, frame index/count, payload digest, and a bounded data fragment. Receivers reject conflicting frames, oversized transfers, invalid indices, expired transfers, and digest/authentication failures.

## Design

- QR image generation and camera decoding are separate capabilities with independent status.
- Multi-frame transfers have bounded total size, memory, frame count, and lifetime.
- API can return QR image bytes or a documented frame payload; it never labels base64 text alone as a displayed/scanned QR image.
- QR receive is disabled when no decoder/camera backend exists. Audio, NFC, Bluetooth, and LiFi remain separate adapters and are not simulated by this RFC.

## API/CLI Changes

Define `qr-send`, `qr-receive/status`, transfer status, and cleanup behavior. `cpip airgap` displays missing optional package/device requirements.

## Acceptance Criteria

- Tests round-trip one- and multi-frame transfers and reject reorder, omission, duplication conflicts, truncation, digest mismatch, replay, and limit overflow.
- Tests run headless without opening a camera or emitting audio/RF.

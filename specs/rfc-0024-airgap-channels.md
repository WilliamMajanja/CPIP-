# RFC-0024: Air-Gapped & Visual Side Channels

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/airgap.py` |
| Related | RFC-0015 |
| Version Target | v6.0.0 |

## Abstract

QR code sync, LED visual beacon, audio FSK modem, and NFC bump for
device-to-device communication in zero-RF environments.

## Design

- QR sync: animated QR sequence via camera (zbarlight/OpenCV)
- LED beacon: Morse/color encoding readable at distance
- Audio FSK: Bell 103/V.21 compatible modem via PyAudio
- NFC bump: nfcpy for contact key exchange
- All channels receive-only on one end; no RF emitted

## CLI

```
cpip airgap qr-sync
cpip airgap qr-send <file>
cpip airgap audio-tx <message>
cpip airgap audio-rx
cpip airgap nfc-pair <peer>
```

## Env

```
CPIP_AIRGAP_CAMERA=/dev/video0
CPIP_AIRGAP_AUDIO_DEVICE=hw:0,0
CPIP_AIRGAP_NFC_DEVICE=/dev/ttyACM0
```

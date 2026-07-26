# RFC-0015: Out-of-Band Side Channels

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/ob_channel.py` |
| Related | RFC-0023, RFC-0024 |
| Version Target | v6.0.0 |

## Abstract

Bluetooth mesh, NFC tap, audio modem, and LiFi camera-flash channels for
fallback communication when cellular/RF is compromised.

## Design

- BT mesh via PyBluez/BlueZ D-Bus for low-bitrate signaling
- NFC tap via nfcpy for proximity verification + short messages
- Audio FSK/DTMF modem via PyAudio for Faraday-room escape
- LiFi: modulate camera LED flash, receive via rolling-shutter
- Auto-failover: route critical alerts over side channels on primary loss

## CLI

```
cpip ob-channel list
cpip ob-channel select <name>
cpip ob-channel send <peer> <msg>
cpip ob-channel test <name>
```

## Env

```
CPIP_OB_BT_MESH=0
CPIP_OB_NFC=0
CPIP_OB_AUDIO=0
CPIP_OB_LIFI=0
CPIP_OB_FAILOVER=1
```

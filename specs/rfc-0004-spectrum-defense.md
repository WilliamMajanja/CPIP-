# RFC-0004: Full Radio Spectrum Defense

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/sdr.py`, `radio/radio_if.c` |
| Related | RFC-0002, RFC-0017 |
| Version Target | v6.0.0 |

## Abstract

Frequency hopping, spread-spectrum burst TX, jammer detection, and
RF fingerprinting of legitimate towers to defend against physical-layer
surveillance and jamming attacks.

## Motivation

Static-frequency radio links are vulnerable to jamming, direction-finding,
and replay attacks. By implementing frequency hopping, spread-spectrum bursts,
and RF fingerprinting, CPIP can evade detection, resist jamming, and identify
rogue transmitters at the physical layer.

## Design

- Frequency hopping: mesh TX rotates across configurable channel set
  (`CPIP_RADIO_HOP_SEQ`) at configurable interval
- Spread-spectrum burst: short-duration (<100ms), wide-BW (>500kHz)
  transmissions to defeat direction-finding
- Jammer detection: monitor RSSI noise floor; sustained >threshold
  for >5s triggers alert and band switch
- RF fingerprint: measure I/Q imbalance, carrier frequency offset, phase
  noise of received base stations; store in SQLite; flag newcomers vs known

## CLI Changes

```
cpip radio hop status
cpip radio hop sequence set <channels>
cpip radio spectrum
cpip radio fingerprint <cellid>
```

## Env Variables

```
CPIP_RADIO_HOP_SEQ="915000000,916000000,917000000"
CPIP_RADIO_HOP_INTERVAL=30
CPIP_RADIO_BURST=1
CPIP_RADIO_BURST_DURATION=50
CPIP_RADIO_JAMMER_THRESHOLD=-40
CPIP_RADIO_JAMMER_COOLDOWN=60
```

## Security Considerations

- Frequency hopping sequence should be derived from a shared secret
- Burst transmissions may still be detectable via energy detection
- Jammer threshold must be calibrated to local noise floor

## Limitations

- Requires SDR hardware capable of TX (HackRF, LimeSDR, USRP)
- RTL-SDR is receive-only
- RF fingerprinting requires baseline data per tower

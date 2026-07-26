# RFC-0008: Hardware / GPIO / Firmware Integration

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/hardware.py`, `server.py` |
| Related | RFC-0001, RFC-0011 |
| Version Target | v6.0.0 |

## Abstract

Trigger physical outputs (LEDs, relays, sirens, Faraday cage) on threat
levels; integrate with Raspberry Pi GPIO, USB watchdog, hardware failsafe.

## Design

- Configurable GPIO pin map via `CPIP_GPIO_PIN_MAP` (JSON)
- Threat-level actions: LOW→blink green, MEDIUM→amber steady,
  HIGH→red+buzzer, CRITICAL→siren+Faraday relay+radio cutoff
- Hardware watchdog: GPIO failsafe to radio-off on daemon crash
- USB dead-drop detection via udev monitor
- RPi HAT detection via device-tree or i2c

## CLI Changes

```
cpip hardware status
cpip hardware test <pin>
cpip hardware watchdog status
```

## Env Variables

```
CPIP_GPIO_PIN_MAP='{"led_green":17,"led_amber":27,"led_red":22,"buzzer":23,"relay_faraday":24,"radio_kill":25}'
CPIP_GPIO_WATCHDOG=1
```

## Limitations

- Requires GPIO access (/dev/gpiomem or /sys/class/gpio)
- Hardware watchdog requires normally-closed relay for failsafe

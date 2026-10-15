# RFC-0030: Hardware Event Adapter Contract

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/hardware.py`, `providers/sensors.py`, `providers/tamper.py`, `providers/power.py` |
| Related | RFC-0008, RFC-0009, RFC-0011, RFC-0016, RFF-0001, RFF-0003 |
| Version Target | v7.0.0 |

## Abstract

Separate hardware-neutral event processing from board-specific GPIO, I2C, sysfs, and udev adapters. Missing hardware remains a normal unavailable state.

## Design

- Each adapter declares detected device/model, configured pins/bus, supported measurements, and permission failures.
- Reads use explicit timeouts, bounded retries, sensor-unit metadata, and resource cleanup.
- GPIO actions require an explicit validated pin map. A software thread is never described as a hardware watchdog.
- Sensor and tamper events flow through one timestamped event schema to the scorer and evidence provider.
- Calibration stores an explicit baseline and does not erase prior audit records.
- No adapter enables an RF transmitter, wipes keys, changes routes, or actuates a relay merely because a severity value was observed; those actions require separate explicit policy.

## API/CLI Changes

Existing hardware/sensor/tamper/power status routes return per-device capability details. Add adapter-specific test/calibrate actions only when their backend exists; otherwise return HTTP 503/501.

## Acceptance Criteria

- Mocked adapter tests run without GPIO/I2C/udev packages or device files.
- Tests cover timeouts, malformed readings, sensor disconnection, invalid pin maps, and clean shutdown.
- Status never reports an unimplemented watchdog, sensor, or physical action as active.

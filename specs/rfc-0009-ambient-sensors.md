# RFC-0009: Biometric / Ambient Sensor Correlation

| Field | Value |
|-------|-------|
| Status | Draft |
| Component | `providers/sensors.py` |
| Related | RFC-0006, RFC-0011 |
| Version Target | v6.0.0 |

## Abstract

Correlate accelerometer, light, MEMS mic, magnetometer, and thermal sensor
data with cellular anomalies to detect Faraday bags, surveillance proximity,
and device tampering.

## Design

- I2C/IIO sensor readers: ADXL345, BH1750, MPU9250, I2S MEMS mic, MLX90614
- Heuristics: accel stillness+cell loss→Faraday bag, light dark+cell loss,
  ultrasonic 18-25kHz→silencing device, mag >50µT→van proximity,
  accel moving+GPS stationary→GPS spoof
- All sensor events feed ML scorer (RFC-0006)

## CLI Changes

```
cpip sensors status
cpip sensors log
cpip sensors calibrate
```

## Env Variables

```
CPIP_SENSOR_I2C_BUS=1
CPIP_SENSOR_ACCEL=1
CPIP_SENSOR_LIGHT=1
CPIP_SENSOR_MIC=1
CPIP_SENSOR_MAG=1
CPIP_SENSOR_THERMAL=0
```

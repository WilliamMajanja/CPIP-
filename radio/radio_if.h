#ifndef RADIO_IF_H
#define RADIO_IF_H

#include <stdint.h>
#include <stddef.h>

#define RADIO_PROTOCOL_VERSION 1
#define RADIO_MAX_PAYLOAD      512
#define RADIO_SOCK_PATH        "/tmp/cpip-radio.sock"

/* ── Packet Types ─────────────────────────────────────────────────── */
enum radio_pkt_type {
    RADIO_PKT_HELLO      = 0x01,
    RADIO_PKT_CONFIG     = 0x02,
    RADIO_PKT_TX_DATA    = 0x03,
    RADIO_PKT_RX_DATA    = 0x04,
    RADIO_PKT_STATUS     = 0x05,
    RADIO_PKT_ERROR      = 0x06,
    RADIO_PKT_BYE        = 0x07,
    RADIO_PKT_PING       = 0x08,
    RADIO_PKT_PONG       = 0x09,
};

/* ── Radio Modes ──────────────────────────────────────────────────── */
enum radio_mode {
    RADIO_MODE_SIM    = 0,   /* software simulation, no HW needed */
    RADIO_MODE_LORA   = 1,   /* SX1276/SX1262 via SPI */
    RADIO_MODE_TNC    = 2,   /* KISS TNC over serial */
    RADIO_MODE_RTL    = 3,   /* RTL-SDR (receive only) */
};

/* ── Modulations ──────────────────────────────────────────────────── */
enum radio_modulation {
    RADIO_MOD_LORA    = 0,
    RADIO_MOD_FSK     = 1,
    RADIO_MOD_AFSK    = 2,
    RADIO_MOD_GMSK    = 3,
    RADIO_MOD_4FSK    = 4,
};

/* ── Error Codes ──────────────────────────────────────────────────── */
enum radio_error {
    RADIO_ERR_NONE         = 0,
    RADIO_ERR_HW_NOT_FOUND = 1,
    RADIO_ERR_SPI          = 2,
    RADIO_ERR_SERIAL       = 3,
    RADIO_ERR_TIMEOUT      = 4,
    RADIO_ERR_CRC          = 5,
    RADIO_ERR_FREQ_INVALID = 6,
    RADIO_ERR_TX_FAILED    = 7,
    RADIO_ERR_RX_FAILED    = 8,
    RADIO_ERR_BUSY         = 9,
    RADIO_ERR_DUTY_CYCLE   = 10,
    RADIO_ERR_UNKNOWN      = 255,
};

/* ── Radio Configuration ──────────────────────────────────────────── */
struct radio_config {
    uint8_t  mode;            /* enum radio_mode */
    uint8_t  modulation;      /* enum radio_modulation */
    uint32_t frequency_hz;    /* carrier frequency */
    uint32_t bandwidth_hz;    /* LoRa: 125000, 250000, 500000 */
    uint8_t  spreading_factor; /* LoRa: SF7-SF12 */
    uint8_t  coding_rate;     /* LoRa: 5-8 */
    uint8_t  tx_power_dbm;    /* TX power */
    uint16_t preamble_len;    /* preamble length */
    char     serial_device[64]; /* /dev/tty* for TNC mode */
    int      serial_baud;      /* baud rate for TNC */
    char     spi_device[64];   /* /dev/spidev* for LoRa */
    int      spi_cs;           /* SPI chip select */
    uint8_t  irq_gpio;         /* GPIO IRQ pin (BCM) */
    uint16_t duty_cycle_ms;    /* max TX time per hour */
    uint16_t listen_before_talk; /* CSMA LBT in ms */
};

/* ── Radio Status ─────────────────────────────────────────────────── */
struct radio_status {
    uint8_t  hw_connected;    /* 1 = radio HW detected */
    uint8_t  mode;            /* current mode */
    int32_t  rssi_last;       /* last RSSI in dBm */
    float    snr_last;        /* last SNR in dB */
    uint32_t packets_tx;      /* total transmitted */
    uint32_t packets_rx;      /* total received */
    uint32_t packets_err;     /* total CRC errors */
    uint32_t uptime_ms;       /* time since init */
    uint8_t  duty_cycle_left; /* percent remaining */
    uint8_t  error_code;      /* last error */
};

/* ── Protocol Frame ───────────────────────────────────────────────── */
struct radio_frame {
    uint16_t length;          /* payload length (network byte order) */
    uint8_t  type;            /* enum radio_pkt_type */
    uint8_t  payload[RADIO_MAX_PAYLOAD];
} __attribute__((packed));

/* ── Config string helpers ────────────────────────────────────────── */
int radio_parse_config(const char *json, struct radio_config *cfg);
void radio_default_config(struct radio_config *cfg);

#endif /* RADIO_IF_H */

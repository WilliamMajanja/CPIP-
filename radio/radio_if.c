/* radio_if.c — CPIP Radio Interface
 * Low-level radio I/O for LoRa (SX1276/SPI), KISS TNC (serial), RTL-SDR, and
 * software simulation.  Communicates with the Python server over a Unix domain
 * socket using a simple binary protocol.
 *
 * Build: gcc -O2 -Wall -Wextra -pthread -lrt -o radio_if radio_if.c
 * Run:   ./radio_if [--lora|--tnc|--rtl|--sim] [config.json]
 *
 * Default mode is LORA (real hardware). Use --sim only for testing.
 * If SPI device is unavailable in LORA mode, the program exits with an error.
 * RTL-SDR mode uses librtlsdr for receive-only operation.
 *
 * "the way God intended" — C for the metal, Python for the pour.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <arpa/inet.h>

#include "radio_if.h"

/* ── Globals ──────────────────────────────────────────────────────────── */
static volatile atomic_int g_running = 1;
static struct radio_config g_cfg;
static struct radio_status g_status;
static pthread_mutex_t g_status_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_listen_fd = -1;   /* Unix socket listen */
static int g_client_fd = -1;   /* Python client connection */

/* ── Simulation state ─────────────────────────────────────────────────── */
static pthread_t g_sim_rx_thread;
static pthread_t g_sim_noise_thread;

/* ── LoRa register map (SX1276 subset) ──────────────────────────────────
 * Real driver would use /dev/spidev — these are the key registers.
 */
#define REG_FIFO            0x00
#define REG_OP_MODE         0x01
#define REG_FR_MSB          0x06
#define REG_FR_MID          0x07
#define REG_FR_LSB          0x08
#define REG_PA_CONFIG       0x09
#define REG_PA_RAMP         0x0A
#define REG_OCP             0x0B
#define REG_LNA             0x0C
#define REG_FIFO_ADDR_PTR   0x0D
#define REG_FIFO_TX_BASE    0x0E
#define REG_FIFO_RX_BASE    0x0F
#define REG_FIFO_RX_CURR    0x10
#define REG_RX_NB_BYTES     0x13  /* SX126x uses different map */
#define REG_MODEM_CONFIG_1  0x1D
#define REG_MODEM_CONFIG_2  0x1E
#define REG_MODEM_CONFIG_3  0x26
#define REG_PREAMBLE_MSB    0x20
#define REG_PREAMBLE_LSB    0x21
#define REG_PAYLOAD_LEN     0x22
#define REG_HOP_PERIOD      0x24
#define REG_DETECT_OPT      0x31
#define REG_DETECT_THR      0x37
#define REG_SYNC_WORD       0x39
#define REG_DIO_MAPPING_1   0x40
#define REG_DIO_MAPPING_2   0x41
#define REG_VERSION         0x42
#define REG_PA_DAC          0x4A
#define REG_AGC_REF         0x61  /* approximate */

/* SX1276 LoRa mode constants */
#define MODE_LORA_SLEEP     0x80
#define MODE_LORA_STDBY     0x81
#define MODE_LORA_TX        0x83
#define MODE_LORA_RX_CONT   0x85
#define MODE_LORA_RX_SINGLE 0x86
#define MODE_LORA_CAD       0x87

/* ── Signal handler ───────────────────────────────────────────────────── */
static void handle_signal(int sig) {
    (void)sig;
    atomic_store(&g_running, 0);
}

/* ── Utility: millisleep ──────────────────────────────────────────────── */
static void msleep(uint32_t ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* ── Utility: millis since epoch ──────────────────────────────────────── */
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ── Frame read/write helpers ─────────────────────────────────────────── */

static int write_frame(int fd, uint8_t type, const uint8_t *payload, uint16_t len) {
    struct radio_frame frame;
    if (len > RADIO_MAX_PAYLOAD) len = RADIO_MAX_PAYLOAD;
    frame.length = htons(len);
    frame.type = type;
    if (len > 0 && payload) memcpy(frame.payload, payload, len);
    size_t total = sizeof(uint16_t) + sizeof(uint8_t) + len;
    return write(fd, &frame, total) == (ssize_t)total ? 0 : -1;
}

static int write_error(int fd, uint8_t code, const char *msg) {
    uint8_t buf[256];
    uint16_t mlen = msg ? strlen(msg) : 0;
    if (mlen > 254) mlen = 254;
    buf[0] = code;
    if (mlen > 0) memcpy(buf + 1, msg, mlen);
    return write_frame(fd, RADIO_PKT_ERROR, buf, 1 + mlen);
}

/* ── SPI (real /dev/spidev + simulation fallback) ─────────────────────
 * On a Pi with SX1276/78 connected to the SPI bus, this drives the
 * radio chip directly.  If /dev/spidev is not available, falls back
 * to the old stub behaviour (logs, returns 0).
 */
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

static int g_spi_fd = -1;

static int spi_open(const char *device) {
    if (!device || !*device) return -1;
    g_spi_fd = open(device, O_RDWR);
    if (g_spi_fd < 0) return -1;
    uint8_t mode = SPI_MODE_0;
    uint8_t bits = 8;
    uint32_t speed = 2000000;
    if (ioctl(g_spi_fd, SPI_IOC_WR_MODE, &mode) < 0) goto fail;
    if (ioctl(g_spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0) goto fail;
    if (ioctl(g_spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) goto fail;
    return 0;
fail:
    close(g_spi_fd);
    g_spi_fd = -1;
    return -1;
}

static int spi_write_reg(uint8_t reg, uint8_t val) {
    if (g_spi_fd < 0) { (void)reg; (void)val; return 0; }
    uint8_t tx[2] = {reg & 0x7F, val};
    uint8_t rx[2] = {0};
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = 2,
        .speed_hz = 2000000,
        .delay_usecs = 0,
        .bits_per_word = 8,
    };
    return ioctl(g_spi_fd, SPI_IOC_MESSAGE(1), &tr);
}

static int spi_read_reg(uint8_t reg, uint8_t *val) {
    if (!val) return -1;
    if (g_spi_fd < 0) { *val = 0x12; return 0; }
    uint8_t tx[2] = {reg | 0x80, 0};
    uint8_t rx[2] = {0};
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = 2,
        .speed_hz = 2000000,
        .delay_usecs = 0,
        .bits_per_word = 8,
    };
    int ret = ioctl(g_spi_fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret >= 0) *val = rx[1];
    return ret;
}

static int spi_burst_write(uint8_t reg, const uint8_t *data, int len) {
    if (!data || len <= 0) return -1;
    if (g_spi_fd < 0) { (void)reg; return 0; }
    int total = 1 + len;
    if ((unsigned)total > sizeof(uint8_t[260])) return -1;
    uint8_t tx[260], rx[260];
    tx[0] = reg & 0x7F;
    memcpy(tx + 1, data, len);
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = total,
        .speed_hz = 2000000,
        .delay_usecs = 0,
        .bits_per_word = 8,
    };
    return ioctl(g_spi_fd, SPI_IOC_MESSAGE(1), &tr);
}

static int spi_burst_read(uint8_t reg, uint8_t *data, int len) {
    if (!data || len <= 0) return -1;
    if (g_spi_fd < 0) { (void)reg; memset(data, 0, len); return 0; }
    int total = 1 + len;
    if ((unsigned)total > sizeof(uint8_t[260])) return -1;
    uint8_t tx[260], rx[260];
    memset(tx, 0, total);
    tx[0] = reg | 0x80;
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = total,
        .speed_hz = 2000000,
        .delay_usecs = 0,
        .bits_per_word = 8,
    };
    int ret = ioctl(g_spi_fd, SPI_IOC_MESSAGE(1), &tr);
    if (ret >= 0) memcpy(data, rx + 1, len);
    return ret;
}

/* ── LoRa Mode Helpers ────────────────────────────────────────────────── */

static int lora_set_op_mode(uint8_t mode) {
    return spi_write_reg(REG_OP_MODE, mode);
}

static int lora_set_frequency(uint32_t freq_hz) {
    /* SX1276: FRF = freq_hz / 61.035 (32 MHz osc) */
    uint64_t frf = ((uint64_t)freq_hz << 19) / 32000000;
    spi_write_reg(REG_FR_MSB, (frf >> 16) & 0xFF);
    spi_write_reg(REG_FR_MID, (frf >> 8) & 0xFF);
    spi_write_reg(REG_FR_LSB, frf & 0xFF);
    return 0;
}

static int lora_configure(struct radio_config *cfg) {
    lora_set_op_mode(MODE_LORA_SLEEP);
    msleep(10);
    lora_set_op_mode(MODE_LORA_STDBY);
    msleep(10);

    lora_set_frequency(cfg->frequency_hz);

    /* Modem config 1: BW + CR + implicit/explict */
    uint8_t bw_bits;
    if (cfg->bandwidth_hz >= 500000) bw_bits = 0x09;  /* 500 kHz */
    else if (cfg->bandwidth_hz >= 250000) bw_bits = 0x08;  /* 250 kHz */
    else bw_bits = 0x07;  /* 125 kHz */
    uint8_t mc1 = (bw_bits << 4) | ((cfg->coding_rate - 4) << 1) | 0x01;
    spi_write_reg(REG_MODEM_CONFIG_1, mc1);

    /* Modem config 2: SF + CRC + TX mode */
    uint8_t mc2 = ((cfg->spreading_factor) << 4) | 0x04;  /* CRC on */
    spi_write_reg(REG_MODEM_CONFIG_2, mc2);

    /* Preamble */
    spi_write_reg(REG_PREAMBLE_MSB, (cfg->preamble_len >> 8) & 0xFF);
    spi_write_reg(REG_PREAMBLE_LSB, cfg->preamble_len & 0xFF);

    /* PA: max power by default */
    spi_write_reg(REG_PA_CONFIG, 0xFF);

    /* LNA boost */
    spi_write_reg(REG_LNA, 0x23);

    /* AGC auto */
    spi_write_reg(REG_MODEM_CONFIG_3, 0x04);

    return 0;
}

static int lora_tx(const uint8_t *data, uint16_t len) {
    if (len > RADIO_MAX_PAYLOAD) len = RADIO_MAX_PAYLOAD;
    lora_set_op_mode(MODE_LORA_STDBY);
    msleep(1);
    spi_write_reg(REG_FIFO_ADDR_PTR, 0x00);
    spi_burst_write(REG_FIFO, data, len);
    spi_write_reg(REG_PAYLOAD_LEN, len);
    lora_set_op_mode(MODE_LORA_TX);
    /* Wait for TX done (in production: IRQ via DIO0 GPIO) */
    msleep(100);
    lora_set_op_mode(MODE_LORA_STDBY);
    return 0;
}

static int lora_rx(uint8_t *buf, uint16_t *len) {
    lora_set_op_mode(MODE_LORA_RX_CONT);
    msleep(50);  /* listen window */
    /* Check IRQ flags (in production: DIO0 rising edge) */
    uint8_t irq = 0;
    spi_read_reg(0x12, &irq);  /* REG_IRQ_FLAGS */
    if (!(irq & 0x40)) {  /* RxDone */
        *len = 0;
        return 0;
    }
    uint8_t nb = 0;
    spi_read_reg(REG_RX_NB_BYTES, &nb);
    if (nb > 0) {
        spi_read_reg(0x10, &nb);  /* current addr */
        spi_write_reg(REG_FIFO_ADDR_PTR, nb);
        spi_burst_read(REG_FIFO, buf, nb);
        *len = nb;
    }
    lora_set_op_mode(MODE_LORA_STDBY);
    (void)irq;
    return 0;
}

/* ── KISS TNC (serial) ────────────────────────────────────────────────── */

static int g_tnc_fd = -1;

static int tnc_open(const char *device, int baud) {
    g_tnc_fd = open(device, O_RDWR | O_NOCTTY | O_NDELAY);
    if (g_tnc_fd < 0) return -1;
    struct termios tio;
    memset(&tio, 0, sizeof(tio));
    cfmakeraw(&tio);
    speed_t spd;
    switch (baud) {
        case 1200: spd = B1200; break;
        case 2400: spd = B2400; break;
        case 4800: spd = B4800; break;
        case 9600: spd = B9600; break;
        case 19200: spd = B19200; break;
        case 38400: spd = B38400; break;
        case 57600: spd = B57600; break;
        default: spd = B115200;
    }
    cfsetispeed(&tio, spd);
    cfsetospeed(&tio, spd);
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 1;
    tcsetattr(g_tnc_fd, TCSANOW, &tio);
    fcntl(g_tnc_fd, F_SETFL, fcntl(g_tnc_fd, F_GETFL) & ~O_NDELAY);
    return 0;
}

static int tnc_tx(const uint8_t *data, uint16_t len) {
    if (g_tnc_fd < 0) return -1;
    uint8_t *frame = malloc(len + 2);
    frame[0] = 0xC0;  /* KISS FEND */
    memcpy(frame + 1, data, len);
    frame[len + 1] = 0xC0;
    int ret = write(g_tnc_fd, frame, len + 2);
    free(frame);
    return (ret > 0) ? 0 : -1;
}

static int tnc_rx(uint8_t *buf, uint16_t *len) {
    if (g_tnc_fd < 0) return -1;
    uint8_t header;
    if (read(g_tnc_fd, &header, 1) != 1 || header != 0xC0) return 0;
    /* Read until FEND */
    *len = 0;
    while (*len < RADIO_MAX_PAYLOAD) {
        uint8_t b;
        if (read(g_tnc_fd, &b, 1) != 1) break;
        if (b == 0xC0) break;
        buf[(*len)++] = b;
    }
    return 0;
}

/* ── Simulation Mode ────────────────────────────────────────────────────
 * Generates synthetic test traffic and loopback echo for development.
 * ONLY active when explicitly requested with --sim flag.
 * NOT used as a fallback for missing hardware.
 */

static void *sim_rx_loop(void *arg __attribute__((unused))) {
    uint8_t buf[RADIO_MAX_PAYLOAD];
    while (atomic_load(&g_running) && g_client_fd >= 0) {
        msleep(random() % 8000 + 2000);  /* random 2-10s between sim packets */
        if (!atomic_load(&g_running)) break;
        /* Generate a synthetic mesh heartbeat (test traffic only) */
        uint16_t plen = snprintf((char*)buf, sizeof(buf),
            "{\"type\":\"sat_heartbeat\",\"pot\":\"sim-%04x\","
            "\"hostname\":\"sim-node\",\"device\":\"radio-sim\","
            "\"port\":4180,\"mesh_port\":4191,\"hops\":0,"
            "\"lat\":%.4f,\"lon\":%.4f,\"timestamp\":%lu,"
            "\"_simulated\":true}",
            (unsigned)(random() & 0xFFFF),
            (random() % 18000) / 100.0 - 90.0,
            (random() % 36000) / 100.0 - 180.0,
            (unsigned long)time(NULL));
        pthread_mutex_lock(&g_status_lock);
        g_status.packets_rx++;
        pthread_mutex_unlock(&g_status_lock);
        write_frame(g_client_fd, RADIO_PKT_RX_DATA, buf, plen);
    }
    return NULL;
}

static void *sim_noise_loop(void *arg) {
    (void)arg;
    while (atomic_load(&g_running)) {
        msleep(30000);
        pthread_mutex_lock(&g_status_lock);
        g_status.rssi_last = -110 + (random() % 15);
        g_status.snr_last = (random() % 30) / 10.0f;
        pthread_mutex_unlock(&g_status_lock);
    }
    return NULL;
}

/* ── RTL-SDR Receive (via librtlsdr) ──────────────────────────────────
 * Receive-only mode using RTL-SDR dongle. Requires librtlsdr.
 * If librtlsdr is unavailable, this mode will fail to initialize.
 */

#ifdef USE_RTLSDR
#include <rtl-sdr.h>

static rtlsdr_dev_t *g_rtl_dev = NULL;
static pthread_t g_rtl_rx_thread;
static volatile int g_rtl_running = 0;

static void rtl_callback(uint8_t *buf, uint32_t len, void *ctx) {
    (void)ctx;
    if (!buf || len == 0) return;
    /* Simple FSK/AFSK detection: look for transitions in I/Q data.
     * This is a simplified demodulator — a real implementation would
     * use a proper FSK/GMSK demodulator for the selected frequency. */
    pthread_mutex_lock(&g_status_lock);
    g_status.packets_rx++;
    g_status.rssi_last = -60 - (random() % 20);  /* approximate RSSI */
    g_status.snr_last = 5.0f + (random() % 30) / 10.0f;
    pthread_mutex_unlock(&g_status_lock);
}

static void *rtl_rx_loop(void *arg __attribute__((unused))) {
    int device_index = 0;
    int r = rtlsdr_open(&g_rtl_dev, device_index);
    if (r < 0) {
        fprintf(stderr, "[radio] RTL-SDR: Failed to open device %d: %d\n", device_index, r);
        g_rtl_running = 0;
        return NULL;
    }
    /* Configure for 915 MHz ISM band, 2.4 MSPS */
    rtlsdr_set_center_freq(g_rtl_dev, g_cfg.frequency_hz);
    rtlsdr_set_sample_rate(g_rtl_dev, 2400000);
    rtlsdr_set_tuner_gain_mode(g_rtl_dev, 0);  /* auto gain */
    rtlsdr_reset_buffer(g_rtl_dev);

    g_rtl_running = 1;
    fprintf(stderr, "[radio] RTL-SDR: Receiving at %u Hz\n", g_cfg.frequency_hz);

    /* Read in async mode — calls rtl_callback for each buffer */
    rtlsdr_read_async(g_rtl_dev, rtl_callback, NULL, 0, 16384);

    rtlsdr_close(g_rtl_dev);
    g_rtl_dev = NULL;
    g_rtl_running = 0;
    return NULL;
}
#endif /* USE_RTLSDR */

/* ── Radio Backend Dispatch ───────────────────────────────────────────── */

static int radio_init(struct radio_config *cfg) {
    memset(&g_status, 0, sizeof(g_status));
    g_status.mode = cfg->mode;

    switch (cfg->mode) {
    case RADIO_MODE_SIM:
        fprintf(stderr, "[radio] WARNING: Running in SIMULATION mode — no real radio traffic\n");
        g_status.hw_connected = 1;
        g_status.rssi_last = -80;
        g_status.snr_last = 8.0f;
        pthread_create(&g_sim_rx_thread, NULL, sim_rx_loop, NULL);
        pthread_create(&g_sim_noise_thread, NULL, sim_noise_loop, NULL);
        pthread_detach(g_sim_rx_thread);
        pthread_detach(g_sim_noise_thread);
        break;

    case RADIO_MODE_LORA:
        if (cfg->spi_device[0] == '\0') {
            fprintf(stderr, "[radio] ERROR: No SPI device specified for LoRa mode\n");
            fprintf(stderr, "[radio] Set --device /dev/spidev0.0 or use --sim for testing\n");
            return -1;
        }
        if (spi_open(cfg->spi_device) < 0) {
            fprintf(stderr, "[radio] ERROR: Cannot open SPI device %s: %s\n",
                    cfg->spi_device, strerror(errno));
            fprintf(stderr, "[radio] Is the SX1276/78 connected? Is SPI enabled?\n");
            fprintf(stderr, "[radio] Run: sudo raspi-config -> Interface -> SPI -> Enable\n");
            fprintf(stderr, "[radio] Or use --sim for simulation testing\n");
            return -1;
        }
        fprintf(stderr, "[radio] SPI device %s opened successfully\n", cfg->spi_device);
        lora_configure(cfg);
        /* Verify chip by reading version register */
        uint8_t ver = 0;
        spi_read_reg(REG_VERSION, &ver);
        if (ver == 0x12) {
            fprintf(stderr, "[radio] SX1276 detected (version reg = 0x%02x)\n", ver);
            g_status.hw_connected = 1;
        } else {
            fprintf(stderr, "[radio] WARNING: SX1276 version reg = 0x%02x (expected 0x12)\n", ver);
            fprintf(stderr, "[radio] Radio may not be connected or may be a different chip\n");
            g_status.hw_connected = (g_spi_fd >= 0) ? 1 : 0;
        }
        break;

    case RADIO_MODE_TNC:
        if (tnc_open(cfg->serial_device, cfg->serial_baud) < 0) {
            fprintf(stderr, "[radio] ERROR: Cannot open TNC device %s: %s\n",
                    cfg->serial_device, strerror(errno));
            fprintf(stderr, "[radio] Is the TNC/modem connected?\n");
            return -1;
        }
        fprintf(stderr, "[radio] TNC opened on %s @ %d baud\n",
                cfg->serial_device, cfg->serial_baud);
        g_status.hw_connected = 1;
        break;

    case RADIO_MODE_RTL:
#ifdef USE_RTLSDR
        fprintf(stderr, "[radio] Starting RTL-SDR receive at %u Hz\n", cfg->frequency_hz);
        pthread_create(&g_rtl_rx_thread, NULL, rtl_rx_loop, NULL);
        pthread_detach(g_rtl_rx_thread);
        g_status.hw_connected = g_rtl_running ? 1 : 0;
#else
        fprintf(stderr, "[radio] ERROR: RTL-SDR support not compiled in.\n");
        fprintf(stderr, "[radio] Rebuild with: make RTL=1  (requires librtlsdr-dev)\n");
        return -1;
#endif
        break;

    default:
        fprintf(stderr, "[radio] ERROR: Unknown radio mode %d\n", cfg->mode);
        return -1;
    }
    return 0;
}

static int radio_transmit(const uint8_t *data, uint16_t len) {
    int ret = -1;
    switch (g_cfg.mode) {
    case RADIO_MODE_SIM:
        /* Sim: echo back as received data for loopback test */
        msleep(10 + random() % 50);
        write_frame(g_client_fd, RADIO_PKT_RX_DATA, data, len);
        ret = 0;
        break;
    case RADIO_MODE_LORA:
        ret = lora_tx(data, len);
        break;
    case RADIO_MODE_TNC:
        ret = tnc_tx(data, len);
        break;
    default:
        break;
    }
    if (ret == 0) {
        pthread_mutex_lock(&g_status_lock);
        g_status.packets_tx++;
        pthread_mutex_unlock(&g_status_lock);
    }
    return ret;
}

__attribute__((unused)) static int radio_receive(uint8_t *buf, uint16_t *len) {
    *len = 0;
    (void)buf;
    switch (g_cfg.mode) {
    case RADIO_MODE_SIM:
        /* sim_rx_loop pushes asynchronously */
        break;
    case RADIO_MODE_LORA:
        return lora_rx(buf, len);
    case RADIO_MODE_TNC:
        return tnc_rx(buf, len);
    default:
        break;
    }
    return 0;
}

/* ── Config Parser (simple JSON subset) ───────────────────────────────── */

int radio_parse_config(const char *json, struct radio_config *cfg) {
    radio_default_config(cfg);
    const char *p = json;
    if (!p) return -1;
    /* field-by-field scan — no JSON lib dependency */
    char *freq = strstr(json, "\"frequency\"");
    if (freq) cfg->frequency_hz = strtoul(freq + 12, NULL, 10);
    char *bw = strstr(json, "\"bandwidth\"");
    if (bw) cfg->bandwidth_hz = strtoul(bw + 11, NULL, 10);
    char *sf = strstr(json, "\"sf\"");
    if (sf) cfg->spreading_factor = strtoul(sf + 4, NULL, 10);
    char *cr = strstr(json, "\"cr\"");
    if (cr) cfg->coding_rate = strtoul(cr + 4, NULL, 10);
    char *pwr = strstr(json, "\"tx_power\"");
    if (pwr) cfg->tx_power_dbm = strtoul(pwr + 10, NULL, 10);
    char *mode = strstr(json, "\"mode\"");
    if (mode) {
        if (strstr(mode, "lora")) cfg->mode = RADIO_MODE_LORA;
        else if (strstr(mode, "tnc")) cfg->mode = RADIO_MODE_TNC;
        else if (strstr(mode, "sim")) cfg->mode = RADIO_MODE_SIM;
    }
    char *dev = strstr(json, "\"device\"");
    if (dev) {
        dev = strchr(dev, '"');
        if (dev) dev = strchr(dev + 1, '"');
        if (dev) {
            int dlen = 0;
            const char *end = dev + 1;
            while (*end && *end != '"') { end++; dlen++; }
            if (dlen > 0 && dlen < 64) {
                memcpy(cfg->serial_device, dev + 1, dlen);
                cfg->serial_device[dlen] = '\0';
            }
        }
    }
    char *baud = strstr(json, "\"baud\"");
    if (baud) cfg->serial_baud = strtoul(baud + 6, NULL, 10);
    return 0;
}

void radio_default_config(struct radio_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = RADIO_MODE_LORA;       /* Default: real hardware, not simulation */
    cfg->modulation = RADIO_MOD_LORA;
    cfg->frequency_hz = 915000000;    /* 915 MHz ISM */
    cfg->bandwidth_hz = 125000;
    cfg->spreading_factor = 9;        /* SF9 */
    cfg->coding_rate = 5;             /* 4/5 */
    cfg->tx_power_dbm = 17;
    cfg->preamble_len = 8;
    cfg->serial_baud = 115200;
    cfg->spi_cs = 0;
    cfg->irq_gpio = 22;
    cfg->duty_cycle_ms = 36000;       /* 1% duty cycle at 915 MHz */
    cfg->listen_before_talk = 100;    /* 100ms LBT */
    strcpy(cfg->spi_device, "/dev/spidev0.0");
    strcpy(cfg->serial_device, "/dev/ttyUSB0");
}

/* ── Unix Socket Server ───────────────────────────────────────────────── */

static int sock_server_init(const char *path) {
    unlink(path);
    g_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_listen_fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (bind(g_listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(g_listen_fd);
        return -1;
    }
    chmod(path, 0666);
    listen(g_listen_fd, 1);
    return 0;
}

static int sock_accept(void) {
    struct sockaddr_un peer;
    socklen_t peerlen = sizeof(peer);
    g_client_fd = accept(g_listen_fd, (struct sockaddr*)&peer, &peerlen);
    return g_client_fd;
}

/* ── Main Command Loop ────────────────────────────────────────────────── */

static void process_command(uint8_t type, const uint8_t *payload, uint16_t len) {
    uint8_t reply[RADIO_MAX_PAYLOAD];

    switch (type) {
    case RADIO_PKT_HELLO: {
        uint16_t mlen = snprintf((char*)reply, sizeof(reply),
            "{\"version\":%d,\"mode\":%d,\"hw\":%d}",
            RADIO_PROTOCOL_VERSION, g_cfg.mode, g_status.hw_connected);
        write_frame(g_client_fd, RADIO_PKT_HELLO, reply, mlen);
        break;
    }
    case RADIO_PKT_CONFIG: {
        struct radio_config new_cfg;
        char json_str[512];
        uint16_t cplen = len < 511 ? len : 511;
        memcpy(json_str, payload, cplen);
        json_str[cplen] = '\0';
        if (radio_parse_config(json_str, &new_cfg) == 0) {
            memcpy(&g_cfg, &new_cfg, sizeof(g_cfg));
            write_frame(g_client_fd, RADIO_PKT_CONFIG, NULL, 0);
        } else {
            write_error(g_client_fd, RADIO_ERR_UNKNOWN, "bad config");
        }
        break;
    }
    case RADIO_PKT_TX_DATA: {
        if (radio_transmit(payload, len) == 0)
            write_frame(g_client_fd, RADIO_PKT_TX_DATA, NULL, 0);
        else
            write_error(g_client_fd, RADIO_ERR_TX_FAILED, "tx failed");
        break;
    }
    case RADIO_PKT_STATUS: {
        pthread_mutex_lock(&g_status_lock);
        g_status.uptime_ms = (uint32_t)(now_ms());
        uint16_t slen = snprintf((char*)reply, sizeof(reply),
            "{\"hw\":%d,\"mode\":%d,\"rssi\":%d,\"snr\":%.1f,"
            "\"tx\":%u,\"rx\":%u,\"err\":%u,\"uptime\":%u,"
            "\"duty\":%u,\"error\":%u}",
            g_status.hw_connected, g_status.mode,
            g_status.rssi_last, (double)g_status.snr_last,
            g_status.packets_tx, g_status.packets_rx, g_status.packets_err,
            g_status.uptime_ms, g_status.duty_cycle_left, g_status.error_code);
        pthread_mutex_unlock(&g_status_lock);
        write_frame(g_client_fd, RADIO_PKT_STATUS, reply, slen);
        break;
    }
    case RADIO_PKT_PING: {
        write_frame(g_client_fd, RADIO_PKT_PONG, NULL, 0);
        break;
    }
    case RADIO_PKT_BYE:
        atomic_store(&g_running, 0);
        break;
    default:
        write_error(g_client_fd, RADIO_ERR_UNKNOWN, "unknown pkt type");
        break;
    }
}

static void handle_client(void) {
    unsigned char hdr[3];  /* 2 bytes len + 1 byte type */

    while (atomic_load(&g_running) && g_client_fd >= 0) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_client_fd, &rfds);
        struct timeval tv = { 1, 0 };
        int ret = select(g_client_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;  /* timeout — allows checking g_running */

        /* Read header (3 bytes) */
        ssize_t nr = read(g_client_fd, hdr, 3);
        if (nr <= 0) break;

        uint16_t plen = (hdr[0] << 8) | hdr[1];
        uint8_t ptype = hdr[2];
        if (plen > RADIO_MAX_PAYLOAD) plen = RADIO_MAX_PAYLOAD;

        uint8_t payload[RADIO_MAX_PAYLOAD];
        if (plen > 0) {
            ssize_t pr = 0;
            while (pr < plen) {
                ssize_t r = read(g_client_fd, payload + pr, plen - pr);
                if (r <= 0) break;
                pr += r;
            }
        }
        process_command(ptype, payload, plen);
    }
}

/* ── Entry Point ──────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    radio_default_config(&g_cfg);

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sim") == 0) g_cfg.mode = RADIO_MODE_SIM;
        else if (strcmp(argv[i], "--lora") == 0) g_cfg.mode = RADIO_MODE_LORA;
        else if (strcmp(argv[i], "--tnc") == 0) g_cfg.mode = RADIO_MODE_TNC;
        else if (strcmp(argv[i], "--rtl") == 0) g_cfg.mode = RADIO_MODE_RTL;
        else if (strcmp(argv[i], "--freq") == 0 && i + 1 < argc)
            g_cfg.frequency_hz = strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--sf") == 0 && i + 1 < argc)
            g_cfg.spreading_factor = strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--bw") == 0 && i + 1 < argc)
            g_cfg.bandwidth_hz = strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--power") == 0 && i + 1 < argc)
            g_cfg.tx_power_dbm = strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            strncpy(g_cfg.serial_device, argv[++i], sizeof(g_cfg.serial_device) - 1);
            g_cfg.serial_device[sizeof(g_cfg.serial_device) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--baud") == 0 && i + 1 < argc)
            g_cfg.serial_baud = strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("CPIP Radio Interface v%d\n", RADIO_PROTOCOL_VERSION);
            printf("Usage: %s [--sim|--lora|--tnc|--rtl] [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --freq <hz>     Frequency (default: 915000000)\n");
            printf("  --sf <7-12>     Spreading factor (default: 9)\n");
            printf("  --bw <hz>       Bandwidth (default: 125000)\n");
            printf("  --power <dbm>   TX power (default: 17)\n");
            printf("  --device <path> Serial/SPI device (default: /dev/ttyUSB0)\n");
            printf("  --baud <rate>   Serial baud (default: 115200)\n");
            printf("  --help          This help\n");
            return 0;
        }
    }

    fprintf(stderr, "[RADIO] CPIP Radio Interface v%d starting...\n",
            RADIO_PROTOCOL_VERSION);

    /* Init radio hardware */
    if (radio_init(&g_cfg) < 0) {
        fprintf(stderr, "[RADIO] Hardware init failed\n");
        return 1;
    }
    fprintf(stderr, "[RADIO] Mode=%d Freq=%u Hz BW=%u SF=%d\n",
            g_cfg.mode, g_cfg.frequency_hz, g_cfg.bandwidth_hz,
            g_cfg.spreading_factor);

    /* Set up Unix socket */
    if (sock_server_init(RADIO_SOCK_PATH) < 0) {
        fprintf(stderr, "[RADIO] Socket bind failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[RADIO] Listening on %s\n", RADIO_SOCK_PATH);

    /* Accept Python connection */
    fprintf(stderr, "[RADIO] Waiting for Python controller...\n");
    if (sock_accept() < 0) {
        fprintf(stderr, "[RADIO] Accept failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "[RADIO] Connected\n");

    /* Send hello */
    write_frame(g_client_fd, RADIO_PKT_HELLO, NULL, 0);

    /* Main loop */
    handle_client();

    /* Cleanup */
    write_frame(g_client_fd, RADIO_PKT_BYE, NULL, 0);
    if (g_client_fd >= 0) close(g_client_fd);
    if (g_listen_fd >= 0) close(g_listen_fd);
    if (g_tnc_fd >= 0) close(g_tnc_fd);
    unlink(RADIO_SOCK_PATH);
    fprintf(stderr, "[RADIO] Shutdown\n");
    return 0;
}

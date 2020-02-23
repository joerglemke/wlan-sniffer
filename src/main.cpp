#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_internal.h"
#include "lwip/err.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"

#include <Arduino.h>
#include <Button2.h>
#include <TFT_eSPI.h>

#ifndef SERIAL_MAX_BAUDRATE
#define SERIAL_MAX_BAUDRATE 115200
#endif

#define MAX_SNAPLEN 2048
#define MIN_CHANNEL 1
#define MAX_CHANNEL 11
#define AP_CHANNEL 10
#define HOP_INTERVAL 214 //in ms (only necessary if channelHopping is true)
#define BEACON_LOG_INTERVAL_USEC 5000000

#define LED_BLUE 15
#define LED_RED 17
#define LED_GREEN 2

int capturePacketSize = 256;
int captureMgmtPacketSize = 1024;
int captureLargeDataLimit = 256;
int captureLargeDataPacketSize = 128;
int currentChannel = AP_CHANNEL;
bool channelHopping = false;
bool fullData = false;
unsigned long timeLastChannelChange = 0;
int64_t timeNextBeacon = 0;
uint32_t timeOffset;
bool dropBeacons = true;
bool filterByMac = false;
byte filterMac[6];
bool sniffing = false;
bool active = false;

Button2 controlButton(0);

TFT_eSPI tft = TFT_eSPI();

void setupTFT() {
  tft.init();
  tft.setRotation(1);
  tft.fillScreen(TFT_BLACK);
  if (TFT_BL > 0) {
    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, TFT_BACKLIGHT_ON);
  }

  tft.setTextSize(1);
  tft.setTextColor(TFT_WHITE);
  tft.setCursor(0, 0);
  tft.setTextDatum(MC_DATUM);
  tft.setSwapBytes(true);
}

void showStringOnTFT(const char* str, uint16_t color) {
  tft.fillScreen(TFT_BLACK);
  tft.setRotation(1);
  tft.setTextSize(4);
  tft.setTextColor(color);
  tft.setTextDatum(MC_DATUM);
  tft.drawString(str, tft.width() / 2, tft.height() / 2);
}

enum OperatingMode {
  OPM_NONE = 0,
  OPM_INITIAL,
  OPM_STARTING,
  OPM_STARTED,
  OPM_RUNNING,
  OPM_STOPPING,
  OPM_STOPPED,
};

OperatingMode currentOpMode;
OperatingMode shownOpMode;

const byte LED_STATES[] = { 0, 1, 4, 5, 2, 3, 0, };

uint8_t ledState(byte leds, byte which) {
  return (leds & which) ? HIGH : LOW;
}

void showStateOnLEDs(OperatingMode opMode) {
  byte leds = LED_STATES[currentOpMode];
  digitalWrite(LED_RED, ledState(leds, 1));
  digitalWrite(LED_GREEN, ledState(leds, 2));
  digitalWrite(LED_BLUE, ledState(leds, 4));
}

const uint16_t TFT_STATE_COLORS[] = {
  TFT_RED,
  TFT_ORANGE,
  TFT_SKYBLUE,
  TFT_MAGENTA,
  TFT_GREEN,
  TFT_YELLOW,
  TFT_DARKGREY,
};

const char* const TFT_STATE_STRINGS[] = {
  "NONE",
  "Waiting",
  "Starting",
  "Started",
  "Sniffing",
  "Stopping",
  "Stopped",
};

void showStateOnTFT(OperatingMode opMode) {
  showStringOnTFT(TFT_STATE_STRINGS[opMode], TFT_STATE_COLORS[opMode]);
}

void setOperatingMode(OperatingMode opMode) {
  currentOpMode = opMode;
}

void showOperatingMode() {
  if (currentOpMode != shownOpMode) {
    shownOpMode = currentOpMode;
    showStateOnLEDs(shownOpMode);
    showStateOnTFT(shownOpMode);
  }
}

void pcap32(uint32_t n){
  uint8_t buf[4];
  buf[0] = n;
  buf[1] = n >> 8;
  buf[2] = n >> 16;
  buf[3] = n >> 24;
  Serial.write(buf, 4);
}

void pcap16(uint16_t n){
  uint8_t buf[2];
  buf[0] = n;
  buf[1] = n >> 8;
  Serial.write(buf, 2);
}

void pcapHeader(){
  pcap32(0xa1b2c3d4); // magic
  pcap16(2); // major version
  pcap16(4); //minor version
  pcap32(0); // timezone
  pcap32(0); // time accuracy
  pcap32(MAX_SNAPLEN); // max capture length
  pcap32(105); // linktype wifi 802.11
}

void pcapPacket(int64_t ts, uint32_t len, uint8_t* buf, uint32_t snaplen) {
  if (snaplen > MAX_SNAPLEN) {
    snaplen = MAX_SNAPLEN;
  }
  if (snaplen > len) {
    snaplen = len;
  }
  pcap32((uint32_t)(ts / 1000000) + timeOffset);
  pcap32((uint32_t)(ts % 1000000));
  pcap32(snaplen);
  pcap32(len);
  Serial.write(buf, snaplen);
}

/* will be executed on every packet the ESP32 gets while beeing in promiscuous mode */
void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!sniffing) {
    if (active) {
      Serial.flush();
      setOperatingMode(OPM_STOPPED);
      active = false;
    }
    return;
  }

  if (!active) {
    Serial.print("SNIFFMODE=running\r\n");
    setOperatingMode(OPM_RUNNING);
    active = true;
    pcapHeader();
  }

  int64_t now_usec = esp_timer_get_time();

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t& ctrl = pkt->rx_ctrl;
  byte* payload = pkt->payload;
  uint32_t length = ctrl.sig_len;
  int packetType = (payload[0] >> 2) & 3;
  int subType = (payload[0] >> 4) & 15;
  
  bool bCapture = true;

  if (filterByMac) {
    bCapture &= !(memcmp(payload + 4,  filterMac, 6) && memcmp(payload + 10, filterMac, 6) && memcmp(payload + 16, filterMac, 6));
    
    if (bCapture && dropBeacons) {
      if (packetType == 0 && subType == 8) {
        if (timeNextBeacon > now_usec) {
          bCapture = false;
        } else {
          timeNextBeacon = now_usec + BEACON_LOG_INTERVAL_USEC;
        }
      }
    }
  }

  if (bCapture) {
    uint32_t snaplen = length;

    if (packetType == 0 || packetType == 1) {
      snaplen = captureMgmtPacketSize;
    } else if (!fullData) {
      if (length >= captureLargeDataLimit) {
        snaplen = captureLargeDataPacketSize;
      } else {
        snaplen = capturePacketSize;
      }
    }

    pcapPacket(now_usec, length, payload, snaplen);
  }
}

esp_err_t event_handler(void *ctx, system_event_t *event) {
  return ESP_OK;
}

void initWiFi(int ap_channel) {
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );  
  // ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_AP) );  
  // wifi_config_t ap_config;
  // ap_config.ap.channel = ap_channel;
  // // ap_config.ap.beacon_interval = 500;
  // ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_AP, &ap_config) );
  // ESP_ERROR_CHECK( esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20) );
  ESP_ERROR_CHECK( esp_wifi_start() );
}

void startSniffing() {
  setOperatingMode(OPM_STARTING);
  Serial.print("SNIFFMODE=starting\r\n");
  Serial.flush();

  Serial.updateBaudRate(SERIAL_MAX_BAUDRATE);
  delay(2000);

  sniffing = true;

  initWiFi(AP_CHANNEL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(sniffer);

  setOperatingMode(OPM_STARTED);
}

void stopSniffing() {
  sniffing = false;
  setOperatingMode(OPM_STOPPING);
  // esp_wifi_set_promiscuous(false);
  // esp_wifi_set_promiscuous_rx_cb(NULL);
  // esp_wifi_stop();
  // esp_wifi_deinit();
}

char cmdBuffer[128];
int cmdLen = 9999;

void processSerial(int ch) {
  if (cmdLen >= sizeof(cmdBuffer)) {
    if (ch == '\n') {
      cmdLen = 0;
    }
    return;
  }
  if (ch != '\n') {
    if (ch >= 32) {
      cmdBuffer[cmdLen++] = ch;
    }
    return;
  }
  cmdBuffer[cmdLen] = 0;
  char* cmdEnd = strchr(cmdBuffer, '=');
  char* args = 0;
  if (cmdEnd == 0) {
    cmdEnd = cmdBuffer + cmdLen;
  } else {
    *cmdEnd = 0;
    args = cmdEnd + 1;
  }
  if (!strcmp(cmdBuffer, "filtermac")) {
    int mac1, mac2, mac3, mac4, mac5, mac6;
    sscanf(args, "%x:%x:%x:%x:%x:%x", &mac1, &mac2, &mac3, &mac4, &mac5, &mac6);
    filterByMac = true;
    filterMac[0] = mac1;
    filterMac[1] = mac2;
    filterMac[2] = mac3;
    filterMac[3] = mac4;
    filterMac[4] = mac5;
    filterMac[5] = mac6;
  } else if (!strcmp(cmdBuffer, "channel")) {
    sscanf(args, "%d", &currentChannel);
  } else if (!strcmp(cmdBuffer, "sizes")) {
    sscanf(args, "%d,%d,%d,%d", &capturePacketSize, &captureMgmtPacketSize, &captureLargeDataLimit, &captureLargeDataPacketSize);
  } else if (!strcmp(cmdBuffer, "scan")) {
    channelHopping = true;
  } else if (!strcmp(cmdBuffer, "full")) {
    fullData = true;
  } else if (!strcmp(cmdBuffer, "allbeacons")) {
    dropBeacons = false;
  } else if (!strcmp(cmdBuffer, "start")) {
    sscanf(args, "%ud", &timeOffset);
    int64_t now_usec = esp_timer_get_time();
    timeOffset -= (now_usec / 1000000);
    startSniffing();
  } else if (!strcmp(cmdBuffer, "stop")) {
    stopSniffing();
  }
  cmdLen = 0;
}

void setup() {
  pinMode(LED_BLUE, OUTPUT);
  pinMode(LED_RED, OUTPUT);
  pinMode(LED_GREEN, OUTPUT);
  setupTFT();
  setOperatingMode(OPM_INITIAL);

  Serial.begin(115200);
  Serial.println();
  Serial.printf("ESP32PCAP baudrate=%d\r\n", SERIAL_MAX_BAUDRATE);

  controlButton.setPressedHandler([](Button2 & b) {
    stopSniffing();
  });
}

void loop() {
  controlButton.loop();
  showOperatingMode();

  if (Serial.available() > 0) {
    processSerial(Serial.read());
  }

  if (channelHopping) {
    unsigned long currentTime = millis();
    if (currentTime - timeLastChannelChange >= HOP_INTERVAL){
      timeLastChannelChange = currentTime;
      if (++currentChannel > MAX_CHANNEL) {
        currentChannel = MIN_CHANNEL;
      }
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    }
  }
}

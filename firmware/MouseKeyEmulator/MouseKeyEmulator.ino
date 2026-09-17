/*
 * MouseKey Emulator - ESP32-S2 HID bridge firmware
 * ================================================
 *
 * The board plugs into the USB port of the machine you want to control and
 * appears there as an ordinary keyboard + mouse (see usb_descriptors.h -- the
 * USB identity is spoofed so nothing looks like an ESP32).  It joins your
 * Wi-Fi, listens for UDP packets from the control PC application and replays
 * them as real HID reports.
 *
 * Board:   ESP32-S2 (e.g. ESP32-S2-Saola / -FN4R2).  The S2 has a native
 *          USB-OTG peripheral, which is what lets it be a USB device at all.
 *
 * Arduino IDE setup  (esp32 core 3.x — uses the core's own USB stack,
 * NO extra library needed)
 * -----------------
 *   Tools -> Board            : "LOLIN S2 Mini"  (or "ESP32S2 Dev Module")
 *   Tools -> USB CDC On Boot  : "Disabled"       <-- IMPORTANT
 *   Tools -> USB Mode         : "USB-OTG (TinyUSB)"  (if the menu is shown)
 *   No Adafruit TinyUSB library required — remove it if previously installed.
 *
 * Why CDC On Boot must be "Disabled": with it Enabled the core starts USB at
 * boot using the board's own name ("LOLIN S2 Mini") BEFORE setup() runs, so the
 * spoofed identity below never takes effect.  With it Disabled we start USB
 * ourselves in setup(), after setting the identity, and bring up our own USB
 * serial console (see MKE_SERIAL_CONSOLE) so configuration still works.
 *
 * First run
 * ---------
 *   1. Flash.  2. Open Serial Monitor at 115200.  3. Configure over serial:
 *      ssid <name> / pass <secret> / key <shared-key> / save / connect.
 *      It prints the assigned IP.  4. In the PC app press "Найти в сети" or
 *      add that IP by hand.
 *
 * Protocol -- must stay in sync with app/core/protocol.py.
 */

#include "USB.h"
#include "USBHID.h"
#include "USBCDC.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <Preferences.h>
#include "usb_descriptors.h"

// ======================= serial console ====================================
// 1 = expose a USB serial console (needed to configure Wi-Fi / key).
// 0 = deployment build: no CDC at all, so the board appears as ONLY the
//     spoofed keyboard+mouse (no extra COM port) and cannot be reconfigured
//     over serial afterwards.
#define MKE_SERIAL_CONSOLE 1

#if MKE_SERIAL_CONSOLE
USBCDC Console(0);
#define LOGF(...)           Console.printf(__VA_ARGS__)
#define LOGLN(...)          Console.println(__VA_ARGS__)
#define LOGPR(x)            Console.print(x)
#define CONSOLE_AVAILABLE() Console.available()
#define CONSOLE_READ()      Console.read()
#else
#define LOGF(...)           ((void)0)
#define LOGLN(...)          ((void)0)
#define LOGPR(x)            ((void)0)
#define CONSOLE_AVAILABLE() (0)
#define CONSOLE_READ()      (-1)
#endif

// ======================= user configuration ================================
// You can hard-code your network here, or leave blank and configure it once
// over the serial console (commands: "ssid <name>", "pass <secret>", "save").
static const char *DEFAULT_WIFI_SSID = "";
static const char *DEFAULT_WIFI_PASS = "";
static const char *DEFAULT_SECRET    = "mousekey";   // must match the PC app
static const uint16_t LISTEN_PORT    = 45123;

// A friendly name reported to the PC app during discovery (not the USB name).
static const char *DEVICE_LABEL      = "ESP32-S2 Bridge";

// ======================= protocol (mirror of protocol.py) ==================
static const uint8_t  PROTO_MAGIC0 = 'M';
static const uint8_t  PROTO_MAGIC1 = 'K';
static const uint8_t  PROTO_VERSION = 1;
static const uint8_t  HEADER_SIZE  = 12;

enum : uint8_t {
  T_KEYBOARD    = 0x01,
  T_MOUSE       = 0x02,
  T_RELEASE_ALL = 0x03,
  T_PING        = 0x04,
  T_PONG        = 0x05,
  T_DISCOVER    = 0x06,
  T_HELLO       = 0x07,
  T_CONSUMER    = 0x08,
};

// ======================= HID setup =========================================
// Core-native composite HID device (keyboard + mouse + consumer).  The report
// descriptor lives in usb_descriptors.h as raw bytes.
USBHID HID;

class MouseKeyHID : public USBHIDDevice {
public:
  MouseKeyHID() {
    HID.addDevice(this, sizeof(MKE_HID_REPORT_DESCRIPTOR));
  }
  void begin() { HID.begin(); }
  bool ready() { return HID.ready(); }
  uint16_t _onGetDescriptor(uint8_t *buffer) override {
    memcpy(buffer, MKE_HID_REPORT_DESCRIPTOR, sizeof(MKE_HID_REPORT_DESCRIPTOR));
    return sizeof(MKE_HID_REPORT_DESCRIPTOR);
  }
  bool send(uint8_t report_id, const void *data, size_t len) {
    return HID.SendReport(report_id, data, len);
  }
};
MouseKeyHID mkhid;

// ======================= globals ===========================================
Preferences prefs;
WiFiUDP udp;
String wifiSsid, wifiPass, secret;
uint32_t sharedToken = 0;
char serialNumber[17];

uint8_t rxbuf[256];
uint32_t lastKeepaliveMs = 0;
uint32_t packetsHandled = 0;
volatile uint8_t lastDisconnectReason = 0;   // Wi-Fi failure code for diagnostics

// last keyboard report we sent, so we only emit HID on real change
uint8_t curMods = 0;
uint8_t curKeys[6] = {0};
uint8_t curButtons = 0;

// ======================= FNV-1a (mirror of protocol.token_of) ==============
static uint32_t fnv1a(const String &s) {
  uint32_t h = 0x811C9DC5UL;
  for (size_t i = 0; i < s.length(); ++i) {
    h ^= (uint8_t)s[i];
    h *= 0x01000193UL;
  }
  return h;
}

static uint32_t rd_u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// serial string is built from the MAC so multiple boards are distinct
static void buildSerial() {
  uint64_t mac = ESP.getEfuseMac();
  snprintf(serialNumber, sizeof(serialNumber), "%04X%08X",
           (uint16_t)(mac >> 32), (uint32_t)mac);
}

// ======================= HID emit helpers ==================================
static void sendKeyboard(uint8_t mods, const uint8_t keys[6]) {
  if (!mkhid.ready()) return;
  uint8_t report[8] = {0};
  report[0] = mods;                         // byte 1 is reserved (stays 0)
  for (int i = 0; i < 6; ++i) report[2 + i] = keys[i];
  mkhid.send(REPORT_ID_KEYBOARD, report, sizeof(report));
}

// HID mouse deltas are signed 8-bit; a larger move is split into steps so a big
// packet still lands accurately instead of being clamped to +/-127.
static void sendMouseSimple(uint8_t buttons, int16_t dx, int16_t dy,
                            int8_t wheel, int8_t pan) {
  if (!mkhid.ready()) return;
  if (dx == 0 && dy == 0) {
    uint8_t report[5] = {buttons, 0, 0, (uint8_t)wheel, (uint8_t)pan};
    mkhid.send(REPORT_ID_MOUSE, report, sizeof(report));
    return;
  }
  bool wheelSent = false;
  while (dx || dy) {
    int8_t sx = (dx > 127) ? 127 : (dx < -127) ? -127 : dx;
    int8_t sy = (dy > 127) ? 127 : (dy < -127) ? -127 : dy;
    bool last = (dx == sx && dy == sy);
    uint8_t report[5] = {buttons, (uint8_t)sx, (uint8_t)sy,
                         (uint8_t)((last && !wheelSent) ? wheel : 0),
                         (uint8_t)((last && !wheelSent) ? pan : 0)};
    mkhid.send(REPORT_ID_MOUSE, report, sizeof(report));
    if (last) wheelSent = true;
    dx -= sx;
    dy -= sy;
    if (dx || dy) delayMicroseconds(400);
  }
}

static void releaseAll() {
  curMods = 0;
  memset(curKeys, 0, sizeof(curKeys));
  curButtons = 0;
  if (mkhid.ready()) {
    uint8_t kbd[8] = {0};
    mkhid.send(REPORT_ID_KEYBOARD, kbd, sizeof(kbd));
    uint8_t mouse[5] = {0};
    mkhid.send(REPORT_ID_MOUSE, mouse, sizeof(mouse));
  }
}

// ======================= UDP packet handling ===============================
static void sendFrame(uint8_t type, const IPAddress &ip, uint16_t port,
                      const uint8_t *payload, uint16_t len, uint32_t seq) {
  uint8_t hdr[HEADER_SIZE];
  hdr[0] = PROTO_MAGIC0; hdr[1] = PROTO_MAGIC1;
  hdr[2] = PROTO_VERSION; hdr[3] = type;
  hdr[4] = sharedToken & 0xFF; hdr[5] = (sharedToken >> 8) & 0xFF;
  hdr[6] = (sharedToken >> 16) & 0xFF; hdr[7] = (sharedToken >> 24) & 0xFF;
  hdr[8] = seq & 0xFF; hdr[9] = (seq >> 8) & 0xFF;
  hdr[10] = (seq >> 16) & 0xFF; hdr[11] = (seq >> 24) & 0xFF;
  udp.beginPacket(ip, port);
  udp.write(hdr, HEADER_SIZE);
  if (payload && len) udp.write(payload, len);
  udp.endPacket();
}

static void sendPong(const IPAddress &ip, uint16_t port,
                     const uint8_t *tag, uint32_t seq) {
  uint8_t payload[9];
  memcpy(payload, tag, 8);
  payload[8] = mkhid.ready() ? 1 : 0;       // hid_ready flag read by the app
  sendFrame(T_PONG, ip, port, payload, sizeof(payload), seq);
}

static void sendHello(const IPAddress &ip, uint16_t port, uint32_t seq) {
  // payload: [ver][hid_ready][name\0][board-id\0]
  // The board id is the MAC-derived serial, unique per board, so the PC app
  // can distinguish several boards on the same LAN and bind to the right one.
  uint8_t payload[2 + 32 + 20];
  payload[0] = PROTO_VERSION;
  payload[1] = mkhid.ready() ? 1 : 0;
  size_t n = strlen(DEVICE_LABEL);
  if (n > 31) n = 31;
  memcpy(payload + 2, DEVICE_LABEL, n);
  size_t off = 2 + n;
  payload[off++] = 0;                       // end of name
  size_t idn = strlen(serialNumber);
  if (idn > 19) idn = 19;
  memcpy(payload + off, serialNumber, idn);
  off += idn;
  payload[off++] = 0;                       // end of board id
  sendFrame(T_HELLO, ip, port, payload, off, seq);
}

static void handlePacket(int len, const IPAddress &ip, uint16_t port) {
  if (len < HEADER_SIZE) return;
  if (rxbuf[0] != PROTO_MAGIC0 || rxbuf[1] != PROTO_MAGIC1) return;
  if (rxbuf[2] != PROTO_VERSION) return;
  uint32_t token = rd_u32(rxbuf + 4);
  if (token != sharedToken) return;             // wrong shared key -> ignore
  uint32_t seq = rd_u32(rxbuf + 8);
  uint8_t type = rxbuf[3];
  const uint8_t *p = rxbuf + HEADER_SIZE;
  int plen = len - HEADER_SIZE;

  switch (type) {
    case T_KEYBOARD:
      if (plen >= 8) {
        curMods = p[0];
        for (int i = 0; i < 6; ++i) curKeys[i] = p[2 + i];
        sendKeyboard(curMods, curKeys);
        packetsHandled++;
      }
      break;

    case T_MOUSE:
      if (plen >= 6) {
        curButtons = p[0];
        int16_t dx = (int16_t)(p[1] | (p[2] << 8));
        int16_t dy = (int16_t)(p[3] | (p[4] << 8));
        int8_t wheel = (int8_t)p[5];
        int8_t pan = (plen >= 7) ? (int8_t)p[6] : 0;
        sendMouseSimple(curButtons, dx, dy, wheel, pan);
        packetsHandled++;
      }
      break;

    case T_CONSUMER:
      if (plen >= 2 && mkhid.ready()) {
        uint8_t usage[2] = {p[0], p[1]};      // 16-bit consumer usage, LE
        mkhid.send(REPORT_ID_CONSUMER, usage, 2);
        delay(5);
        uint8_t zero[2] = {0, 0};
        mkhid.send(REPORT_ID_CONSUMER, zero, 2);
      }
      break;

    case T_RELEASE_ALL:
      releaseAll();
      break;

    case T_PING:
      sendPong(ip, port, p, seq);
      break;

    case T_DISCOVER:
      sendHello(ip, port, seq);
      break;

    default:
      break;
  }
}

// ======================= Wi-Fi =============================================
static void onWifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
    lastDisconnectReason = info.wifi_sta_disconnected.reason;
  }
}

// Turn a disconnect reason code into a human hint (common cases only).
static const char *wifiReasonHint(uint8_t reason) {
  switch (reason) {
    case 201: return "сеть не найдена — возможно это 5 ГГц (S2 их не видит) или вне зоны";
    case 15:  return "неверный пароль (таймаут рукопожатия)";
    case 2:
    case 202:
    case 203: return "ошибка авторизации — проверьте пароль/тип шифрования";
    case 200: return "слабый сигнал";
    default:  return "см. код ниже";
  }
}

static void connectWifi() {
  if (wifiSsid.length() == 0) {
    LOGLN("[wifi] SSID не задан. Введите: ssid <имя>, затем pass <пароль>, затем save");
    return;
  }
  LOGF("[wifi] Подключение к \"%s\"...\n", wifiSsid.c_str());
  lastDisconnectReason = 0;
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);                 // latency matters more than power here
  WiFi.begin(wifiSsid.c_str(), wifiPass.c_str());
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(250);
    LOGPR('.');
  }
  LOGLN();
  if (WiFi.status() == WL_CONNECTED) {
    udp.begin(LISTEN_PORT);
    LOGF("[wifi] Подключено. IP: %s  порт: %u\n",
                  WiFi.localIP().toString().c_str(), LISTEN_PORT);
    LOGF("[key ] Общий ключ: \"%s\" (token 0x%08X)\n",
                  secret.c_str(), sharedToken);
  } else {
    LOGF("[wifi] Не удалось подключиться (код %u: %s)\n",
                  lastDisconnectReason, wifiReasonHint(lastDisconnectReason));
    LOGLN("[wifi] Подсказка: команда \"scan\" покажет видимые 2.4 ГГц сети");
  }
}

// ======================= serial console ====================================
static void saveConfig() {
  prefs.begin("mke", false);
  prefs.putString("ssid", wifiSsid);
  prefs.putString("pass", wifiPass);
  prefs.putString("secret", secret);
  prefs.end();
  LOGLN("[cfg ] Сохранено во флеш");
}

static void loadConfig() {
  prefs.begin("mke", true);
  wifiSsid = prefs.getString("ssid", DEFAULT_WIFI_SSID);
  wifiPass = prefs.getString("pass", DEFAULT_WIFI_PASS);
  secret   = prefs.getString("secret", DEFAULT_SECRET);
  prefs.end();
  sharedToken = fnv1a(secret);
}

static void handleSerial() {
  static String line;
  while (CONSOLE_AVAILABLE()) {
    char c = CONSOLE_READ();
    if (c == '\n' || c == '\r') {
      line.trim();
      if (line.length()) {
        if (line.startsWith("ssid ")) {
          wifiSsid = line.substring(5); wifiSsid.trim();
          LOGLN("[cfg ] SSID установлен");
        } else if (line.startsWith("pass ")) {
          wifiPass = line.substring(5);
          LOGLN("[cfg ] Пароль установлен");
        } else if (line.startsWith("key ")) {
          secret = line.substring(4); secret.trim();
          sharedToken = fnv1a(secret);
          LOGF("[cfg ] Ключ установлен (token 0x%08X)\n", sharedToken);
        } else if (line == "save") {
          saveConfig();
        } else if (line == "connect") {
          connectWifi();
        } else if (line == "scan") {
          LOGLN("[scan] Поиск 2.4 ГГц сетей (ESP32-S2 видит только их)...");
          WiFi.mode(WIFI_STA);
          int n = WiFi.scanNetworks();
          if (n <= 0) {
            LOGLN("[scan] Сети не найдены. Плата далеко от роутера?");
          } else {
            for (int i = 0; i < n; ++i) {
              LOGF("  %-24s  %4d dBm  ch%-2d  %s\n",
                            WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i),
                            WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "open" : "secured");
            }
            LOGF("[scan] Найдено %d сетей. Если вашей тут нет — она 5 ГГц.\n", n);
          }
          WiFi.scanDelete();
        } else if (line == "status") {
          LOGF("[stat] Wi-Fi:%s IP:%s USB:%s пакетов:%u\n",
                        WiFi.status() == WL_CONNECTED ? "up" : "down",
                        WiFi.localIP().toString().c_str(),
                        mkhid.ready() ? "ready" : "no",
                        packetsHandled);
        } else {
          LOGLN("[help] ssid <n> | pass <p> | key <k> | save | connect | scan | status");
        }
      }
      line = "";
    } else if (line.length() < 128) {
      line += c;
    }
  }
}

// ======================= setup / loop ======================================
void setup() {
  buildSerial();

  // --- spoof the USB identity BEFORE the USB stack starts ---
  USB.VID(SPOOF_VENDOR_ID);
  USB.PID(SPOOF_PRODUCT_ID);
  USB.manufacturerName(SPOOF_MANUFACTURER);
  USB.productName(SPOOF_PRODUCT);
  USB.serialNumber(serialNumber);
  USB.usbVersion(0x0200);                    // USB 2.0
  USB.firmwareVersion(SPOOF_BCD_DEVICE);

#if MKE_SERIAL_CONSOLE
  Console.begin(115200);                     // our own CDC, under the spoofed id
#endif
  mkhid.begin();                             // register the composite HID
  USB.begin();                               // bring up USB with our identity

  delay(400);                                // let the host enumerate the CDC
  LOGLN();
  LOGLN("=== MouseKey Emulator - ESP32-S2 bridge ===");
  LOGF("[usb ] Представляюсь как %04X:%04X \"%s %s\" S/N %s\n",
                SPOOF_VENDOR_ID, SPOOF_PRODUCT_ID,
                SPOOF_MANUFACTURER, SPOOF_PRODUCT, serialNumber);

  WiFi.onEvent(onWifiEvent);            // capture disconnect reason for diagnostics
  loadConfig();
  connectWifi();
}

void loop() {
  handleSerial();

  if (WiFi.status() != WL_CONNECTED) {
    static uint32_t lastTry = 0;
    if (millis() - lastTry > 5000) {
      lastTry = millis();
      connectWifi();
    }
    delay(10);
    return;
  }

  int len = udp.parsePacket();
  if (len > 0) {
    int n = udp.read(rxbuf, sizeof(rxbuf));
    if (n > 0) handlePacket(n, udp.remoteIP(), udp.remotePort());
  }

  // nothing else to do; keep the loop tight for low latency
}

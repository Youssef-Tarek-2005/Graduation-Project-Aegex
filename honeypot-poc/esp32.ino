#include <WiFi.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <DHT.h>

// ---------- Wi-Fi / collector ----------
const char* WIFI_SSID = "YOUR_SSID";        // SSID of the Kali access point (2.4 GHz only)
const char* WIFI_PASS = "YOUR_PASSWORD";
const char* COLLECTOR = "http://KALI_IP:5000/event";  // replace KALI_IP with Kali's IP on the AP interface (ip -br addr)

// ---------- Static IP (optional; change the addresses to your Kali AP subnet first) ----------
// Start with false to test with DHCP. Once it connects, set to true if you want the fixed IP.
const bool USE_STATIC_IP = false;
IPAddress STATIC_IP(192, 168, 137, 241);
IPAddress GATEWAY(192, 168, 137, 1);     // Kali (access point)
IPAddress SUBNET(255, 255, 255, 0);
IPAddress DNS_SERVER(192, 168, 137, 1);

const unsigned long WIFI_CONNECT_TIMEOUT_MS = 20000;
const unsigned long WIFI_RETRY_INTERVAL_MS  = 15000;
unsigned long lastWifiRetryMs = 0;

// ---------- Sensors ----------
#define DHTPIN  4     // DHT22 DATA -> GPIO4
#define DHTTYPE DHT22
#define MQ2PIN  34    // MQ-2 A0 -> GPIO34 (ADC1, safe with Wi-Fi). MQ-2 powered from 3V3, so no divider

DHT dht(DHTPIN, DHTTYPE);

const unsigned long SENSOR_INTERVAL_MS = 2000;    // DHT22 needs >= 2 s between reads
const unsigned long REPORT_INTERVAL_MS = 10000;   // periodic sensor event to collector
const unsigned long MQ2_WARMUP_MS      = 60000;   // MQ-2 needs warm-up for stable values

float lastTemp = NAN;
float lastHum  = NAN;
int   lastGas  = 0;       // raw ADC 0-4095 (not ppm, uncalibrated)
unsigned long lastSensorMs = 0;
unsigned long lastReportMs = 0;

// ---------- Request-event queue ----------
const unsigned long FLUSH_INTERVAL_MS = 2000;
const int MAX_QUEUED = 40;

String eventQueue[MAX_QUEUED];
int queuedCount = 0;
unsigned long droppedCount = 0;   // events lost because the queue was full
unsigned long lastFlushMs = 0;

WebServer server(80);

// ---------- Helpers ----------
String clean(const String& s) {  // keep the JSON valid and short
  String out;
  out.reserve(s.length());
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    uint8_t u = (uint8_t)c;
    if (c == '\\')                out += '/';
    else if (c == '"')            out += '\'';
    else if (u < 0x20 || u >= 0x7F) out += '?';   // control / non-ASCII bytes from scanners
    else                          out += c;
  }
  if (out.length() > 120) out = out.substring(0, 120) + "...";
  return out;
}

String numOrNull(float v, int decimals) {
  return isnan(v) ? String("null") : String(v, decimals);
}

String methodName() {
  switch (server.method()) {
    case HTTP_GET:     return "GET";
    case HTTP_POST:    return "POST";
    case HTTP_PUT:     return "PUT";
    case HTTP_DELETE:  return "DELETE";
    case HTTP_OPTIONS: return "OPTIONS";
    case HTTP_HEAD:    return "HEAD";
    case HTTP_PATCH:   return "PATCH";
    default:           return "OTHER";
  }
}

int readGasRaw() {
  long sum = 0;
  for (int i = 0; i < 16; i++) {
    sum += analogRead(MQ2PIN);
    delayMicroseconds(200);
  }
  return (int)(sum / 16);
}

void updateSensors() {
  if (millis() - lastSensorMs < SENSOR_INTERVAL_MS) return;
  lastSensorMs = millis();

  float t = dht.readTemperature();
  float h = dht.readHumidity();
  lastTemp = isnan(t) ? NAN : t;   // NaN -> reported as null
  lastHum  = isnan(h) ? NAN : h;
  lastGas  = readGasRaw();
}

bool mq2Ready() {
  return millis() >= MQ2_WARMUP_MS;
}

String sensorJson() {
  return "\"temp_c\":" + numOrNull(lastTemp, 1) +
         ",\"hum_pct\":" + numOrNull(lastHum, 1) +
         ",\"gas_raw\":" + String(lastGas) +
         ",\"gas_ready\":" + String(mq2Ready() ? "true" : "false");
}

void postJson(const String& payload) {
  Serial.println(payload);
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.setConnectTimeout(800);
    http.setTimeout(800);
    http.begin(COLLECTOR);
    http.addHeader("Content-Type", "application/json");
    int code = http.POST(payload);
    if (code <= 0) {
      Serial.printf("POST failed: %s\n", HTTPClient::errorToString(code).c_str());
    }
    http.end();
  }
}

// ---------- Honeypot request logging (queued, non-blocking) ----------
void logEvent(const String& note) {
  if (queuedCount >= MAX_QUEUED) {
    droppedCount++;
    return;
  }
  eventQueue[queuedCount++] =
    "{\"ms\":" + String(millis()) +
    ",\"src\":\"" + server.client().remoteIP().toString() +
    "\",\"method\":\"" + methodName() +
    "\",\"uri\":\"" + clean(server.uri()) +
    "\",\"ua\":\"" + clean(server.header("User-Agent")) +
    "\",\"note\":\"" + clean(note) + "\"}";
}

void flushEvents() {
  if (queuedCount == 0 && droppedCount == 0) return;
  if (millis() - lastFlushMs < FLUSH_INTERVAL_MS) return;
  lastFlushMs = millis();

  String payload = "{\"type\":\"request_batch\",\"ms\":" + String(millis()) +
                   ",\"count\":" + String(queuedCount) +
                   ",\"dropped\":" + String(droppedCount) + "," +
                   sensorJson() + ",\"events\":[";
  for (int i = 0; i < queuedCount; i++) {
    if (i) payload += ",";
    payload += eventQueue[i];
    eventQueue[i] = "";            // free the memory
  }
  payload += "]}";

  queuedCount = 0;
  droppedCount = 0;
  postJson(payload);
}

// ---------- Pages ----------
void handleRoot() {
  logEvent("root page");
  server.send(200, "text/html",
    "<h1>SmartCam 2000</h1><p>Firmware 1.0.3</p>"
    "<a href='/login'>Admin login</a>");
}

void handleLogin() {
  if (server.method() == HTTP_POST) {
    logEvent("login attempt, username length " + String(server.arg("user").length()));
    server.send(401, "text/html", "<p>Invalid credentials</p>");
  } else {
    logEvent("login page");
    server.send(200, "text/html",
      "<form method='POST'>User <input name='user'> "
      "Pass <input name='pass' type='password'> <button>Login</button></form>");
  }
}

void handleStatus() {
  logEvent("status page");
  String body = "{\"device\":\"SmartCam 2000\",\"uptime_ok\":true," + sensorJson() + "}";
  server.send(200, "application/json", body);
}

void handleNotFound() {
  logEvent("unknown path");
  server.send(404, "text/plain", "Not found");
}

// ---------- Wi-Fi diagnostics ----------
void onWifiEvent(arduino_event_id_t event, arduino_event_info_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
    // Reason 15 = 4-way handshake timeout (usually wrong password),
    // 201 = AP not found, 202 = auth failed, 205 = connection failed
    Serial.printf("[WiFi] disconnected, reason=%d\n", info.wifi_sta_disconnected.reason);
  } else if (event == ARDUINO_EVENT_WIFI_STA_CONNECTED) {
    Serial.println("[WiFi] associated with AP");
  } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
    Serial.println("[WiFi] got IP");
  }
}

void scanNetworks() {
  Serial.println("Scanning...");
  int n = WiFi.scanNetworks();
  if (n <= 0) {
    Serial.println("No networks found");
    return;
  }
  bool found = false;
  for (int i = 0; i < n; i++) {
    Serial.printf("  %s  ch%d  RSSI %d\n", WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i));
    if (WiFi.SSID(i) == WIFI_SSID) found = true;
  }
  Serial.println(found ? "Target SSID FOUND in scan" : "Target SSID NOT found in scan");
}

bool connectWifi() {
  if (USE_STATIC_IP) {
    if (!WiFi.config(STATIC_IP, GATEWAY, SUBNET, DNS_SERVER)) {   // must come before begin()
      Serial.println("Static IP config failed");
    }
  }
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting");
  unsigned long t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < WIFI_CONNECT_TIMEOUT_MS) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("ESP32 IP: ");
    Serial.println(WiFi.localIP());
    return true;
  }
  Serial.printf("Connect failed, status=%d\n", WiFi.status());
  return false;
}

// ---------- Setup / loop ----------
void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\nBooting...");

  dht.begin();
  analogReadResolution(12);                         // 0-4095
  analogSetPinAttenuation(MQ2PIN, ADC_11db);        // full 0-3.3 V range

  WiFi.onEvent(onWifiEvent);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(500);

  scanNetworks();
  connectWifi();   // does not hang forever; loop() keeps retrying

  // Keep the User-Agent header so scanners (e.g. Nmap NSE) are identifiable
  const char* headerKeys[] = {"User-Agent"};
  server.collectHeaders(headerKeys, 1);

  server.on("/", handleRoot);
  server.on("/login", handleLogin);
  server.on("/status", handleStatus);
  server.onNotFound(handleNotFound);
  server.begin();
}

void loop() {
  server.handleClient();
  updateSensors();
  flushEvents();   // send queued request events in one batch

  // Retry Wi-Fi if it dropped or never connected
  if (WiFi.status() != WL_CONNECTED && millis() - lastWifiRetryMs >= WIFI_RETRY_INTERVAL_MS) {
    lastWifiRetryMs = millis();
    Serial.println("Wi-Fi not connected, rescanning...");
    WiFi.disconnect();
    scanNetworks();          // prints every visible network + FOUND / NOT found
    WiFi.scanDelete();
    WiFi.begin(WIFI_SSID, WIFI_PASS);
  }

  // Periodic sensor reading sent to the collector (separate from attack traffic)
  if (millis() - lastReportMs >= REPORT_INTERVAL_MS) {
    lastReportMs = millis();
    String payload = "{\"type\":\"sensor\",\"ms\":" + String(millis()) + "," + sensorJson() + "}";
    postJson(payload);
  }
}
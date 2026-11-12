"""Threat Intelligence & Reporting - the "Layered Knowledge Base".

Five layers, as in the architecture diagram: MITRE ATT&CK, OWASP IoT Top 10, CVE/NVD, CWE/CAPEC and threat-intel feeds.
This is a small curated seed shipped with the project. Extend it by appending KBEntry objects (or loading your own
JSON) and by pointing AEGEX_IP_BLOCKLIST at an IOC file; verify CVE details against NVD before acting on them."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from ..config import MOCK_BAD_IPS


@dataclass(frozen=True)
class KBEntry:
    id: str
    layer: str                       # mitre_attack | owasp_iot_top10 | cve_nvd | cwe_capec | threat_feeds
    title: str
    description: str
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {**asdict(self), "tags": list(self.tags)}


LAYER_TITLES = {
    "mitre_attack": "MITRE ATT&CK (tactics, techniques, procedures)",
    "owasp_iot_top10": "OWASP IoT Top 10 (common risks)",
    "cve_nvd": "CVE / NVD (vulnerabilities)",
    "cwe_capec": "CWE / CAPEC (weaknesses & attack patterns)",
    "threat_feeds": "Threat Intelligence Feeds (IOC, indicators, reports)",
}

_E = KBEntry
KNOWLEDGE_BASE: list[KBEntry] = [
    # --- MITRE ATT&CK ---------------------------------------------------------------------------------------------
    _E("T1595.002", "mitre_attack", "Active Scanning: Vulnerability Scanning", "Adversary probes many ports and services to find exploitable weaknesses before attacking.", ("scan", "port", "probe", "reconnaissance")),
    _E("T1498", "mitre_attack", "Network Denial of Service", "Flooding the target with traffic so legitimate users and sensors lose availability.", ("ddos", "flood", "denial", "traffic", "availability")),
    _E("T1499.004", "mitre_attack", "Endpoint DoS: Application or System Exploitation", "Exploiting a software flaw to crash or hang a service.", ("crash", "segfault", "exploit", "zero-day")),
    _E("T1110.001", "mitre_attack", "Brute Force: Password Guessing", "Repeated login attempts with common or default credentials.", ("brute", "password", "login", "credentials", "telnet", "ssh")),
    _E("T1078.001", "mitre_attack", "Valid Accounts: Default Accounts", "Abusing vendor default usernames and passwords.", ("default", "credentials", "admin", "root")),
    _E("T1105", "mitre_attack", "Ingress Tool Transfer", "Downloading malware or tools onto the device (wget/curl/tftp).", ("wget", "download", "malware", "mirai", "payload")),
    _E("T1059.004", "mitre_attack", "Command and Scripting Interpreter: Unix Shell", "Running shell commands on the compromised device.", ("shell", "command", "busybox", "sh")),
    _E("T1070.002", "mitre_attack", "Indicator Removal: Clear Linux or Mac System Logs", "Deleting logs to hide activity.", ("logs", "rm", "cover", "tracks")),
    _E("T1486", "mitre_attack", "Data Encrypted for Impact", "Encrypting device data and demanding payment for recovery.", ("ransomware", "encrypt", "locked", "ransom")),
    _E("T1490", "mitre_attack", "Inhibit System Recovery", "Deleting backups so data cannot be restored.", ("backup", "delete", "recovery", "ransomware")),
    _E("T1565.002", "mitre_attack", "Data Manipulation: Transmitted Data Manipulation", "Altering or spoofing data in transit, e.g. fake sensor readings.", ("spoof", "mqtt", "sensor", "manipulation", "telemetry")),
    _E("T0836", "mitre_attack", "Modify Parameter (ATT&CK for ICS)", "Changing device thresholds or configuration, e.g. alarm limits.", ("config", "threshold", "parameter", "alarm", "sensor")),
    _E("T1125", "mitre_attack", "Video Capture", "Accessing camera video or snapshots without authorization.", ("camera", "video", "rtsp", "stream", "snapshot")),
    _E("T1133", "mitre_attack", "External Remote Services", "Using exposed remote services (RTSP, SSH, Telnet, web UI) as an entry point.", ("remote", "rtsp", "telnet", "exposed")),
    _E("T1190", "mitre_attack", "Exploit Public-Facing Application", "Exploiting a vulnerability in an internet-reachable service.", ("exploit", "web", "cgi", "vulnerability", "zero-day")),
    # --- OWASP IoT Top 10 (2018) ----------------------------------------------------------------------------------
    _E("I1", "owasp_iot_top10", "Weak, Guessable, or Hardcoded Passwords", "Default or easily guessed credentials enable brute force and botnet takeover.", ("password", "default", "credentials", "mirai", "brute")),
    _E("I2", "owasp_iot_top10", "Insecure Network Services", "Unneeded or vulnerable services (Telnet, open RTSP/MQTT) exposed on the network.", ("telnet", "service", "port", "scan", "rtsp", "mqtt")),
    _E("I3", "owasp_iot_top10", "Insecure Ecosystem Interfaces", "Weak authentication or input validation in web, cloud or mobile interfaces.", ("web", "api", "interface", "authentication", "camera")),
    _E("I4", "owasp_iot_top10", "Lack of Secure Update Mechanism", "Firmware cannot be updated, or updates are unsigned.", ("firmware", "update", "download", "patch")),
    _E("I5", "owasp_iot_top10", "Use of Insecure or Outdated Components", "Old libraries and unpatched software with known flaws.", ("outdated", "component", "cve", "patch", "exploit")),
    _E("I7", "owasp_iot_top10", "Insecure Data Transfer and Storage", "Unencrypted data in transit or at rest (plain MQTT, readable storage).", ("mqtt", "encrypt", "storage", "transfer", "spoof")),
    _E("I8", "owasp_iot_top10", "Lack of Device Management", "No monitoring, logging or remote management of deployed devices.", ("management", "logging", "monitoring")),
    _E("I9", "owasp_iot_top10", "Insecure Default Settings", "Insecure out-of-the-box configuration and no way to harden it.", ("default", "settings", "config")),
    # --- CVE / NVD (well-known IoT examples) ------------------------------------------------------------------------
    _E("CVE-2017-17215", "cve_nvd", "Huawei HG532 remote code execution", "Router flaw exploited by Mirai-family botnets (Satori) for remote code execution.", ("router", "mirai", "rce", "botnet")),
    _E("CVE-2021-36260", "cve_nvd", "Hikvision camera command injection", "Unauthenticated command injection in the web server of many IP cameras.", ("camera", "hikvision", "command", "injection", "rce")),
    _E("CVE-2017-7921", "cve_nvd", "Hikvision camera authentication bypass", "Improper authentication allowing access to camera configuration and snapshots.", ("camera", "bypass", "authentication", "snapshot")),
    _E("CVE-2014-6271", "cve_nvd", "Shellshock (GNU Bash)", "Bash environment-variable code execution, abused through CGI scripts on embedded devices.", ("cgi", "bash", "shell", "exploit", "web")),
    # --- CWE / CAPEC -----------------------------------------------------------------------------------------------
    _E("CWE-798", "cwe_capec", "Use of Hard-coded Credentials", "Credentials embedded in firmware let anyone log in.", ("credentials", "hardcoded", "default", "password")),
    _E("CWE-521", "cwe_capec", "Weak Password Requirements", "The product does not enforce strong passwords.", ("password", "weak", "brute")),
    _E("CWE-306", "cwe_capec", "Missing Authentication for Critical Function", "A sensitive function (stream, config) works without login.", ("authentication", "camera", "stream", "config")),
    _E("CWE-78", "cwe_capec", "OS Command Injection", "User input reaches a shell command unfiltered.", ("command", "injection", "shell", "cgi")),
    _E("CWE-120", "cwe_capec", "Classic Buffer Overflow", "Copying input into a fixed buffer without checking its size; typical cause of device crashes.", ("overflow", "segfault", "crash", "exploit", "zero-day")),
    _E("CAPEC-300", "cwe_capec", "Port Scanning", "Attacker enumerates open ports and services.", ("scan", "port", "probe")),
    _E("CAPEC-125", "cwe_capec", "Flooding", "Overwhelming a service with requests to exhaust resources.", ("flood", "ddos", "traffic")),
    _E("CAPEC-49", "cwe_capec", "Password Brute Forcing", "Systematically trying credentials until one works.", ("brute", "password", "login")),
    _E("CAPEC-194", "cwe_capec", "Fake the Source of Data", "Injecting forged data (e.g. sensor values) that appears legitimate.", ("spoof", "sensor", "fake", "mqtt")),
    _E("CAPEC-100", "cwe_capec", "Overflow Buffers", "Sending oversized input to corrupt memory and take control.", ("overflow", "exploit", "buffer")),
    # --- Threat intelligence feeds ---------------------------------------------------------------------------------
    *[_E(f"IOC-{ip}", "threat_feeds", f"Malicious IP {ip}", "Known-bad address from the project's mock blocklist (RFC 5737 documentation range).", ("ioc", "ip", "blocklist", ip)) for ip in MOCK_BAD_IPS],
    _E("IOC-mirai-dropper", "threat_feeds", "Mirai dropper command pattern", "wget/busybox one-liners that download and run a Mirai binary.", ("ioc", "mirai", "wget", "busybox", "dropper")),
    _E("IOC-default-creds", "threat_feeds", "Botnet default-credential wordlist", "admin/admin, root/root, root/123456, admin/1234, support/support.", ("ioc", "credentials", "wordlist", "botnet")),
    _E("IOC-ransom-note", "threat_feeds", "Ransom-note and .locked file markers", "Files renamed to *.locked and README_RESTORE.txt dropped on the device.", ("ioc", "ransomware", "locked", "note")),
]

# One profile per attack scenario: what the analyzer and the blue-team report use.
CATEGORY_PROFILE: dict[str, dict] = {
    "vulnerability_scanning": {
        "title": "Vulnerability scanning", "base_severity": "low", "mitre": ["T1595.002"], "owasp": ["I2"], "cwe_capec": ["CAPEC-300"],
        "mitigations": ["Close or firewall unused ports and services.", "Rate-limit and alert on many-port connection attempts from one source.", "Add the scanning source to the blocklist."]},
    "ddos": {
        "title": "Denial of service (DDoS)", "base_severity": "high", "mitre": ["T1498"], "owasp": ["I2"], "cwe_capec": ["CAPEC-125"],
        "mitigations": ["Apply connection and bandwidth rate limits at the gateway.", "Put the device behind a firewall that drops unsolicited inbound traffic.", "Block the flooding sources and monitor device CPU and memory."]},
    "mirai_botnet": {
        "title": "Mirai-style botnet infection", "base_severity": "high", "mitre": ["T1110.001", "T1078.001", "T1105", "T1059.004"], "owasp": ["I1", "I2"], "cwe_capec": ["CWE-798", "CAPEC-49"],
        "mitigations": ["Change all default credentials and enforce strong passwords.", "Disable Telnet and expose SSH only through a VPN.", "Block the dropper URL and source IPs; re-flash an infected device."]},
    "ransomware": {
        "title": "Ransomware", "base_severity": "critical", "mitre": ["T1486", "T1490", "T1059.004"], "owasp": ["I1", "I7"], "cwe_capec": ["CWE-521"],
        "mitigations": ["Isolate the device from the network immediately.", "Restore from offline backups; do not pay the ransom.", "Rotate credentials and restrict write access to data directories."]},
    "sensor_manipulation": {
        "title": "Sensor / telemetry manipulation", "base_severity": "high", "mitre": ["T1565.002", "T0836"], "owasp": ["I7", "I9"], "cwe_capec": ["CAPEC-194"],
        "mitigations": ["Require authentication and TLS for MQTT; restrict who may publish to sensor topics.", "Lock alarm thresholds and alert on configuration changes.", "Disable unused BLE pairing and GATT write access."]},
    "unauthorized_camera_access": {
        "title": "Unauthorized camera access", "base_severity": "high", "mitre": ["T1125", "T1133", "T1078.001"], "owasp": ["I1", "I3"], "cwe_capec": ["CWE-306"],
        "mitigations": ["Require authentication on RTSP and snapshot URLs.", "Disable remote stream access or put it behind a VPN.", "Review camera access logs and rotate camera credentials."]},
    "zero_day_exploit": {
        "title": "Zero-day / unknown exploit", "base_severity": "critical", "mitre": ["T1190", "T1499.004"], "owasp": ["I4", "I5"], "cwe_capec": ["CWE-120", "CAPEC-100"],
        "mitigations": ["Isolate and snapshot the device for forensic analysis.", "Restrict the exposed service and apply virtual patching at the gateway.", "Report the crash trace to the vendor and monitor for new CVEs."]},
}

_BY_ID = {e.id: e for e in KNOWLEDGE_BASE}


def get_entries(ids: list[str]) -> list[KBEntry]:
    return [_BY_ID[i] for i in ids if i in _BY_ID]


def references_for(category: str) -> dict[str, list[dict]]:
    """Knowledge-base entries linked to an attack category, grouped by layer."""
    prof = CATEGORY_PROFILE.get(category)
    if not prof:
        return {}
    return {"mitre_attack": [e.to_dict() for e in get_entries(prof["mitre"])],
            "owasp_iot_top10": [e.to_dict() for e in get_entries(prof["owasp"])],
            "cwe_capec": [e.to_dict() for e in get_entries(prof["cwe_capec"])]}

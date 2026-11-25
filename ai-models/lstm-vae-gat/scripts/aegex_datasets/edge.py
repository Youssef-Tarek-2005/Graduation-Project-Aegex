"""Edge-IIoTset (Ferrag et al., 2022): one pcap per attack / per normal device, file-level labels."""
import os

import aegex_prep as ap

NAME = "edge"
TITLE = "Edge-IIoTset"
SOURCE = "Kaggle mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot"
ORDER = 20
ACTIVE = True

ZIP = "edge-IIotset.zip"
ORIGINALS = [ZIP]
_ATTACK = "Edge-IIoTset dataset/Attack traffic/"
_NORMAL = "Edge-IIoTset dataset/Normal traffic/"
SOURCES = {      # capture: (zip member, attack_class)  - only attacks inside the project scope
    "ransomware": (_ATTACK + "Ransomware attack.pcap", "ransomware"),
    "vulnerability_scanner": (_ATTACK + "Vulnerability scanner attack.pcap", "scanning"),
    "port_scanning": (_ATTACK + "Port Scanning attack.pcap", "scanning"),
    "os_fingerprinting": (_ATTACK + "OS Fingerprinting attack.pcap", "scanning"),
    "ddos_http": (_ATTACK + "DDoS HTTP Flood Attacks.pcap", "ddos"),
    "ddos_icmp": (_ATTACK + "DDoS ICMP Flood Attacks.pcap", "ddos"),
    "ddos_tcp_syn": (_ATTACK + "DDoS TCP SYN Flood Attacks.pcap", "ddos"),
    "ddos_udp": (_ATTACK + "DDoS UDP Flood Attacks.pcap", "ddos"),
}
for _dev in ["Distance", "Flame_Sensor", "Heart_Rate", "IR_Receiver", "Modbus", "Soil_Moisture",
             "Sound_Sensor", "Temperature_and_Humidity", "Water_Level", "phValue"]:
    SOURCES["normal_" + _dev.lower()] = (f"{_NORMAL}{_dev}/{_dev}.pcap", "benign")

BASELINE_NOTE = ("Edge-IIoTset ships attacks and normal traffic as separate captures, so near-perfect "
                 "scores are expected and partly reflect capture differences, not only attack behaviour.")
# NOTE most normal captures' test periods are only 4-20 minutes long (bursty recordings); only
# temperature_and_humidity spans hours. Slowed-down attacks are only built where they fit.
BENCH = {"bases": ["normal_water_level", "normal_temperature_and_humidity", "normal_soil_moisture",
                   "normal_sound_sensor"],
         "attacks": ["port_scanning", "os_fingerprinting", "vulnerability_scanner", "ransomware",
                     "ddos_http", "ddos_tcp_syn", "ddos_udp", "ddos_icmp"]}
QUOTED_RUN = "lstm_ae_v8__vae_v5"


def captures():
    return sorted(SOURCES, key=lambda n: -("ddos" in n))      # biggest first so the pool stays busy


def build(name):
    member, cls = SOURCES[name]
    epath, emember = ap.locate(ZIP, member)
    df, st = ap.build_flows_from_pcap(epath, member=emember, log=lambda m: ap.log(f"[edge/{name}]", m))
    # Edge-IIoTset labels are per file: every packet in an attack file is labelled attack
    # (verified: Attack_label == 1 for all rows of every in-scope attack CSV).
    is_att = int(cls != "benign")
    df["is_attack"], df["mal_frac"] = is_att, float(is_att)
    df["attack_class"], df["campaign"] = cls, ""
    df["original_label"] = os.path.basename(member)
    st["label_source"] = "file-level (official Edge-IIoTset labelling)"
    return df, st

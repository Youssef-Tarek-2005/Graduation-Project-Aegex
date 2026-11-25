"""Gotham Dataset 2025 (Belarbi et al., Zenodo 10.5281/zenodo.14502760, CC BY 4.0).

78 simulated IoT devices; one capture per scenario = merged + de-duplicated per-device pcaps, labelled
with the official labeller's IP rules (exact-IP matching). The pcap merge / labeller is pcap_labeller.py.
"""
import os

import aegex_prep as ap

from . import pcap_labeller as ag

NAME = "gotham"
TITLE = "Gotham 2025"
SOURCE = "Zenodo 10.5281/zenodo.14502760 (GothamDataset2025.zip, put in gotham_2025/)"
ORDER = 50
ACTIVE = False                 # trained and benchmarked on its own (model run *_gotham_v1)
ORIGINALS = [ag.ORIGINAL_NAME]  # stored in a sub-folder, key in ORIGINALS_SHA256.txt

# Separate scenario captures (ag.SCENARIOS); the 2 h benign capture (78 devices) is the normal base.
# Merlin C&C ('other') is out of scope and not injected.
BENCH = {"bases": ["benign"],
         "attacks": ["network_scanning", "mirai_infection", "mirai_dos", "coap_amplification", "merlin"],
         "classes": ["scanning", "ddos", "mirai"]}
QUOTED_RUN = "lstm_ae_gotham_v1__vae_gotham_v1__recal_dev"

_ORDER = ["mirai-dos", "benign", "mirai-infection", "merlin", "network-scanning", "coap-amplificator"]  # biggest first


def _zip():
    return os.path.join(ap.DATA_DIR, ag.ZIP)


def captures():
    """Scenario folders present in the zip (capture name = ag.SCENARIOS[scenario])."""
    avail = ag.list_members(_zip())
    return [s for s in _ORDER if s in avail]


def build(scenario, zip_path=None):
    zip_path = zip_path or _zip()
    members = ag.list_members(zip_path)[scenario]
    name = ag.SCENARIOS[scenario]
    df, st = ag.build_scenario_flows(zip_path, scenario, members, log=lambda m: ap.log(f"[gotham/{name}]", m))
    st["label_source"] = "official Gotham labeller rules (othmbela/gotham-network-packet-labeller metadata), " \
                         "exact-IP matching; Unknown packets treated as benign"
    return df, st


def capture_name(scenario):
    """Zip folder name -> capture name used under preprocessed/ (e.g. mirai-dos -> mirai_dos)."""
    return ag.SCENARIOS[scenario]

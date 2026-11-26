"""Flow features: 41 numbers per network connection (contract -> flow_features).

    9 numbers that describe the connection      duration, bytes and packets each way, speed, direction, packet size
    4 proto        one-hot                      tcp udp icmp other
   11 service      one-hot                      http ssh telnet mqtt dns rtsp ssl dhcp ntp other none
   14 conn_state   one-hot                      how the connection went (SF = normal open+close, S0 = no answer, ...)
    3 port class   one-hot                      well_known (<1024), registered (<49152), dynamic
   --
   41

What is stored in flows.features is the vector after three fixed steps:
  1. fill:      a missing value (Zeek's "-", saved as NULL in step 5) becomes 0, as the contract says
  2. derive:    bytes_per_sec, pkts_per_sec, bytes_ratio_out, mean_pkt_size_orig
  3. transform: log1p on the "big" numbers, so 100 bytes and 10 MB end up 4.6 and 16.1 apart, not 10 million
It is NOT scaled yet. The scaler is fitted in step 9 on the training data only, and C/D apply it on top. Keeping
the stored vector free of anything fitted means it never changes when the split changes.
The raw values stay readable in the flows columns (orig_bytes, duration_s, ...).

No identifiers are features: no IPs, no ports (only the port's class), no times, no IDs, no labels.
"""
from __future__ import annotations

import math
from typing import Any, Mapping

from ingest.event import CONTRACT

FEATURE_VERSION: str = CONTRACT["feature_version"]
SPEC = CONTRACT["flow_features"]
VOCAB: dict[str, list[str]] = CONTRACT["categorical_vocabularies"]

NUMERIC: list[str] = [f["name"] for f in SPEC["numeric"]]
TRANSFORM: dict[str, str] = {f["name"]: f["transform"] for f in SPEC["numeric"]}
ONE_HOT: list[str] = [f["name"] for f in SPEC["one_hot"]]
FEATURE_NAMES: list[str] = NUMERIC + [f"{group}_{value}" for group in ONE_HOT for value in VOCAB[group]]
assert len(FEATURE_NAMES) == SPEC["dimension"], f"contract says {SPEC['dimension']} flow features, built {len(FEATURE_NAMES)}"

# Zeek recognises RTSP (the camera stream) as http, because the two look alike. On the RTSP ports we call it rtsp,
# so the models can tell "someone is watching the camera" from "someone is browsing a web page".
RTSP_PORTS = {554, 8554}


def _num(v: Any) -> float:
    """Missing, NaN or negative -> 0 (contract: fill_missing = 0). Byte and packet counts can't be negative."""
    if v is None:
        return 0.0
    v = float(v)
    return 0.0 if math.isnan(v) or v < 0 else v


def raw_numeric(duration_s: Any, orig_bytes: Any, resp_bytes: Any, orig_pkts: Any, resp_pkts: Any) -> dict[str, float]:
    """The 9 numbers before the transform. Formulas are exactly the contract's `from` column."""
    dur, ob, rb, op, rp = map(_num, (duration_s, orig_bytes, resp_bytes, orig_pkts, resp_pkts))
    return {
        "duration_s": dur,
        "orig_bytes": ob,
        "resp_bytes": rb,
        "orig_pkts": op,
        "resp_pkts": rp,
        "bytes_per_sec": (ob + rb) / max(dur, 0.001),
        "pkts_per_sec": (op + rp) / max(dur, 0.001),
        "bytes_ratio_out": ob / (ob + rb + 1),          # 0 = all data came back, close to 1 = all data went out
        "mean_pkt_size_orig": ob / max(op, 1),
    }


def _transform(name: str, value: float) -> float:
    kind = TRANSFORM[name]
    if kind == "log1p":
        return math.log1p(value)
    if kind == "none":
        return value
    raise ValueError(f"unknown transform {kind!r} for {name} in the contract")


def categories(proto: Any, service: Any, conn_state: Any, dst_port: Any) -> dict[str, str | None]:
    """Each one-hot group's value, mapped onto the contract's fixed vocabulary.
    Unseen values -> 'other'. Missing service -> 'none'. Missing port -> None (all three port columns 0)."""
    p = str(proto).lower() if proto else ""
    proto_v = p if p in VOCAB["proto"] else "other"

    # Zeek writes several services comma-separated ("ssl,http"); the first one counts. A leading "-" means
    # Zeek tried that analyzer and it failed, so it's not really that service.
    first = str(service).split(",")[0].strip().lower() if service else ""
    first = "" if first.startswith("-") else first
    port = int(dst_port) if dst_port is not None else None
    if port in RTSP_PORTS and first in ("", "http"):
        first = "rtsp"
    service_v = "none" if not first else (first if first in VOCAB["service"] else "other")

    state_v = conn_state if conn_state in VOCAB["conn_state"] else "other"

    if port is None:
        port_v = None
    else:
        port_v = "well_known" if port < 1024 else "registered" if port < 49152 else "dynamic"
    return {"proto": proto_v, "service": service_v, "conn_state": state_v, "dst_port_class": port_v}


def flow_features(flow: Mapping[str, Any]) -> dict[str, float]:
    """One flow (a flows row or a Flow as a dict) -> the 41 features, keyed by name, in contract order."""
    raw = raw_numeric(flow.get("duration_s"), flow.get("orig_bytes"), flow.get("resp_bytes"),
                      flow.get("orig_pkts"), flow.get("resp_pkts"))
    out = {name: _transform(name, raw[name]) for name in NUMERIC}
    cats = categories(flow.get("proto"), flow.get("service"), flow.get("conn_state"), flow.get("dst_port"))
    for group in ONE_HOT:
        for value in VOCAB[group]:
            out[f"{group}_{value}"] = 1.0 if cats[group] == value else 0.0
    return out


def to_vector(features: Mapping[str, float]) -> list[float]:
    """Dict keyed by name -> plain list in contract order (what a model actually receives)."""
    return [float(features[name]) for name in FEATURE_NAMES]


# If someone edits the numeric list in the contract, the formulas above must be edited too. Fail loudly at import.
assert list(raw_numeric(0, 0, 0, 0, 0)) == NUMERIC, \
    f"contract numeric flow features {NUMERIC} don't match raw_numeric(); update features/flow.py"

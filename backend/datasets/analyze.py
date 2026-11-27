"""Step 1 - dataset analysis: which public datasets we have, and real numbers measured from them.

    cd backend
    $env:AEGEX_DATA = "C:\\aegex_data"                       # folder with the downloaded original files
    .venv\\Scripts\\python -m datasets.analyze                # every dataset in the catalogue
    .venv\\Scripts\\python -m datasets.analyze --datasets kitsune xiiotid --quick

What it does, in 4 steps:
  1. reads the catalogue, datasets/sources.json (the AI team's DATASET_SOURCES.json, unchanged)
  2. checks every original file of every dataset in AEGEX_DATA: there? right size? right SHA-256?
  3. every capture whose files are there is read with the AI team's own adapter
     (ai-models/lstm-vae-gat/scripts/aegex_datasets) into their shared flow table, and measured:
     connections, attack share, classes, hosts, time span, protocols, relabelled rows, missing values
  4. writes datasets/report/datasets_report.md (tables for the slides) and datasets_report.json

Numbers in the report are MEASURED from the files on this PC. Numbers in the AI team's documents
(DATASETS_AND_PREPROCESSING.md) are REPORTED; the report keeps the two apart.
Nothing is written into AEGEX_DATA; the original files are only read.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
AI_SCRIPTS = REPO / "ai-models" / "lstm-vae-gat" / "scripts"
CATALOGUE = HERE / "sources.json"
REPORT_DIR = HERE / "report"
DEFAULT_DATA = Path(os.environ.get("AEGEX_DATA") or r"C:\aegex_data")
LAN = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]


# --------------------------------------------------------------------------- 1. catalogue
def load_catalogue(path: Path = CATALOGUE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def used_files(ds: dict) -> list[dict]:
    """The original files the AI team actually used (the catalogue also lists unused ones)."""
    return [f for f in ds["files"] if f.get("used") and not f["file"].endswith("/")
            and " and " not in f["file"]]


# --------------------------------------------------------------------------- 2. are the files here?
def sha256(path: Path, block: int = 1 << 22) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(block), b""):
            h.update(b)
    return h.hexdigest()


def find(data_dir: Path, name: str) -> tuple[Path | None, bool]:
    """-> (path, unpacked). Looks for the file itself anywhere under data_dir, then for an unpacked
    copy (Mirai_pcap.pcap.zip -> Mirai_pcap.pcap), like the AI team's aegex_prep.locate()."""
    base = Path(name).name
    direct = data_dir / name
    if direct.is_file():
        return direct, False
    hits = sorted(data_dir.rglob(base), key=lambda p: len(str(p)))
    if hits:
        return hits[0], False
    if base.lower().endswith(".zip"):
        hits = sorted(data_dir.rglob(base[:-4]), key=lambda p: len(str(p)))
        if hits:
            return hits[0], True
    return None, False


def check_file(data_dir: Path, entry: dict, quick: bool = False) -> dict:
    """Status of one original file: verified / present / unpacked / size mismatch / checksum mismatch / missing."""
    out = {"file": entry["file"], "expected_bytes": entry.get("size_bytes"), "expected_sha256": entry.get("sha256")}
    path, unpacked = find(data_dir, entry["file"])
    if path is None:
        return {**out, "status": "missing"}
    out.update(path=str(path), bytes=path.stat().st_size)
    if unpacked:                                   # the zip's content, not the zip: no checksum to compare
        return {**out, "status": "unpacked"}
    if entry.get("size_bytes") and out["bytes"] != entry["size_bytes"]:
        return {**out, "status": "size mismatch"}
    if quick or not entry.get("sha256"):
        return {**out, "status": "present"}
    ok = sha256(path) == entry["sha256"].lower()
    return {**out, "status": "verified" if ok else "checksum mismatch"}


# --------------------------------------------------------------------------- 3. measure
def load_adapters(data_dir: Path):
    """The AI team's dataset adapters, pointed at data_dir. aegex_prep reads AEGEX_DATA when imported."""
    os.environ["AEGEX_DATA"] = str(data_dir)
    if str(AI_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(AI_SCRIPTS))
    import aegex_datasets
    return aegex_datasets


def is_lan(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in LAN)


def summarize(df) -> dict:
    """Numbers for one capture, from a flow table in the AI team's FLOW_COLUMNS layout."""
    n = len(df)
    ips = set(df["src_ip"].dropna().astype(str)) | set(df["dst_ip"].dropna().astype(str))
    attack = df[df["is_attack"] == 1]
    t0, t1 = (float(df["ts"].min()), float(df["ts_end"].max())) if n else (None, None)
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if t is not None else None
    note = df["label_note"].fillna("").astype(str) if "label_note" in df else None
    return {
        "flows": n,
        "attack_flows": len(attack),
        "attack_share": round(len(attack) / n, 4) if n else 0.0,
        "classes": {str(k): int(v) for k, v in df["attack_class"].value_counts().items()},
        "hosts": len(ips),
        "lan_hosts": sum(is_lan(ip) for ip in ips),
        "attack_sources": sorted(map(str, attack["src_ip"].dropna().unique()))[:20],
        "n_attack_sources": int(attack["src_ip"].nunique()),
        "protocols": {str(k): int(v) for k, v in df["proto"].value_counts().items()},
        "packets": int(df["fwd_pkts"].sum() + df["bwd_pkts"].sum()),
        "bytes": int(df["fwd_bytes"].sum() + df["bwd_bytes"].sum()),
        "start_utc": iso(t0), "end_utc": iso(t1),
        "span_hours": round((t1 - t0) / 3600, 2) if n else 0.0,
        "relabelled_flows": int((note != "").sum()) if note is not None else 0,   # rows with a label note
        "label_notes": sorted(set(note[note != ""]))[:5] if note is not None else [],
        "missing_values": {c: int(df[c].isna().sum()) for c in ("ts", "src_ip", "dst_ip", "proto")
                           if c in df and int(df[c].isna().sum())},
        "_ips": ips,                               # for the dataset total; removed before saving
    }


def combine(caps: dict) -> dict:
    """Dataset total from its measured captures (hosts are a union, not a sum)."""
    ok = [c for c in caps.values() if "flows" in c]
    if not ok:
        return {}
    classes: dict = {}
    for c in ok:
        for k, v in c["classes"].items():
            classes[k] = classes.get(k, 0) + v
    ips = set().union(*(c["_ips"] for c in ok))
    flows, attacks = sum(c["flows"] for c in ok), sum(c["attack_flows"] for c in ok)
    return {"captures": len(ok), "flows": flows, "attack_flows": attacks,
            "attack_share": round(attacks / flows, 4) if flows else 0.0, "classes": classes,
            "hosts": len(ips), "lan_hosts": sum(is_lan(ip) for ip in ips),
            "relabelled_flows": sum(c["relabelled_flows"] for c in ok)}


def measure(reg, name: str, log=print) -> dict:
    """Read every capture of one dataset with its adapter. Missing files -> that capture is skipped."""
    mod = reg.get(name)
    if hasattr(mod, "run"):
        return {"_note": "streaming adapter (file too big for one table): measure it with the AI team's "
                         f"step1_flows.py --datasets {name}"}
    try:
        captures = list(mod.captures())
    except FileNotFoundError as e:
        return {"_note": f"files missing: {e}"}
    out = {}
    for cap in captures:
        t = time.time()
        try:
            df, _ = mod.build(cap)
        except FileNotFoundError as e:
            out[str(cap)] = {"status": "files missing", "detail": str(e).split(" not found")[0]}
            continue
        except Exception as e:                     # one broken capture must not stop the others
            out[str(cap)] = {"status": "error", "detail": f"{type(e).__name__}: {e}"}
            continue
        out[str(cap)] = {"status": "measured", **summarize(df)}
        log(f"  [{name}/{cap}] {len(df):,} connections in {time.time() - t:.0f} s")
    return out


# --------------------------------------------------------------------------- 4. report
def gb(b) -> str:
    return "-" if not b else f"{b / 1e9:.2f} GB" if b >= 1e8 else f"{b / 1e6:.1f} MB"


def classes_text(classes: dict) -> str:
    return ", ".join(f"{k} {v:,}" for k, v in sorted(classes.items(), key=lambda kv: -kv[1]))


def render(report: dict) -> str:
    L = ["# Dataset analysis (Step 1)", "",
         f"Generated {report['generated']} from `{report['data_dir']}`. Catalogue: `backend/datasets/sources.json` "
         f"(AI team, {report['catalogue_date']}).", "",
         "**Measured** = counted by `python -m datasets.analyze` from the files on this PC. "
         "**Reported** = taken from the AI team's documents, not re-counted here.", "",
         "## 1. The datasets (catalogue)", "",
         "| Dataset | Source | Download (used files) | Labels | Used by models | Files here |",
         "|---|---|---|---|---|---|"]
    for d in report["datasets"]:
        have = sum(f["status"] in ("verified", "present", "unpacked") for f in d["files"])
        L.append(f"| {d['name']} | {d['host']} `{d['slug']}` | {gb(d['size_bytes'])} | {d['label_method']} | "
                 f"{', '.join(d['models'])} | {have} / {len(d['files'])} |")

    L += ["", "## 2. Measured", ""]
    rows = [(d, cap, c) for d in report["datasets"] for cap, c in d["captures"].items() if c.get("status") == "measured"]
    if rows:
        L += ["Connections = two-way flows made by the AI team's adapter (the unit the models use). Hosts = every "
              "IP address seen, including addresses that were only probed by a scan.", "",
              "| Dataset | Capture | Connections | Attack connections | Classes | Hosts (LAN) | Attack sources | "
              "Time span (UTC) | Rows with a label note |", "|---|---|---|---|---|---|---|---|---|"]
        for d, cap, c in rows:
            L.append(f"| {d['name']} | {cap} | {c['flows']:,} | {c['attack_flows']:,} ({c['attack_share']:.1%}) | "
                     f"{classes_text(c['classes'])} | {c['hosts']} ({c['lan_hosts']}) | {c['n_attack_sources']} | "
                     f"{c['start_utc']} → {c['end_utc']} ({c['span_hours']} h) | {c['relabelled_flows']:,} |")
        L += ["", "Protocols and data quality per capture:", ""]
        for d, cap, c in rows:
            miss = ", ".join(f"{k} {v:,}" for k, v in c["missing_values"].items()) or "none"
            L.append(f"- **{d['name']} / {cap}**: protocols {classes_text(c['protocols'])}; "
                     f"{c['packets']:,} packets, {gb(c['bytes'])}; missing values: {miss}; "
                     f"attack sources: {', '.join(c['attack_sources']) or '-'}.")
            for n in c.get("label_notes", []):
                L.append(f"  - label note: {n}")
    else:
        L.append("Nothing measured yet: no dataset files found in the data folder.")

    L += ["", "## 3. Still to download", ""]
    for d in report["datasets"]:
        miss = [f for f in d["files"] if f["status"] == "missing"]
        bad = [f for f in d["files"] if f["status"] in ("size mismatch", "checksum mismatch")]
        if not miss and not bad:
            continue
        size = sum(f["expected_bytes"] or 0 for f in miss)
        L.append(f"- **{d['name']}** ({len(miss)} file(s), {gb(size)}): {d['url']}")
        if d["host"] == "kaggle" and len(miss) <= 6:
            for f in miss:
                L.append(f"  - `kaggle datasets download -d {d['slug']} -f \"{f['file']}\" -p {report['data_dir']}`")
        for f in bad:
            L.append(f"  - ⚠ `{f['file']}`: {f['status']} - download it again")

    L += ["", "## 4. Rejected by the AI team (reported)", ""]
    L += [f"- {r['name']}: {r['reason']}" for r in report["rejected"]]
    return "\n".join(L) + "\n"


def to_json(obj):
    """Drop the helper '_ips' sets before saving."""
    if isinstance(obj, dict):
        return {k: to_json(v) for k, v in obj.items() if k != "_ips"}
    if isinstance(obj, list):
        return [to_json(v) for v in obj]
    return obj


# --------------------------------------------------------------------------- main
def analyze(data_dir: Path, only: list[str] | None = None, quick: bool = False, log=print) -> dict:
    cat = load_catalogue()
    reg = None
    out = []
    for ds in cat["datasets"]:
        if only and ds["id"] not in only:
            continue
        files = [check_file(data_dir, f, quick) for f in used_files(ds)]
        log(f"{ds['id']}: {sum(f['status'] != 'missing' for f in files)} / {len(files)} files here")
        captures: dict = {}
        if any(f["status"] in ("verified", "present", "unpacked") for f in files):
            reg = reg or load_adapters(data_dir)
            captures = measure(reg, ds["id"], log)
        out.append({"id": ds["id"], "name": ds["name"], "host": ds["host"],
                    "slug": ds.get("kaggle_slug") or ds.get("url"), "url": ds["url"],
                    "size_bytes": sum(f.get("size_bytes") or 0 for f in used_files(ds)) or ds.get("total_size_bytes_approx"),
                    "label_method": ds["labelling"]["method"], "models": ds.get("used_by_models", []),
                    "files": files, "captures": captures, "total": combine(captures)})
    return {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "data_dir": str(data_dir),
            "catalogue_date": cat.get("generated"), "datasets": out, "rejected": cat.get("rejected_datasets", [])}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--data", type=Path, default=DEFAULT_DATA, help="folder with the original files (AEGEX_DATA)")
    p.add_argument("--datasets", nargs="+", help="catalogue ids, e.g. kitsune xiiotid (default: all)")
    p.add_argument("--quick", action="store_true", help="check sizes only, skip SHA-256 (big files)")
    p.add_argument("--out", type=Path, default=REPORT_DIR)
    a = p.parse_args(argv)
    if not a.data.is_dir():
        p.error(f"data folder {a.data} does not exist (set AEGEX_DATA or pass --data)")
    report = analyze(a.data, a.datasets, a.quick)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "datasets_report.json").write_text(json.dumps(to_json(report), indent=1), encoding="utf-8")
    (a.out / "datasets_report.md").write_text(render(report), encoding="utf-8")
    print(f"report: {a.out / 'datasets_report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

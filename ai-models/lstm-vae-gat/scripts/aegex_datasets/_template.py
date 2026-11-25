"""
TEMPLATE - copy to <name>.py (no leading underscore) to add a dataset. Nothing else needs editing:
step 1-5, training, the benchmark and the results summary pick it up from this package.

Checklist
  1. put the original files in the data folder (AEGEX_DATA, default the project folder), never modify them
  2. add their SHA-256 to ORIGINALS_SHA256.txt  (Get-FileHash <file> -Algorithm SHA256)
  3. fill in this module; build() must return flows in aegex_prep.FLOW_COLUMNS (see the existing plug-ins:
     pcap -> kitsune.py / edge.py, Zeek -> iot23.py, NetFlow CSV -> nf_toniot.py, CICFlowMeter CSV -> aci.py)
  4. python step1_flows.py --datasets <name>, then step2_features.py / step3_sequences_graphs.py the same way
  5. optional: BENCH (realistic benchmark), QUOTED_RUN (after you benchmarked a model on it)
"""
import aegex_prep as ap

NAME = "mydataset"                 # folder name under preprocessed/flows, windows, graphs
TITLE = "My Dataset"
SOURCE = "where to download it (URL / Kaggle slug), licence"
ORDER = 900                        # position in the dataset lists
ACTIVE = False                     # True = part of the default pipeline / training run
ORIGINALS = ["my_dataset.zip"]     # file names as listed in ORIGINALS_SHA256.txt

BASELINE_NOTE = ""                 # one sentence shown with the step 5 baseline (optional)
CROSS_CAPTURE = []                 # captures for the leave-one-capture-out baseline (optional)
BENCH = None                       # realistic-benchmark case, see aegex_bench.py / the other plug-ins
QUOTED_RUN = None                  # model_results/benchmark/<folder> quoted on the results page


def captures():
    """Capture names, processed in this order (biggest first keeps the worker pool busy)."""
    return ["all"]


def build(capture):
    """One capture -> (flows DataFrame with aegex_prep.FLOW_COLUMNS, stats dict incl. 'label_source').
    Columns `dataset` / `capture` are filled in by step 1. Read originals only through ap.locate(),
    ap.open_maybe_zip() or ap.read_original_bytes() so nothing is ever extracted or modified."""
    raise NotImplementedError

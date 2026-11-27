# backend/datasets: the public IoT datasets (Step 1)

| File | What it is |
|---|---|
| `sources.json` | The AI team's dataset catalogue (`DATASET_SOURCES.json`, 26 Nov 2026, unchanged). For each dataset: download link, exact files, sizes, SHA-256, label mapping and the models that used it. It also lists the 5 rejected datasets. |
| `DATASETS_AND_PREPROCESSING.md` | The AI team's write-up (unchanged): how each dataset was labelled and preprocessed. Its numbers are **reported**. |
| `analyze.py` | Step 1: checks which files you have and **measures** them. |
| `report/datasets_report.md` | The output: tables you can paste into slides. `.json` holds the same data. |

## Where the data goes

The originals are about 40 GB, so keep them **outside the project folder**. The project is in OneDrive, which
would upload them to the cloud. Use `C:\aegex_data\` (the default) or set `AEGEX_DATA`. Put every file in that
folder as downloaded, except Gotham, which goes in `gotham_2025\`. Nothing here ever writes into it.

Kitsune Mirai also needs the AI team's behaviour relabel. Make it once:

```powershell
.venv\Scripts\python -I ..\ai-models\lstm-vae-gat\scripts\aegex_datasets\kitsune\relabel_mirai.py C:\aegex_data\Mirai_pcap.pcap.zip C:\aegex_data\mirai_labels.csv.zip C:\aegex_data\kitsune_mirai_relabeled
```

## Run it

```powershell
cd backend
.venv\Scripts\python -m datasets.analyze                          # all datasets, SHA-256 checked
.venv\Scripts\python -m datasets.analyze --datasets kitsune --quick  # one dataset, sizes only
```

Each capture is read with the AI team's own adapter (`ai-models/lstm-vae-gat/scripts/aegex_datasets`), so the
counts use the same unit as the models: two-way connections. Captures whose files are missing are skipped, and
the report lists what is still to download, with the `kaggle` commands.

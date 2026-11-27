# Trained artifacts

Copy these out of your local run. Every file is small — the largest is a few
hundred KB — so they belong in git.

The anomaly-detection layer (LSTM autoencoder → VAE → temporal GAT) keeps its own
trained bundles in `../lstm-vae-gat/models/`.

From `PoC_results/`:

    type_classifier.keras
    type_scaler.pkl
    type_classes.json
    type_report.csv

From `EGraphSAGE_results/`:

    egraphsage.pt
    egs_scaler.pkl
    egs_features.json
    egs_summary.json
    egs_comparison.csv
    egs_zeroday_by_family.csv
    egs_window_sweep.csv
    egs_zeroday.png
    egs_window_sweep.png

Do **not** add the dataset CSV. It is ~1.1 GB; GitHub rejects files over
100 MB and `.gitignore` already excludes it.

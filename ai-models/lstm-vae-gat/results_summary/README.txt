Aegex results summary  (generated 2026-11-26 19:05 by scripts\models\export_results_summary.py)

All rates are shares between 0 and 1 (0.907 = 90.7 %). Column `quoted` = yes for the numbers on the results page.

headline_results.csv     ONE ROW PER DATASET with the quoted numbers: LSTM-AE, VAE, LSTM or VAE and the one-line
                         rule side by side (detection, false alarms; noise floor for LSTM and VAE).
benchmark_summary.csv    MAIN RESULTS. Realistic benchmark: real attack traffic hidden in real normal traffic,
                         test data only. One row per benchmark run x dataset x method.
  detection_macro          share of attack windows flagged, every attack type weighted equally
  detection_ci95_low/high  95 % bootstrap interval of detection_macro
  false_alarm_rate         share of clean normal windows flagged (target about 0.01)
  false_alarms_per_hour    the same as alerts per hour of normal traffic
  noise_floor_*            share flagged when plain NORMAL traffic is injected like an attack (self = the
                           device's own traffic replayed, other_device = another device's traffic). Detection
                           only counts as far as it is above this.
  threshold_calibration    none = alarm lines saved in the model; network = reset on the network's own
                           validation-period normal traffic; per-device = network + one line per device
benchmark_by_attack.csv  detection per attack type and speed (x1 = original speed, x10 / x100 = slowed down)
benchmark_false_alarms_by_capture.csv
                         false alarms per normal recording (e.g. Kitsune's camera network vs its Mirai network)
gat_summary.csv          GAT (which host is attacking / attacked, per minute) vs window alerts alone.
                         test_set benchmark = realistic benchmark (quoted); dataset_test = datasets' own split.
                         held_out_attack = attack type removed from GAT training in that run.
gat_by_attack.csv        GAT detection per attack; seen_in_training = no -> the unseen-attack result
                         one_input_rule_* = best single GAT input (chosen + thresholded on val only); the GAT
                         only counts for what it adds above it. gat_v5 was trained without port/service link inputs.
gat_controls.csv         GAT on hosts that only received injected NORMAL traffic (should be low)
test_split_summary.csv   datasets' OWN test split per class (optimistic: attacks come as pure blocks; not quoted).
                         For benign rows the flagged share is the false-alarm rate.

Which run is quoted for each dataset is set in that dataset's plug-in (scripts\aegex_datasets\<name>.py,
QUOTED_RUN). nf_toniot is quoted with the thresholds saved in the model: recalibrating collapses there,
because one device dominates the calibration slice.

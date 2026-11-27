# Detection evaluation (Step 8)

Generated 2026-11-27 18:21 UTC by `python -m evaluate`. Ground truth = flow labels.

**Flow level**: recall = attack flows covered by an alert; precision = covered flows that really were attacks; false alarm rate = normal flows covered. **Attacker level**: hosts that sent attack traffic and were flagged; normal hosts flagged; time from a host's first attack flow to its first alert.

## ds-kitsune-mirai

27,966 flows, 13,104 attack (46.9%). Scored from 2018-10-25T06:58:00+00:00 on (after the calibration part). Kitsune / mirai: public dataset, all 50,032 connections (datasets.to_unified)

| Detector | Alerts | Recall | Precision | F1 | False alarm rate | Attackers found | Normal hosts flagged | Time to detect |
|---|---|---|---|---|---|---|---|---|
| Rule baseline | 1 | 100.0 % | 84.4 % | 91.5 % | 16.3 % | 1 / 2 | 0 / 292 | 192.168.2.110 70.9 s |
| LSTM-AE | 187 | 57.0 % | 84.2 % | 68.0 % | 9.4 % | 1 / 2 | 2 / 292 | 192.168.2.110 83.4 s |
| VAE | 707 | 94.3 % | 80.5 % | 86.9 % | 20.1 % | 1 / 2 | 1 / 292 | 192.168.2.110 94.4 s |
| LSTM-AE + VAE | 744 | 98.3 % | 80.2 % | 88.3 % | 21.4 % | 1 / 2 | 3 / 292 | 192.168.2.110 83.4 s |
| Temporal GAT | 16 | 100.0 % | 56.5 % | 72.2 % | 67.9 % | 2 / 2 | 8 / 292 | 192.168.2.107 0 s, 192.168.2.110 0 s |
| Any detector | 761 | 100.0 % | 54.7 % | 70.8 % | 72.9 % | 2 / 2 | 9 / 292 | 192.168.2.107 0 s, 192.168.2.110 0 s |

Attackers missed: Rule baseline: 192.168.2.107; LSTM-AE: 192.168.2.107; VAE: 192.168.2.107; LSTM-AE + VAE: 192.168.2.107.

## poc-attack

1,866 flows, 1,599 attack (85.7%). PoC test recording (demo.make_poc_pcaps): normal hotspot traffic + port scan 11:05 + HTTP flood 11:10 from 192.168.137.50

| Detector | Alerts | Recall | Precision | F1 | False alarm rate | Attackers found | Normal hosts flagged | Time to detect |
|---|---|---|---|---|---|---|---|---|
| Rule baseline | 2 | 100.0 % | 100.0 % | 100.0 % | 0.0 % | 1 / 1 | 0 / 3 | 192.168.137.50 0 s |
| LSTM-AE | 100 | 100.0 % | 98.0 % | 99.0 % | 12.0 % | 1 / 1 | 1 / 3 | 192.168.137.50 0 s |
| VAE | 100 | 100.0 % | 98.0 % | 99.0 % | 12.0 % | 1 / 1 | 1 / 3 | 192.168.137.50 0 s |
| LSTM-AE + VAE | 100 | 100.0 % | 98.0 % | 99.0 % | 12.0 % | 1 / 1 | 1 / 3 | 192.168.137.50 0 s |
| Temporal GAT | 5 | 100.0 % | 97.7 % | 98.9 % | 13.9 % | 1 / 1 | 2 / 3 | 192.168.137.50 0 s |
| Any detector | 107 | 100.0 % | 96.4 % | 98.2 % | 22.5 % | 1 / 1 | 2 / 3 | 192.168.137.50 0 s |


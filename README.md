# Configuration Fingerprints in Flow-Based Slow-HTTP Detection — code and artefacts

Code, audit scripts and result files for the article
"Configuration Fingerprints in Flow-Based Slow-HTTP Detection: What Intrusion Classifiers Learn from CIC Benchmarks"
(S.H.U. Shah, submitted to *Computers & Security*).

## Contents
| Path | What it is |
|---|---|
| `notebooks/paper2_revision.ipynb` | Complete pipeline: loading, cleaning, invariant features, training (RF, XGBoost, MLP, FGSAN), re-timing, statistics, all tables and figures |
| `notebooks/paper2_revision_executed.ipynb` | The same notebook with the outputs of the run reported in the paper |
| `notebooks/pcap_check_slowhttptest_executed.ipynb` | Executed PCAP check (victim capture UCAP172.31.69.25, Friday-16-02-2018) with outputs (Appendix D) |
| `notebooks/input_checksums.ipynb` | Computes the SHA-256 digests in `results/input_checksums.csv` |
| `scripts/fig_dense_benign.py` | Redraws Fig. 5 and Fig. 6 from `results/R7_dense_grid.csv` and `results/R11_benign_retiming.csv` |
| `notebooks/pcap_check_slowhttptest.ipynb` | PCAP spot-check of the CSE-CIC-IDS2018 DoS-SlowHTTPTest class and CSV re-audit |
| `scripts/audit_degeneracy.py` | Stand-alone vector-level audit (Tables 4–5): distinct vectors and label conflicts under four schemas, destination-port profile, SHA-256 of inputs |
| `results/` | All result tables (CSV) written by the notebook, including the per-seed ledger and `requirements_freeze.txt` |
| `results/input_checksums.csv` | SHA-256 digests of every input file |

## Data
Public releases of the Canadian Institute for Cybersecurity (https://www.unb.ca/cic/datasets/):
- CSE-CIC-IDS2018: `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/` — Thursday-15-02-2018, Friday-16-02-2018 (download with `aws s3 cp --no-sign-request ...`)
- CICIDS2017 MachineLearningCVE: Wednesday-workingHours, Monday-WorkingHours
- CIC-DoS2017: Parquet conversion of the CICFlowMeter output (Kaggle dataset `dhoogla/cicdos2017`)

## Reproducing the results
1. Create a Kaggle notebook from `notebooks/paper2_revision.ipynb`, attach the three datasets, enable a GPU (T4) and Internet.
2. *Save Version → Save & Run All*. Every cell after the main pipeline is fail-safe. Runtime ≈ 3–4 h.
3. Download `paper2_revision_outputs.zip` from the version output; it contains `tables/` (all CSVs below), `figures/` and the package list.
4. Audit only (no GPU): `python scripts/audit_degeneracy.py <csv/parquet files> --out audit_out`.

## Where each table and figure comes from
| Manuscript | Result file |
|---|---|
| Tables 2–3 | notebook Section 6 output |
| Tables 4–5 | `R1_degeneracy_all_fields.csv`; `scripts/audit_degeneracy.py` |
| Table 8, Fig. 5 | `R6_flips_admissible_cluster_benign.csv`, `R7_dense_grid.csv` |
| Table 9 | `R3_slowloris_only_training.csv` |
| Table 10 | `R8_dos2017_own_domain_retention.csv` |
| Tables 12, 14, 15, C1 | `R4_evaluation_all.csv`, `R4_prevalence_sensitivity.csv`, `R5_block_bootstrap.csv` |
| Table 16 | `R10_reverse_5seeds.csv`, `R10_reverse_preservation.csv` |
| Table 17, Appendix B | `R5_paired_hierarchical.csv` |
| Appendix D | `notebooks/pcap_check_slowhttptest_executed.ipynb` |
| Table 11, Fig. 6 (benign re-timing) | `R11_benign_retiming.csv`, `R11_benign_retiming_summary.csv` |
| Counterfactual interventions (Sec. 4.1) | `R8_counterfactual_interventions.csv` |
| Per-seed ledger | `results/results.csv`, `results/Ledger.md` |

## Settings that matter
Seeds 1–5 (MLP comparisons 1–10); split seed fixed in the notebook; thresholds calibrated to 0.1% FPR; CuDNN deterministic.

## Licence
Code: MIT. Datasets remain under their original CIC terms and are not redistributed here.

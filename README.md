# BEAD — Benford-Entropic Anomaly Detector

**BEAD** is a lightweight, unsupervised Network Intrusion Detection System (NIDS)
that combines **Benford's Law** first-digit conformity analysis with **Shannon Entropy**
into a single Hybrid Anomaly Score to achieve mimicry-resistant detection of
malicious traffic — without payload decryption.

This repository accompanies the IEEE conference paper:

> **"Statistical Anomaly Detection in Encrypted Network Traffic Using Benford's Law
> and Entropic Hybrid Analysis"**
> Anuprita S. Korde, Irfan Siddavatam
> K.J. Somaiya School of Engineering, Somaiya Vidyavihar University, Mumbai

---

## How BEAD Works

```
Raw Packets
    │
    ▼
[Layer 1]  Data Acquisition      — libpcap / DPDK / BPF filtering
    │
    ▼
[Layer 2]  Flow Preprocessing    — 5-tuple hash, IAT & packet-size extraction
    │
    ▼
[Layer 3]  Statistical Analysis  — MAD, Chi-square, KS conformity tests
                                   + Shannon Entropy Hybrid Engine
    │
    ▼
[Layer 4]  Decision & Alerting   — Threshold comparison → SIEM / CEF alert
```

### Hybrid Anomaly Score

```
S = α · MAD + (1 − α) · |H_obs − H_B|
```

where `MAD` is the Mean Absolute Deviation from the Benford distribution,
`H_obs` is the observed Shannon Entropy, `H_B ≈ 3.134 bits` is the
Benford-expected entropy, and `α = 0.65` is the empirically calibrated weight.

An alert is raised when `S > τ` (95th-percentile baseline threshold)
or `χ² > 15.51` (α = 0.05, df = 8).

---

## Repository Structure

```
bead-nids/
├── benford_analyzer.py   # Core BEAD engine (MAD, χ², KS, entropy, hybrid score)
├── test_demo.py          # Synthetic test suite and visualisation demo
├── conference_paper.tex  # IEEE LaTeX source of the companion paper
├── requirements.txt      # Python dependencies
└── README.md
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/sagarkorde/bead-nids.git
cd bead-nids

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the test suite
python test_demo.py
```

### Programmatic Usage

```python
from benford_analyzer import BenfordAnalyzer

analyzer = BenfordAnalyzer()

# Analyse a sequence of packet sizes (integers, bytes)
packet_sizes = [64, 1500, 128, 576, 1024, ...]
results = analyzer.analyze(packet_sizes, verbose=True)

print(f"MAD:        {results['mad']:.4f}")
print(f"Chi-square: {results['chi_square_statistic']:.4f}")
print(f"Compliant:  {results['compliant']}")
```

---

## Key Properties

| Property | Value |
|---|---|
| Detection paradigm | Unsupervised (label-free) |
| Payload access required | No |
| Encryption agnostic | Yes (TLS 1.3, QUIC, HTTP/3) |
| Computational complexity | O(n) per sliding window |
| Default window size | 1 000 packets |
| MAD threshold | > 0.015 → suspicious |
| Chi-square threshold | > 15.51 (α = 0.05, df = 8) |
| Throughput (ARM Cortex-A72) | 148 000 pps, 6.7 µs latency |
| F1 under mimicry attack | 0.891 (vs 0.612 for MAD-only) |

---

## NSL-KDD Results (mean ± 1 s.d., 10 runs)

| Method | Prec. | Rec. | F1 | FPR |
|---|---|---|---|---|
| Benford MAD only (label-free) | 0.881 ± .012 | 0.863 ± .015 | 0.872 ± .011 | 0.112 ± .009 |
| RF, 41 features † | 0.952 ± .010 | 0.941 ± .006 | 0.946 ± .006 | 0.047 ± .004 |
| Kitsune AE † | 0.934 ± .009 | 0.958 ± .009 | 0.946 ± .007 | 0.063 ± .005 |
| Draper-Gil et al. † | 0.906 ± .009 | 0.882 ± .014 | 0.894 ± .010 | 0.091 ± .007 |
| **BEAD (proposed, label-free)** | **0.943 ± .009** | **0.937 ± .008** | **0.940 ± .008** | **0.058 ± .004** |

† Supervised — uses labeled training data; included for context only.

---

## Citation

If this work is useful in your research, please cite:

```
@inproceedings{korde2025bead,
  title     = {Statistical Anomaly Detection in Encrypted Network Traffic
               Using Benford's Law and Entropic Hybrid Analysis},
  author    = {Korde, Anuprita S. and Siddavatam, Irfan},
  booktitle = {Proc. IEEE Conf.},
  year      = {2025}
}
```

---

## License

See [LICENSE](LICENSE) for details.

# Adaptive Trust Chain (ATC) — Phase 4: ASI-PLC Simulator

> **Companion code for:**
> Sk. Riad Bin Ashraf, Bernd Noche, Tan Gürpinar — *"Adaptive Trust Chain (ATC): A Blockchain-Based Weld Certification Framework for Structural Integrity Assurance in Green Hydrogen Infrastructure"* — IEEE Access (under review)
> Chair of Transport Systems and Logistics (TuL), University of Duisburg-Essen, Germany

---

## 🔗 Live Interactive Simulator

**[Launch the ASI-PLC Simulator in your browser →](https://hasiburrahman4.github.io/simulator.html)**

No installation required. Adjust scenario counts and fault injection parameters, run the simulation, and explore latency distributions and PLC state transitions interactively — all in a single HTML page.

---

## Overview

This repository contains the Phase 4 prototype simulation for the **Autonomous Safety Interlock (ASI-PLC)** — the hardware-enforcement layer of the Adaptive Trust Chain framework. The ATC is a five-layer permissioned blockchain architecture that closes the *passive safety gap* in weld certification for green hydrogen infrastructure by translating blockchain compliance state into a physical **Compliance Bit** at Safety PLC level via OPC-UA.

The Phase 4 simulator reproduces the five-step Compliance Bit decision cycle (Algorithm 2 in the paper) and all Monte Carlo results reported in **Section VII-E** of the manuscript. It is a design-level prototype — latency parameters are derived from published Hyperledger Besu QBFT benchmarks (Saleh & Cevik, 2025), not a deployed physical system.

---

## Background

Welded joints in green hydrogen infrastructure operate under pressures exceeding 700 bar and are susceptible to **hydrogen embrittlement (HE)** in the weld heat-affected zone (HAZ). Prevailing certification practice relies on paper-based procedure logs and post-fabrication audits — a *passive safety gap* that gives rise to:

- **Administrative latency**: credential expiry not matched by equipment lockout
- **Traceability deficits**: in-process parameters cannot be reconstructed after a structural failure

The ATC addresses this by linking a Hyperledger Besu QBFT blockchain directly to a SIL 2-rated Safety PLC. The **Compliance Bit** is `FALSE` by default (Fail-Locked design). The welding relay energises **if and only if** all upstream checks pass and the Oracle payload is cryptographically verified.

---

## Repository Structure

```
hasiburrahman4.github.io/
│
├── Prototype_app.py      # Interactive Streamlit UI — reproduces all paper figures & Table 8
├── simulator.html        # Standalone browser-based simulator (no install needed)
├── run_atc_app.bat       # One-click launcher for the Streamlit app (Windows)
├── Images/               # Simulation output figures (Figs. 8a–8f in paper)
│   ├── Figure_1.png      # Fig. 8a — ASI-PLC Latency Distribution
│   ├── Figure_2.png      # Fig. 8b — Decision Outcomes by Scenario Type
│   ├── Figure_3.png      # Fig. 8c — Compliance Bit Timeline & Latency
│   ├── Figure_4.png      # Fig. 8d — Latency CDF: Valid vs. Timeout
│   ├── Figure_5.png      # Fig. 8e — Non-Compliance & Attack Detection Rate
│   └── Figure_6.png      # Fig. 8f — ASI-PLC Safety State Machine
└── README.md
```

**Build phases referenced in the paper (Phases 1–3 available from the corresponding author upon request):**

| Phase | Artefact | Description |
|-------|----------|-------------|
| 1 | `WeldComplianceASC.sol` | Solidity 0.8.20 Adaptive Smart Contract (Algorithm 1) |
| 2 | Quantitative simulations | Weibull, Paris–Erdogan, DTMC models (Sections VII-B–D) |
| 3 | Oracle Gateway Simulator | Payload generation and signing |
| **4** | **`Prototype_app.py` / `simulator.html`** | **ASI-PLC state machine & Monte Carlo — this repo (Section VII-E)** |

---

## The ASI-PLC State Machine

The simulator implements the five-step Compliance Bit decision cycle from **Algorithm 2** in the paper, running on a 500 ms cycle aligned with the QBFT finality window:

```
Step 1 — Heartbeat Monitoring   → Latency > 500 ms          ⟹ SOFT_LOCK
Step 2 — Anti-Replay Check      → Nonce ≤ last nonce         ⟹ HARD_LOCK
Step 3 — HMAC-SHA256 Verify     → Signature mismatch         ⟹ HARD_LOCK (MitM detected)
Step 4 — Asymmetric Sig Verify  → Oracle identity unverified ⟹ HARD_LOCK
Step 5 — Compliance Bit         → All checks passed          ⟹ COMPLIANT / NON_COMPLIANT
```

**PLC States:**

| State | Meaning | Recovery |
|-------|---------|----------|
| `IDLE` | Awaiting first Oracle payload | — |
| `COMPLIANT` | Compliance Bit TRUE — relay energised | — |
| `NON_COMPLIANT` | ASC returned FALSE (e.g. preheat below minimum) | Automatic on next valid cycle |
| `SOFT_LOCK` | Heartbeat timeout (>500 ms) | Automatic on restored connectivity |
| `HARD_LOCK` | Cryptographic failure (MitM / replay) | **Manual admin reset required** |

The full state transition diagram (IEC 61131-3 / IEC 61511-1 SIL 2) is shown below:

[![Fig. 8f — ASI-PLC Safety State Machine](https://github.com/hasiburrahman4/hasiburrahman4.github.io/raw/main/Images/Figure_6.png)](https://github.com/hasiburrahman4/hasiburrahman4.github.io/blob/main/Images/Figure_6.png)

*Fig. 8f — ASI-PLC Safety State Machine (IEC 61131-3 / IEC 61511-1 SIL 2). Default state is Fail-Locked (ComplianceBit := FALSE). HARD LOCK requires authenticated manual admin reset; SOFT LOCK recovers automatically on heartbeat restoration.*

---

## Monte Carlo Simulation (n = 200, seed = 2025)

`Prototype_app.py` and `simulator.html` both run 200 welding operation scenarios across **five fault types** and reproduce all results in **Section VII-E** of the paper.

**Default scenario plan:**

| Scenario | Count | Fault Type | Expected Outcome |
|----------|-------|------------|-----------------|
| Valid (compliant) | 120 | `NONE` | `COMPLIANT`, relay ON |
| Non-compliant weld | 50 | `NON_COMPLY` | `NON_COMPLIANT`, relay OFF |
| MitM attack | 10 | `MITM` | `HARD_LOCK`, relay OFF |
| Replay attack | 10 | `REPLAY` | `HARD_LOCK`, relay OFF |
| Oracle timeout | 10 | `TIMEOUT` | `SOFT_LOCK`, relay OFF |
| **Total** | **200** | | |

### Decision Outcomes by Scenario Type

[![Fig. 8b — ASI-PLC Decision Outcomes by Scenario Type](https://github.com/hasiburrahman4/hasiburrahman4.github.io/raw/main/Images/Figure_2.png)](https://github.com/hasiburrahman4/hasiburrahman4.github.io/blob/main/Images/Figure_2.png)

*Fig. 8b — ASI-PLC decision outcomes across all 200 scenarios (n=200, seed=2025). All 120 valid scenarios resolve as COMPLIANT; all 10 MitM and 10 Replay attacks trigger HARD_LOCK; 9/10 timeout scenarios trigger SOFT_LOCK (one scenario at boundary latency).*

### Non-Compliance and Attack Detection Rate

[![Fig. 8e — Non-Compliance & Attack Detection Rate](https://github.com/hasiburrahman4/hasiburrahman4.github.io/raw/main/Images/Figure_5.png)](https://github.com/hasiburrahman4/hasiburrahman4.github.io/blob/main/Images/Figure_5.png)

*Fig. 8e — Zero false positives confirmed across all 80 non-compliant and attack scenarios. Non-compliant: 50/50 (100%); MitM: 10/10 (100%); Replay: 10/10 (100%); Timeout: 9/10 (90%, one scenario at boundary latency).*

**Key results (ground-truth values, seed = 2025):**

- Valid scenario mean latency: **274.6 ms** (P95 = 320.6 ms, SD = 28.2 ms) — within the 500 ms permissive window
- **Zero false positives** across all 80 non-compliant/attack scenarios
- Timeout scenarios trigger Soft Lock at mean **526.4 ms** (SD ≈ 20 ms)

> ⚠️ These results confirm the logical correctness of the simulation model under the assumed latency distributions. They are not measurements from a deployed physical system.

---

## Simulation Output Figures

Running `Prototype_app.py` or using the [browser simulator](https://hasiburrahman4.github.io/simulator.html) generates the following six publication-quality figures (paper Fig. 8a–8f).

### Fig. 8a — ASI-PLC Latency Distribution: Valid-Credential Scenarios

[![Fig. 8a — ASI-PLC Latency Distribution](https://github.com/hasiburrahman4/hasiburrahman4.github.io/raw/main/Images/Figure_1.png)](https://github.com/hasiburrahman4/hasiburrahman4.github.io/blob/main/Images/Figure_1.png)

*QBFT finality + OPC-UA delivery latency for valid-credential scenarios (n=120, seed=2025). Mean = 274.6 ms; P95 = 320.6 ms. All valid scenarios fall well within the 500 ms permissive window. KDE overlay confirms near-normal distribution.*

---

### Fig. 8c — Compliance Bit Timeline & Latency (First 40 Decisions)

[![Fig. 8c — Compliance Bit Timeline & Latency](https://github.com/hasiburrahman4/hasiburrahman4.github.io/raw/main/Images/Figure_3.png)](https://github.com/hasiburrahman4/hasiburrahman4.github.io/blob/main/Images/Figure_3.png)

*Top panel: Compliance Bit state (TRUE/FALSE) over the first 40 PLC decision cycles. Bottom panel: per-cycle latency with 500 ms permissive window and mean valid latency (274.6 ms) reference lines.*

---

### Fig. 8d — ASI-PLC Latency CDF: Valid vs. Timeout Scenarios

[![Fig. 8d — Latency CDF: Valid vs. Timeout](https://github.com/hasiburrahman4/hasiburrahman4.github.io/raw/main/Images/Figure_4.png)](https://github.com/hasiburrahman4/hasiburrahman4.github.io/blob/main/Images/Figure_4.png)

*Cumulative distribution functions for valid (n=120, solid green) and timeout (n=10, dashed blue) scenarios. Valid P95 = 320.6 ms; the entire valid CDF sits below the 500 ms permissive window. All timeout scenarios fall in the Soft Lock zone (>500 ms), confirming clean separation between the two populations.*

---

## Security Scenarios Tested

| Threat | Injection Method | ATC Response |
|--------|-----------------|--------------|
| **MitM payload injection** | HMAC signature corrupted | HARD_LOCK — manual reset required |
| **Replay attack** | Stale nonce re-used (nonce = 1) | HARD_LOCK — monotonic nonce check fails |
| **Oracle connectivity loss** | Latency drawn from N(526.4, 20) ms | SOFT_LOCK — relay de-energised, auto-recovers |
| **Non-compliant weld** | `compliant_flag = False` (e.g. preheat below minimum) | `NON_COMPLIANT` — relay stays off |

These correspond to the STRIDE threat model in **Table IV** of the paper.

---

## Usage

### Option A — Browser (no installation)

Open **<https://hasiburrahman4.github.io/simulator.html>** in any modern browser. Adjust sliders for scenario counts and fault types, then click **Run Simulation**. No Python or dependencies required.

### Option B — Interactive Streamlit app

**Requirements:** Python 3.10+

```bash
pip install numpy scipy matplotlib seaborn streamlit
streamlit run Prototype_app.py
```

Or on Windows, double-click `run_atc_app.bat`.

The Streamlit app provides:

- Adjustable scenario counts and random seed via sidebar controls
- Live metric cards (total scenarios, false positives/negatives, hard lock events)
- Latency distribution histogram
- PLC state distribution bar chart
- Scrollable scenario detail table (first 30 results)
- Full state count JSON export

---

## Reproducibility

All simulation parameters match the values documented in the paper. To reproduce the exact published results:

```python
seed = 2025  # Fixed seed ensures identical latency draws and scenario outcomes
```

The simulation uses `numpy.random.default_rng(seed)` throughout. No external data files are required. The browser-based `simulator.html` uses an equivalent seeded PRNG (mulberry32) and produces consistent results at `seed = 2025`.

**Published results (seed = 2025, verified):**

| Metric | Value |
|--------|-------|
| Valid scenario mean latency | 274.6 ms |
| Valid scenario P95 latency | 320.6 ms |
| Valid scenario SD | 28.2 ms |
| Timeout mean latency | 526.4 ms |
| False positives (all fault types) | 0 / 80 |

---

## Limitations and Scope

This prototype is a **design-level plausibility check**, not an empirical validation of deployed hardware:

- Latency parameters are drawn from published QBFT benchmarks (Saleh & Cevik, 2025), not measured on a physical fabrication floor
- The HMAC/asymmetric signature verification is a faithful software simulation; production deployment requires a hardware security module (HSM) for the Oracle private key
- Field measurement of latency and false-positive rates under industrial electromagnetic and network conditions remains a prerequisite for operational deployment

---

## Citation

If you use this code in your research, please cite:

```bibtex
@article{ashraf2025atc,
  author  = {Ashraf, Sk. Riad Bin and Noche, Bernd and G{\"u}rpinar, Tan},
  title   = {Adaptive Trust Chain ({ATC}): A Blockchain-Based Weld Certification
             Framework for Structural Integrity Assurance in Green Hydrogen
             Infrastructure},
  journal = {IEEE Access},
  year    = {2025},
  note    = {Under review}
}
```

---

## Authors

**Sk. Riad Bin Ashraf** · **Bernd Noche** · **Tan Gürpinar**
Chair of Transport Systems and Logistics (TuL), Faculty of Engineering
University of Duisburg-Essen, 47057 Duisburg, Germany
Correspondence: <shake.ashraf@uni-due.de>

---

## License

**`simulator.html`** is released as **public domain** — no rights reserved. Free for any use without restriction.

**`Prototype_app.py`** and all other repository content are released for **academic reproducibility**. For commercial use or deployment in safety-critical systems, please contact the authors. No warranty is provided; this is a research prototype and must not be used as-is in any production or regulatory context.

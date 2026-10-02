# Datasets and Evaluation

## What is evaluated today

`POST /api/v1/research/run` (`app/research/evaluate.py`) scores three approaches on **labelled synthetic trials**:

- **Rule-based:** all rule detectors, default thresholds.
- **ML:** the Isolation Forest detector with its effect-size gate.
- **Hybrid:** the union of the two.

Unit of evaluation: one source host in one 10-minute window. Each trial is benign background traffic from 46 simulated devices;
attack trials add one behaviour (port scan, brute force, exfiltration, DNS tunnelling, lateral movement) from one host, at a *strong* intensity
(above rule thresholds) or a *subtle* one (below). The label is 1 only for the injected host. Reported: confusion matrix, precision, recall,
F1, false-positive rate, per-attack recall, and detection latency (60-second checkpoints, strong attacks only).

Reference run (seed 2024, 80 trials): rules recall 50% (every strong attack, no subtle one), ML recall 20% (only the subtle exfiltration, plus some strong
cases), hybrid 60%; false-positive rate about 0.03% for rules, 0% for ML.

### Reading these numbers

They are **not** evidence of real-world accuracy. The benign model, the attacks and the thresholds were all written by the same author; benign traffic is homogeneous;
subtle intensities were built to sit below rule thresholds. The ML detector was deliberately **not** re-tuned after seeing this benchmark, because tuning on it would make the
evaluation circular. The result shows the rule/ML trade-off, and in particular that the ML gate is conservative (it needs a >= 6 sigma deviation; features that are constant in training,
such as failed connections, have their standard deviation floored, which limits sensitivity). Revisiting that floor against a held-out public dataset is future work.

## Evaluating on a public flow CSV (loader implemented, datasets not bundled)

```bash
cd apps/api
python -m app.research.csvflows --schema cicids2017 --csv path/to/Monday-WorkingHours.pcap_ISCX.csv --max-rows 300000
python -m app.research.csvflows --schema unsw-nb15 --csv path/to/UNSW-NB15_1.csv
```

`app/research/csvflows.py` maps a flow row onto the event vocabulary, groups into (source host, 10-minute window) units, and scores rule-based, ML and hybrid detection on a
**chronological split**: the Isolation Forest is trained only on benign units from the first half of the time range, and every method is scored on the second half. The output is the same
metric set as the synthetic benchmark (no latency).

**Validation status:** the loader and evaluator are tested on small hand-built CSVs that follow the published column names (including CICIDS's leading-space headers and
`%m/%d/%Y %H:%M` timestamps). They have **not** been run on the real datasets, which are large and were not available. Expect to adjust `SCHEMAS` if a real file differs in column names or
timestamp format. Known interpretation choices: a flow with no payload in either direction is treated as a connection attempt; UNSW-NB15's public-looking addresses mean address-based
rules (exfiltration, lateral movement) see everything as external, so the ML profiles all sources there.

## Public datasets (not bundled)

NetSentinel does **not** redistribute CICIDS-style or UNSW-NB15-style datasets. Obtain them from their publishers and follow their licences.

Manual ingestion path (the `csvflows` module above automates steps 1-3):

1. Read the flow CSV in chunks (pandas), never loading it whole.
2. Map each row onto the `NetworkEvent` shape: timestamp, source and destination address, destination port, protocol, bytes sent/received, duration, and the dataset's label stored in `attributes.label`.
3. Group into source-host x window units exactly as the synthetic benchmark does, then call the same three scorers.
4. Register the dataset in the `datasets` table (name, kind, record count, licence, metadata).

Caveats to resolve when implementing: these datasets are flow-level (no payloads), so rules that rely on authentication events (brute force, lateral movement) have no input, and
per-flow labels must be aggregated to the host-window unit. Class imbalance and duplicated records are well-known issues in these corpora.

## Custom PCAPs

Upload on the Replay page. Captures are unlabelled, so they can be replayed and investigated but not scored.

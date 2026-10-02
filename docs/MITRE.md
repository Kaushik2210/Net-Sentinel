# MITRE ATT&CK Mapping

## Catalogue

`apps/api/app/data/mitre.json` is the single source of truth: 33 techniques across the 13 Enterprise tactics,
loaded into the `mitre_techniques` table at startup (upserted, so edits reach existing databases).
The UI contains no hard-coded technique data.

The catalogue is a **curated subset** of [MITRE ATT&CK](https://attack.mitre.org/); IDs and tactic names follow
ATT&CK Enterprise, and descriptions are short paraphrases. ATT&CK is a trademark of The MITRE Corporation.
A test asserts that every technique referenced by a detector exists in the catalogue.

## Mapping

Each detector declares the techniques it evidences (`mitre = ("T1110",)`), and alerts carry them. The mapping
expresses *what behavior the rule observed*, not a verdict that an adversary used that technique.

| Detector | Techniques |
|---|---|
| PortScanDetector | T1046, T1595 |
| BruteForceDetector | T1110 |
| CredentialCompromiseDetector | T1078, T1110 |
| LateralMovementDetector | T1021, T1078 |
| DNSAnomalyDetector | T1071.004 |
| ConnectionAnomalyDetector | T1090 |
| DataExfiltrationDetector | T1041, T1048 |
| SuspiciousProtocolDetector | T1571 |
| MLAnomalyDetector / behavioral scorer | none (statistical signals are not mapped to techniques) |

## API and UI

- `GET /api/v1/mitre`: matrix grouped by tactic, with per-technique alert count, max/mean confidence, first seen.
- `GET /api/v1/mitre/{id}`: related alerts, evidence event IDs and **timeline position** (step N of M in its incident).
- `/mitre`: matrix view (observed cells highlighted; most of the matrix is intentionally unobserved), search and an
  observed-only filter, and a detail panel linking to the incident.

"Observed" means referenced by at least one alert in the last 7 days.

## Limitations

- Subset only; sub-techniques are included only where a detector needs them.
- Coverage shows what *these rules* can see, not what an attacker did. Absence of a highlighted cell is not absence of the technique.

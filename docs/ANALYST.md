# Investigation Workspace and Evidence-Bound Analyst

## Workspace (`/investigate`)

Incident queue (left), attack timeline with workflow controls and notes (centre), evidence and analyst tabs (right).
Analysts and admins can mark an incident *investigating*, *resolved*, *false positive* or *escalated*, assign it to an analyst or admin,
and add notes (max 4,000 characters). Viewers can read everything. Every change is written to the audit log
(`incident.status` with from/to, `incident.assign`, `incident.note`), and the incident's trail is shown beside it.

## The analyst

> It must not invent security conclusions. It receives structured evidence and may only cite what exists.

```
alerts, events, risk factors ─▶ evidence package (closed set of IDs) ─▶ answer (claims + citations) ─▶ validator ─▶ response
```

- **Evidence package** (`app/analyst/evidence.py`): chain steps, supporting signals, risk factors, MITRE techniques, evidence event IDs, built from stored rows.
- **Answers** (`app/analyst/answers.py`): `explain`, `what_changed`, `timeline`, `evidence`, `next_steps`, `related_events`, `exfiltration`, `report` (incidents);
  `why_suspicious`, `related_alerts` (devices). Each answer is a list of claims, each with the IDs it relies on.
- **Validator:** `validate()` rejects an answer that cites an identifier outside the package; the API returns an error rather than showing it.
- **Insufficient evidence:** when the package cannot support an answer (for example "Did data leave the network?" with no exfiltration alert, or a quiet device)
  the response is exactly `Insufficient evidence.`
- **No language model.** Answers are deterministic and assembled from templates over stored evidence; responses carry `mode: deterministic` and a notice saying so.
  `app/analyst/provider.py` defines the adapter a model could implement later. Its output would pass through the same validator, and no provider name
  would be shown unless one is actually configured.

"Next steps" are standard analyst checks keyed to the stages observed. They are guidance triggered by evidence, not findings about the network.

## Limitations

- Templated language is rigid by design; it trades fluency for verifiability.
- Citations prove that referenced records exist, not that a conclusion drawn from them is correct.
- Notes are plain text and not versioned; audit entries record that a note was added, not its content.

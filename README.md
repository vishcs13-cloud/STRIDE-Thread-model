# STRIDE Threat Model Study – Microservice Data Flows

Maps the data flows and structural threats of a microservice system using the
**STRIDE** method, and exports the model for **OWASP Threat Dragon**.

## Project description

Microservices add many network connections, and each one can be attacked.
This project models a sample online shop called **ShopSphere** (13 DFD
elements, 14 data flows, 3 trust boundaries) and, with one Python script:

1. generates threats for every element using **STRIDE-per-element**,
2. scores them (likelihood x impact, 1-5 scale) and checks which existing
   controls already mitigate them,
3. exports an **OWASP Threat Dragon** model, a CSV threat register, a data
   flow diagram image and summary charts.

**Result for ShopSphere:** 103 threats, 45 open (19 High, 21 Medium, 5 Low)
and 58 mitigated. Top risk: the unauthenticated payment webhook (F10).

## Data set

There is no external data set. The "data" is the system model defined in
`stride_threat_model.py` (sections 2 and 3) and the generated output files in
`output/`. Useful references:

- OWASP Threat Dragon: <https://owasp.org/www-project-threat-dragon/>
- Threat Dragon source and docs: <https://github.com/OWASP/threat-dragon>
- MITRE CWE weakness list (for mapping threats): <https://cwe.mitre.org/data/>

## Technologies used

- Python 3.9+
- Matplotlib (diagram and charts)
- OWASP Threat Dragon (viewing/editing the exported model)
- STRIDE threat modelling method

## Setup and run

```bash
pip install -r requirements.txt
python stride_threat_model.py
# optional: choose another output folder
python stride_threat_model.py --out my_results
```

## Output files (`output/`)

| File | What it is |
|------|------------|
| `threat_dragon_model.json` | Model to open in OWASP Threat Dragon |
| `threats.csv` | Threat register: one row per threat |
| `dfd.png` | Data flow diagram with trust boundaries |
| `risk_summary.png` | Charts: STRIDE categories, severity, riskiest components |
| `summary.json` | Totals |

## Open the model in Threat Dragon

1. Open the Threat Dragon web or desktop app.
2. Choose *Open an existing threat model* and select
   `output/threat_dragon_model.json`.
3. Open the diagram "ShopSphere data flow diagram" and click any element to
   see its threats.

The JSON follows the Threat Dragon v2 format. If your version complains,
use `threats.csv` and `dfd.png` instead.

## Key information

- **STRIDE** = Spoofing, Tampering, Repudiation, Information disclosure,
  Denial of service, Elevation of privilege.
- **Severity:** High >= 15, Medium 8-14, Low <= 7 (score = likelihood x impact).
- A threat is **Mitigated** when the matching control exists (for example TLS
  for flow tampering); otherwise it is **Open**.
- To model your own system, edit the `element(...)` calls and `FLOW_ROWS`
  list in `stride_threat_model.py`, then run it again.
- The controls in the example are assumptions, not a real system audit.

## Files

```
stride_threat_model.py      main code
requirements.txt            dependencies
README.md                   this file
STRIDE_Project_Report.docx  full project report
output/                     generated results
```

# TTP Matcher

**TTP Matcher** is a Python utility for Cyber Threat Intelligence (CTI) analysts.  
It matches **observed MITRE ATT&CK techniques (TTPs)** against known **intrusion sets (threat actors)**.

## Features
- Supports MITRE ATT&CK Enterprise **STIX 2.1 JSON** or simple **CSV mapping**
- **Alias collapsing** (`--collapse-aliases`) → merges synonymous actor names (e.g., Callisto / COLDRIVER / SEABORGIUM → Star Blizzard)
- **Parent vs exact matching**
  - `--mode exact`: sub-techniques must match exactly (T1059.001 only matches .001)
  - `--mode parent`: sub-techniques normalized to parent (T1059.001 → T1059)
- **Scoring**
  - Raw matches
  - Weighted matches (downweight common noisy TTPs)
  - Jaccard similarity
- **Filtering**
  - By platform (`--platform Windows`, Linux, macOS, etc.)
  - By minimum number of distinct tactics (`--min-tactics 2`)
  - Ignore techniques (`--ignore Txxxx`)
- **Export options**
  - JSON / CSV results

## Installation
Clone the repository:
```bash
git clone https://github.com/deltatl/ttpmatcher.git
cd ttpmatcher
```
## Usage

Basic example:
```bash
python3 ttpmatcher.py \
  --source stix \
  --stix-file enterprise-attack.json \
  --mode parent \
  --collapse-aliases \
  --ttps T1059 T1566.001 T1078 \
  --top 10
```
Example with filters:
```bash
python3 ttpmatcher.py \
  --source stix \
  --stix-file enterprise-attack.json \
  --mode parent \
  --platform Windows \
  --min-tactics 2 \
  --downweight T1059,T1047,T1105 \
  --ignore T1204.002 \
  --collapse-aliases \
  --ttps T1059 T1566.001 T1078 \
  --top 10
  ```
Export results to JSON:
```bash
python3 ttpmatcher.py \
  --source stix \
  --stix-file enterprise-attack.json \
  --mode parent \
  --collapse-aliases \
  --ttps T1059 T1566.001 T1078 \
  --top 10 \
  --export-json results.json
```
Export results to CSV:
```bash
python3 ttpmatcher.py \
  --source stix \
  --stix-file enterprise-attack.json \
  --mode parent \
  --collapse-aliases \
  --ttps T1059 T1566.001 T1078 \
  --top 10 \
  --export-csv results.csv
```
Requirements

Python 3.8+

MITRE ATT&CK Enterprise STIX JSON (download from MITRE ATT&CK)

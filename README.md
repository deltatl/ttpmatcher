# TTP Matcher

**TTP Matcher** is a Python utility for Cyber Threat Intelligence (CTI) analysts.  
It matches **observed ATT&CK techniques (TTPs)** against known **MITRE ATT&CK intrusion sets (threat actors)**.

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

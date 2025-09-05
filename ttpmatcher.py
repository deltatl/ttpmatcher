#!/usr/bin/env python3
"""
TTP-to-Threat Actor Matcher (v0.3)

Enter observed ATT&CK Technique IDs (Txxxx or Txxxx.yyy) and score which
threat actors (intrusion sets) most closely match those TTPs.


  Features:
  - Supports MITRE ATT&CK Enterprise STIX 2.1 JSON bundle or CSV mapping
  - Alias collapsing (--collapse-aliases) → merges synonymous actor names
  - Parent vs exact matching of techniques
  - Weighted scoring (downweight common noisy techniques)
  - Platform and tactic filters
  - Export results as JSON/CSV


Data sources supported:
  1) MITRE ATT&CK Enterprise STIX 2.1 JSON bundle ("enterprise-attack.json").
  2) Simple CSV mapping with headers: actor,technique_id

Matching modes:
  - exact: sub-techniques must match exactly (T1059.001 only matches .001)
  - parent: sub-techniques are normalized to their parent (T1059.001 -> T1059)

Scoring:
  - matches: count of overlapping technique IDs
  - weighted_matches: sum of per-technique weights (default 1.0; downweights apply)
  - jaccard: |A ∩ B| / |A ∪ B|

Note: tactic coverage, platform filter, and alias collapse are effective with
STIX source; CSV lacks that metadata.
"""
from __future__ import annotations
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

# -----------------------------
# Helpers
# -----------------------------

def norm_tid_exact(tid: str) -> str:
    return tid.strip().upper().replace("​", "")

def norm_tid_parent(tid: str) -> str:
    t = norm_tid_exact(tid)
    return t.split(".")[0]

# Default downweight set for very common techniques (override with --downweight)
DEFAULT_DOWNWEIGHT: Set[str] = {
    # Execution / Defense Evasion / Credential Access usual suspects
    "T1059",  # Command and Scripting Interpreter
    "T1047",  # Windows Management Instrumentation
    "T1053",  # Scheduled Task/Job
    "T1105",  # Ingress Tool Transfer
    "T1027",  # Obfuscated/Compressed Files and Information
    "T1003",  # OS Credential Dumping
    "T1055",  # Process Injection
}

# -----------------------------
# Loading mappings
# -----------------------------

def load_csv_mapping(csv_path: Path, mode: str) -> Dict[str, Set[str]]:
    """Load actor->technique_id mapping from a simple CSV.
    CSV columns: actor, technique_id
    """
    norm = norm_tid_parent if mode == "parent" else norm_tid_exact
    mapping: Dict[str, Set[str]] = defaultdict(set)
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            actor = row.get("actor") or row.get("Actor") or row.get("name")
            tid = row.get("technique_id") or row.get("Technique ID") or row.get("technique")
            if not actor or not tid:
                continue
            mapping[actor.strip()].add(norm(tid))
    return mapping


def extract_attack_pattern_ids(obj: dict) -> List[str]:
    """Return list of ATT&CK external IDs for an attack-pattern STIX object."""
    ids = []
    for ref in obj.get("external_references", []) or []:
        src = (ref.get("source_name") or "").lower()
        if src in {"mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"}:
            ext_id = ref.get("external_id")
            if ext_id and ext_id.upper().startswith("T"):
                ids.append(ext_id.upper())
    return ids


def load_stix_mapping(stix_path: Path, mode: str):
    """Build actor->technique_id mapping from a MITRE ATT&CK STIX bundle.
    Also returns technique metadata (tactics, platforms) and alias map.

    Returns: (actor_map_by_alias, technique_meta, alias_to_canonical)
      - actor_map_by_alias: Dict[actor_name_or_alias, Set[tid]]
      - technique_meta: Dict[tid, {"tactics": Set[str], "platforms": Set[str]}]
      - alias_to_canonical: Dict[actor_name_or_alias, canonical_primary_name]
    """
    norm = norm_tid_parent if mode == "parent" else norm_tid_exact

    with stix_path.open(encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    # Index intrusion sets and their aliases
    intrusions: Dict[str, dict] = {}
    intrusion_aliases: Dict[str, Set[str]] = defaultdict(set)
    alias_to_canonical: Dict[str, str] = {}
    for o in objects:
        if o.get("type") == "intrusion-set" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            intrusions[o["id"]] = o
            primary = (o.get("name") or o["id"]).strip()
            names: Set[str] = set()
            if primary:
                names.add(primary)
            for al in o.get("aliases", []) or []:
                if al:
                    names.add(al.strip())
            intrusion_aliases[o["id"]] = names
            for n in names:
                alias_to_canonical[n] = primary

    # Index attack-patterns by id -> list of TIDs and collect tactics/platforms
    ap_to_tids: Dict[str, List[str]] = {}
    tid_meta: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: {"tactics": set(), "platforms": set()})
    for o in objects:
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            tids = extract_attack_pattern_ids(o)
            if tids:
                ap_to_tids[o["id"]] = tids
                # Tactics from kill_chain_phases
                for kcp in o.get("kill_chain_phases", []) or []:
                    phase = (kcp.get("phase_name") or "").upper()
                    for tid in tids:
                        tid_meta[ norm(tid) ]["tactics"].add(phase)
                # Platforms
                for plat in o.get("x_mitre_platforms", []) or []:
                    for tid in tids:
                        tid_meta[ norm(tid) ]["platforms"].add(plat.upper())

    # Walk relationships: intrusion-set --uses--> attack-pattern
    actor_map_by_alias: Dict[str, Set[str]] = defaultdict(set)
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses":
            src = o.get("source_ref", "")
            tgt = o.get("target_ref", "")
            if src.startswith("intrusion-set--") and tgt.startswith("attack-pattern--"):
                if src in intrusions and tgt in ap_to_tids:
                    for alias in intrusion_aliases.get(src, {(intrusions[src].get("name") or src)}):
                        for tid in ap_to_tids[tgt]:
                            actor_map_by_alias[alias].add(norm(tid))

    return actor_map_by_alias, tid_meta, alias_to_canonical

# -----------------------------
# Scoring
# -----------------------------

def build_weight_map(downweight: Set[str]) -> Dict[str, float]:
    weights: Dict[str, float] = defaultdict(lambda: 1.0)
    for t in downweight:
        weights[t] = 0.5  # halve the contribution of noisy techniques
    return weights


def score_actors(
    observed: Set[str],
    actor_map: Dict[str, Set[str]],
    weights: Optional[Dict[str, float]] = None,
) -> List[Tuple[str, int, float, int, float, Set[str], Set[str]]]:
    """Compute overlap scores.
    Returns list of tuples: (actor, matches, weighted_matches, actor_total, jaccard, matched, missing)
    """
    if weights is None:
        weights = defaultdict(lambda: 1.0)
    results = []
    for actor, tids in actor_map.items():
        matched = observed.intersection(tids)
        if not matched:
            continue
        union = len(observed.union(tids))
        jacc = len(matched) / union if union else 0.0
        missing = observed.difference(tids)
        wsum = sum(weights.get(t, 1.0) for t in matched)
        results.append((actor, len(matched), wsum, len(tids), jacc, matched, missing))
    # Sort by weighted matches desc, then raw matches desc, then Jaccard desc, then name
    results.sort(key=lambda x: (-x[2], -x[1], -x[4], x[0].lower()))
    return results

# -----------------------------
# Formatting
# -----------------------------

def format_table(results, observed: Set[str], show_weighted: bool) -> str:
    if not results:
        return "No overlaps found."
    header = ("Actor", "Matches", "Weighted", "Actor TTPs", "Jaccard", "Matched IDs", "Missing from Actor") if show_weighted \
        else ("Actor", "Matches", "Actor TTPs", "Jaccard", "Matched IDs", "Missing from Actor")

    if show_weighted:
        rows = [header] + [
            (
                actor,
                str(matches),
                f"{w:.2f}",
                str(total),
                f"{jacc:.3f}",
                ", ".join(sorted(matched)),
                ", ".join(sorted(missing)) if missing else "",
            )
            for actor, matches, w, total, jacc, matched, missing in results
        ]
    else:
        rows = [header] + [
            (
                actor,
                str(matches),
                str(total),
                f"{jacc:.3f}",
                ", ".join(sorted(matched)),
                ", ".join(sorted(missing)) if missing else "",
            )
            for actor, matches, _w, total, jacc, matched, missing in results
        ]

    col_w = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for r in rows:
        line = " | ".join(val.ljust(col_w[i]) for i, val in enumerate(r))
        lines.append(line)
        if r is rows[0]:
            lines.append("-+-".join("-" * w for w in col_w))
    return "\n".join(lines)

# -----------------------------
# Filters (STIX-only)
# -----------------------------

def filter_by_platform(observed: Set[str], platform: Optional[str], tid_meta) -> Set[str]:
    if not platform:
        return observed
    want = platform.upper()
    keep: Set[str] = set()
    for t in observed:
        meta = tid_meta.get(t)
        if not meta:
            continue
        if any(p == want for p in meta.get("platforms", set())):
            keep.add(t)
    return keep


def tactic_coverage_ok(matched: Set[str], tid_meta, min_tactics: int) -> bool:
    if min_tactics <= 1:
        return True
    tactics: Set[str] = set()
    for t in matched:
        tactics.update(tid_meta.get(t, {}).get("tactics", set()))
    return len(tactics) >= min_tactics

# -----------------------------
# Alias collapsing (STIX-only)
# -----------------------------

def collapse_alias_actor_map(actor_map_by_alias: Dict[str, Set[str]], alias_to_canonical: Dict[str, str]) -> Dict[str, Set[str]]:
    """Merge alias keys into their canonical primary name."""
    collapsed: Dict[str, Set[str]] = defaultdict(set)
    for alias, tids in actor_map_by_alias.items():
        canon = alias_to_canonical.get(alias, alias)
        collapsed[canon].update(tids)
    return collapsed

# -----------------------------
# Main
# -----------------------------

def main():
    p = argparse.ArgumentParser(description="Score threat actors against observed ATT&CK technique IDs.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--source", choices=["stix", "csv"], help="Data source type")
    p.add_argument("--stix-file", type=Path, help="Path to MITRE ATT&CK Enterprise STIX JSON bundle")
    p.add_argument("--csv-file", type=Path, help="Path to CSV file with columns: actor,technique_id")

    p.add_argument("--ttps", nargs="*", default=[], help="Observed technique IDs, space or comma separated. Example: T1059 T1566.001 T1078")
    p.add_argument("--input-file", type=Path, help="Optional text file with one technique ID per line")

    p.add_argument("--mode", choices=["exact", "parent"], default="parent", help="Matching mode")
    p.add_argument("--min-matches", type=int, default=1, help="Only show actors with at least this many raw matches")
    p.add_argument("--min-tactics", type=int, default=1, help="(STIX) Require at least this many distinct tactics in the matched set")
    p.add_argument("--platform", type=str, help="(STIX) Filter observed TTPs to a specific platform, e.g., Windows, Linux, macOS, Network, Office 365, SaaS, IaaS, etc.")

    p.add_argument("--downweight", type=str, help="Comma-separated TIDs to downweight (0.5x). Defaults to common noisy techniques.")
    p.add_argument("--ignore", type=str, help="Comma-separated TIDs to ignore/remove from observed set")

    p.add_argument("--collapse-aliases", action="store_true", help="(STIX) Collapse synonymous actor names under the primary name")

    p.add_argument("--top", type=int, default=0, help="If > 0, limit output to top N actors")

    p.add_argument("--export-json", type=Path, help="Path to export detailed results as JSON")
    p.add_argument("--export-csv", type=Path, help="Path to export detailed results as CSV")

    args = p.parse_args()

    # Collect observed TTPs
    raw: List[str] = []
    for t in args.ttps:
        raw.extend([s for s in t.split(",") if s])
    if args.input_file and args.input_file.exists():
        with args.input_file.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    raw.append(line)

    if not raw:
        print("No observed technique IDs provided.", file=sys.stderr)
        sys.exit(2)

    norm = norm_tid_parent if args.mode == "parent" else norm_tid_exact
    observed: Set[str] = {norm(t) for t in raw}

    # Apply ignore list
    if args.ignore:
        ignore_set = {norm(t) for t in args.ignore.split(",") if t}
        observed = {t for t in observed if t not in ignore_set}

    # Load mapping & metadata
    technique_meta = {}
    alias_to_canonical = {}
    if args.source == "csv":
        if not args.csv_file:
            print("--csv-file is required with --source csv", file=sys.stderr)
            sys.exit(2)
        actor_map = load_csv_mapping(args.csv_file, args.mode)
    else:
        if not args.stix_file:
            print("--stix-file is required with --source stix", file=sys.stderr)
            sys.exit(2)
        actor_map_by_alias, technique_meta, alias_to_canonical = load_stix_mapping(args.stix_file, args.mode)
        actor_map = collapse_alias_actor_map(actor_map_by_alias, alias_to_canonical) if args.collapse_aliases else actor_map_by_alias

    # STIX-only platform filter for observed set
    if technique_meta and args.platform:
        observed = filter_by_platform(observed, args.platform, technique_meta)
        if not observed:
            print("No observed techniques remain after platform filter.")
            sys.exit(0)

    # Build weights
    down = DEFAULT_DOWNWEIGHT.copy()
    if args.downweight:
        down.update({norm(t) for t in args.downweight.split(",") if t})
    weights = build_weight_map(down)

    # Score
    raw_results = score_actors(observed, actor_map, weights)

    # Apply min-matches filter
    results = [r for r in raw_results if r[1] >= args.min_matches]

    # Apply min-tactics (STIX only)
    if technique_meta and args.min_tactics > 1:
        filtered = []
        for actor, matches, wsum, total, jacc, matched, missing in results:
            if tactic_coverage_ok(matched, technique_meta, args.min_tactics):
                filtered.append((actor, matches, wsum, total, jacc, matched, missing))
        results = filtered

    if args.top and args.top > 0:
        results = results[: args.top]

    # Print table
    show_weighted = True
    print(format_table(results, observed, show_weighted))

    # Export
    if args.export_json:
        out = []
        for actor, matches, wsum, total, jacc, matched, missing in results:
            out.append({
                "actor": actor,
                "matches": matches,
                "weighted_matches": wsum,
                "actor_total": total,
                "jaccard": jacc,
                "matched": sorted(matched),
                "missing": sorted(missing),
            })
        args.export_json.write_text(json.dumps({
            "observed": sorted(observed),
            "mode": args.mode,
            "platform": args.platform,
            "min_tactics": args.min_tactics,
            "collapse_aliases": args.collapse_aliases,
            "results": out
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.export_csv:
        with args.export_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["actor", "matches", "weighted_matches", "actor_total", "jaccard", "matched", "missing"])
            for actor, matches, wsum, total, jacc, matched, missing in results:
                w.writerow([actor, matches, f"{wsum:.6f}", total, f"{jacc:.6f}", " ".join(sorted(matched)), " ".join(sorted(missing))])


if __name__ == "__main__":
    main()


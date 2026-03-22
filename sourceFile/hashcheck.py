#!/usr/bin/env python3
"""
HashCheck: A lightweight, forensically-friendly file hashing & verification tool.

Modes:
SCAN - Produce a CSV manifest containing file paths, sizes, timestamps, and hashes.
VERIFY - Compare a live directory against a previous manifest and flags changes.

Features:
- Supports SHA-256 (default), SHA-1, and MD5
- Recursive folder scanning
- Handles large files via chunked reads (4MB)
- No external dependencies (100% Python)
"""

from __future__ import annotations
import argparse, csv, datetime, hashlib, os, sys, uuid, platform
from pathlib import Path
from typing import Iterable, Dict

CHUNK = 4 * 1024 * 1024  # 4MB

def utc_iso(ts: float) -> str:
    """
    Convert a POSIX timestamp into a clean, zero-microsecond UTC ISO formatter.
    Example: 2025-11-15T16:22:10Z
    """
    return datetime.datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"

def hash_file(path: Path, algo: str) -> Dict[str, str]:
    """
    Hash a single file using the given algorithm (sha256, sha1, md5).

    Returns a standardized dictionary containing:
    - path (absolute)
    - size_bytes
    - mtime_utc (modification time)
    - algo (hashing algorithm used)
    - hash (hex digest)
    - status ("OK" during scan)
    - error field (empty unless exception occurs)
    """
    st = path.stat()
    h = hashlib.new(algo)
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return {
        "path": str(path.resolve()),
        "size_bytes": str(st.st_size),
        "mtime_utc": utc_iso(st.st_mtime),
        "algo": algo,
        "hash": h.hexdigest(),
        "status": "OK",
        "error": "",
    }

def iter_targets(root: Path, recursive: bool) -> Iterable[Path]:
    """
    Yield every file to be processed.

    Handles:
    - Single-file hashing
    - Directory hashing (with or without recursion)
    """
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    if recursive:
        for p in root.rglob("*"):
            if p.is_file():
                yield p
    else:
        for p in root.iterdir():
            if p.is_file():
                yield p

def write_csv(rows, out_path: Path, run_meta: Dict[str, str]):
    """
    Save all scanned or verified file information to a CSV output.

    Includes run metadata:
    - run_id
    - timestamp
    - host OS information
    """
    newfile = not out_path.exists()
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # stable header
        w.writerow(["run_id","run_started_utc","tool_version","host","os","algo","path","size_bytes","mtime_utc","hash","status","error"])
        for r in rows:
            w.writerow([
                run_meta["run_id"],
                run_meta["run_started_utc"],
                run_meta["tool_version"],
                run_meta["host"],
                run_meta["os"],
                r.get("algo",""),
                r.get("path",""),
                r.get("size_bytes",""),
                r.get("mtime_utc",""),
                r.get("hash",""),
                r.get("status",""),
                r.get("error",""),
            ])

def load_manifest(manifest: Path):
    """
    Load an existing CSV manifest (created by SCAN mode).

    Returns:
        dict[path] = {"hash" : <hex>, "aglo" : <algorithm>}
    """
    data = {}
    with manifest.open("r", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        # tolerate columns order, use 'path','hash','algo'
        for row in rd:
            p = row.get("path","").strip()
            if not p:
                continue
            data[p] = {"hash": row.get("hash","").strip(), "algo": row.get("algo","sha256").strip()}
    return data

def scan(args):
    """
    SCAN MODE:
    - Walk the directory (or single file)
    - Hash everything
    - Save a baseline manifest CSV
    """
    target = Path(args.path)
    algo = args.algo.lower()
    run_meta = {
        "run_id": str(uuid.uuid4()),
        "run_started_utc": utc_iso(datetime.datetime.utcnow().timestamp()),
        "tool_version": "0.1.0",
        "host": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
    }
    rows = []
    for p in iter_targets(target, args.recursive):
        try:
            rows.append(hash_file(p, algo))
        except Exception as e:
            rows.append({
                "path": str(p.resolve()),
                "size_bytes": "",
                "mtime_utc": "",
                "algo": algo,
                "hash": "",
                "status": "ERROR",
                "error": f"{type(e).__name__}: {e}",
            })
    out = Path(args.out)
    write_csv(rows, out, run_meta)
    print(f"[+] Wrote CSV: {out} ({len(rows)} rows)")

def verify(args):
    """
    VERIFY MODE:
    - Re-hash all files
    - Compare against baseline manifest
    - Detect MISMATCH, NEW, MISSING, files
    - Produce a verification CSV report
    """
    target = Path(args.path)
    manifest = Path(args.manifest)
    known = load_manifest(manifest)
    algo = args.algo.lower()
    run_meta = {
        "run_id": str(uuid.uuid4()),
        "run_started_utc": utc_iso(datetime.datetime.utcnow().timestamp()),
        "tool_version": "0.1.0",
        "host": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
    }
    rows = []
    seen = set()
    # scan current files
    for p in iter_targets(target, args.recursive):
        try:
            rec = hash_file(p, algo)
            kpath = str(Path(rec["path"]))  # normalized absolute
            if kpath in known:
                expected = known[kpath]["hash"]
                rec["status"] = "OK" if rec["hash"] == expected else "MISMATCH"
            else:
                rec["status"] = "NEW"
            rows.append(rec)
            seen.add(kpath)
        except Exception as e:
            rows.append({
                "path": str(p.resolve()),
                "size_bytes": "",
                "mtime_utc": "",
                "algo": algo,
                "hash": "",
                "status": "ERROR",
                "error": f"{type(e).__name__}: {e}",
            })
    # find MISSING files from manifest
    for kpath in known.keys():
        if kpath not in seen:
            rows.append({
                "path": kpath,
                "size_bytes": "",
                "mtime_utc": "",
                "algo": known[kpath].get("algo", algo),
                "hash": known[kpath]["hash"],
                "status": "MISSING",
                "error": "",
            })
    out = Path(args.out)
    write_csv(rows, out, run_meta)
    # quick summary
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f"[+] Wrote CSV: {out} (OK={counts.get('OK',0)}, MISMATCH={counts.get('MISMATCH',0)}, NEW={counts.get('NEW',0)}, MISSING={counts.get('MISSING',0)}, ERROR={counts.get('ERROR',0)})")

def main():
    """
    CLI entrypoint for:
        hashcheck scan <path> --out manifest.csv
        hashcheck verify <path> --manifest manifest.csv --out verify.csv
    """
    ap = argparse.ArgumentParser(description="HashCheck starter (CLI)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_scan = sub.add_parser("scan", help="Hash files/folders and write CSV manifest")
    ap_scan.add_argument("path", help="File or directory to hash")
    ap_scan.add_argument("--algo", default="sha256", choices=["sha256","sha1","md5"], help="Hash algorithm (default: sha256)")
    ap_scan.add_argument("--recursive", action="store_true", help="Recurse into directories")
    ap_scan.add_argument("--out", default="manifest.csv", help="Output CSV path")
    ap_scan.set_defaults(func=scan)

    ap_verify = sub.add_parser("verify", help="Compare current hashes to a previous manifest CSV")
    ap_verify.add_argument("path", help="File or directory to verify")
    ap_verify.add_argument("--manifest", required=True, help="Path to existing CSV manifest")
    ap_verify.add_argument("--algo", default="sha256", choices=["sha256","sha1","md5"], help="Hash algorithm (should match manifest)")
    ap_verify.add_argument("--recursive", action="store_true", help="Recurse into directories")
    ap_verify.add_argument("--out", default="verify_report.csv", help="Output CSV path")
    ap_verify.set_defaults(func=verify)

    args = ap.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[-] Aborted by user.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
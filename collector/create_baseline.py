#!/usr/bin/env python3
"""
collector/create_baseline.py
Usage: python3 create_baseline.py --snapshots data/snapshots --out data/baseline.json
"""
import json, argparse, os, statistics, glob

def build_baseline(snapshot_files):
    hashes = {}
    modules_set = set()
    for sfile in snapshot_files:
        try:
            s = json.load(open(sfile))
        except Exception:
            continue
        fh = s.get('file_hashes', {})
        for k,v in fh.items():
            if v:
                hashes.setdefault(k, []).append(v)
        mods = s.get('modules', [])
        for m in mods:
            modules_set.add(m)
    # choose majority or first hash if consistent
    final_hashes = {k: (statistics.mode(v) if v else None) for k,v in hashes.items()}
    return {"file_hashes": final_hashes, "modules": sorted(list(modules_set))}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshots', default='data/snapshots')
    parser.add_argument('--out', default='data/baseline.json')
    args = parser.parse_args()

    files = glob.glob(os.path.join(args.snapshots, '*.json'))
    baseline = build_baseline(files)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump(baseline, f, indent=2)
    print("Baseline written to", args.out)

if __name__ == "__main__":
    main()

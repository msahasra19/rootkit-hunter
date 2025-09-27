#!/usr/bin/env python3
"""
collector/snapshot.py
Creates a JSON snapshot of host telemetry.
Usage:
  python3 snapshot.py --output data/snapshots/snap.json --targets /bin/ls,/bin/bash
"""
import psutil, hashlib, json, time, os, argparse

def hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def collect_snapshot(targets):
    snapshot = {
        "host": os.uname().nodename,
        "ts": time.time(),
        "processes": [],
        "net": [],
        "modules": [],
        "file_hashes": {}
    }

    # processes
    for p in psutil.process_iter(['pid','name','ppid','cmdline','username','cpu_percent','memory_percent','create_time']):
        try:
            snapshot['processes'].append(p.info)
        except Exception:
            pass

    # network connections
    for c in psutil.net_connections(kind='inet'):
        try:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None
            snapshot['net'].append({"laddr": laddr, "raddr": raddr, "status": c.status, "pid": c.pid})
        except Exception:
            pass

    # modules (linux)
    try:
        with open('/proc/modules') as f:
            snapshot['modules'] = [ln.split()[0] for ln in f if ln.strip()]
    except Exception:
        snapshot['modules'] = []

    # file hashes
    for t in targets:
        snapshot['file_hashes'][t] = hash_file(t)

    return snapshot

def ensure_dirs():
    os.makedirs('data/snapshots', exist_ok=True)
    os.makedirs('data/events', exist_ok=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default=None)
    parser.add_argument('--targets', default="/bin/ls,/bin/bash", help="comma-separated list")
    args = parser.parse_args()

    targets = [t.strip() for t in args.targets.split(',') if t.strip()]

    ensure_dirs()
    snap = collect_snapshot(targets)
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(snap, f, indent=2)
        print("Wrote snapshot:", args.output)
    else:
        fname = f"data/snapshots/snapshot_{int(time.time())}.json"
        with open(fname, 'w') as f:
            json.dump(snap, f)
        print("Wrote snapshot:", fname)

if __name__ == "__main__":
    main()

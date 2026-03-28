#!/usr/bin/env python3
import json, sys, os
from datetime import datetime

MANIFEST_FILE = os.path.join(os.path.dirname(__file__), '..', 'SEAL_MANIFEST.json')

def load_manifest():
    if os.path.exists(MANIFEST_FILE):
        with open(MANIFEST_FILE) as f:
            data = json.load(f)
        if "entries" not in data:
            data["entries"] = data.get("seals", [])
        return data
    return {"entries": [], "total": 0}

def append_entry(pack_path):
    with open(pack_path) as f:
        pack = json.load(f)
    
    manifest = load_manifest()
    
    entry = {
        "sealed_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": pack.get("root", ""),
        "parent": pack.get("parent", ""),
        "location": os.path.abspath(pack_path)
    }
    
    manifest["entries"].append(entry)
    manifest["total"] = len(manifest["entries"])
    
    with open(MANIFEST_FILE, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Manifest updated: {manifest['total']} entries")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: append_manifest.py <pack.json>")
        sys.exit(1)
    append_entry(sys.argv[1])

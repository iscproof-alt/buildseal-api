import json, sys, hashlib

def verify(pack_path):
    with open(pack_path) as f:
        pack = json.load(f)
    results = {}
    results["profile"] = pack.get("profile", "unknown")
    results["version"] = pack.get("version", 0)
    ch = pack.get("content_hash", {}).get("digest", "")
    results["hash"] = "OK" if ch else "MISSING"
    root = pack.get("root", "")
    results["root"] = "OK" if root else "MISSING"
    sigs = pack.get("signatures", [])
    sig = sigs[0].get("signature", "") if sigs else ""
    results["signature"] = "PRESENT" if len(sig) > 10 else "MISSING"
    parent = pack.get("parent", "")
    results["parent"] = parent if parent else "genesis"
    valid = (results["hash"] == "OK" and results["signature"] == "PRESENT" and results["root"] == "OK")
    results["verdict"] = "VALID" if valid else "INVALID"
    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    verify(sys.argv[1])

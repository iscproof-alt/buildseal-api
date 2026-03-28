#!/usr/bin/env python3
import json, sys, os

MANIFEST_FILE = os.path.join(os.path.dirname(__file__), '..', 'SEAL_MANIFEST.json')

def verify_chain():
    with open(MANIFEST_FILE) as f:
        manifest = json.load(f)
    
    entries = manifest.get("entries", [])
    
    if not entries:
        print("Manifest boş.")
        return
    
    print(f"Toplam entry: {len(entries)}")
    print("---")
    
    errors = 0
    for i, entry in enumerate(entries):
        root = entry.get("root", "")
        parent = entry.get("parent", "")
        location = entry.get("location", "")
        
        # Dosya var mı?
        file_ok = os.path.exists(location)
        
        # Parent kontrolü
        if i == 0:
            parent_ok = True  # genesis
        else:
            prev_root = entries[i-1].get("root", "")
            parent_ok = (parent == prev_root) or (parent == "")
        
        status = "✅" if (file_ok and parent_ok) else "❌"
        if not file_ok or not parent_ok:
            errors += 1
        
        print(f"{status} [{i+1}] {entry.get('sealed_at','')} root={root[:16]}...")
        if not file_ok:
            print(f"   ⚠ Dosya yok: {location}")
        if not parent_ok:
            print(f"   ⚠ Parent uyuşmuyor: {parent[:16]} != {prev_root[:16]}")
    
    print("---")
    if errors == 0:
        print("Zincir bütün. ✅")
    else:
        print(f"Zincirde {errors} hata var. ❌")

if __name__ == "__main__":
    verify_chain()

use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use serde_json::json;

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() >= 3 && args[1] == "--keygen" {
        let keyfile = &args[2];
        let signing_key = SigningKey::generate(&mut OsRng);
        let secret_bytes = signing_key.to_bytes();
        let public_bytes = signing_key.verifying_key().to_bytes();
        let fingerprint = &sha256_hex(&public_bytes)[..16];
        let key_data = json!({
            "private": hex::encode(secret_bytes),
            "public": hex::encode(public_bytes),
            "fingerprint": fingerprint
        });
        fs::write(keyfile, serde_json::to_string_pretty(&key_data).unwrap()).unwrap();
        println!("Key generated: {}", keyfile);
        println!("Fingerprint: {}", fingerprint);
        return;
    }

    if args.len() < 4 {
        eprintln!("Usage: isc_pack_v5 <content> <profile> <content_id> [--parent <hash>] [--key <keyfile>]");
        std::process::exit(2);
    }

    let content_path = &args[1];
    let profile = &args[2];
    let content_id = &args[3];

    let parent_hash = if let Some(pos) = args.iter().position(|a| a == "--parent") {
        args.get(pos + 1).cloned().unwrap_or_default()
    } else {
        String::new()
    };

    let signing_key = if let Some(pos) = args.iter().position(|a| a == "--key") {
        let keyfile = &args[pos + 1];
        let key_data: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(keyfile).expect("cannot read key file")
        ).unwrap();
        let priv_hex = key_data["private"].as_str().unwrap();
        let priv_bytes = hex::decode(priv_hex).unwrap();
        let arr: [u8; 32] = priv_bytes.try_into().unwrap();
        SigningKey::from_bytes(&arr)
    } else {
        SigningKey::generate(&mut OsRng)
    };

    let public_bytes = signing_key.verifying_key().to_bytes();
    let fingerprint = &sha256_hex(&public_bytes)[..16];

    let content_bytes = fs::read(content_path).expect("cannot read content");
    let content_hash = sha256_hex(&content_bytes);

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let sealed_at = chrono::DateTime::from_timestamp(now as i64, 0)
        .unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let mut final_pack = json!({
        "version": 5,
        "profile": profile,
        "content_id": content_id,
        "content_hash": { "alg": "sha256", "digest": content_hash },
        "parent": parent_hash,
        "claims": [],
        "sealed_at": sealed_at,
        "root": "",
        "signatures": [{ "alg": "ed25519", "public_key": hex::encode(public_bytes), "fingerprint": fingerprint, "signature": "" }]
    });

    let root_input = serde_json::to_string(&final_pack).unwrap();
    let root = sha256_hex(root_input.as_bytes());
    let sig = signing_key.sign(hex::decode(&root).unwrap().as_slice());

    final_pack["root"] = json!(root);
    final_pack["signatures"][0]["signature"] = json!(hex::encode(sig.to_bytes()));

    let pack_name = format!("{}_v5_pack.json", content_id.replace("/", "_"));
    fs::write(&pack_name, serde_json::to_string_pretty(&final_pack).unwrap()).unwrap();

    println!("ISCProof Evidence Pack V5");
    println!("profile:     {}", profile);
    println!("content_id:  {}", content_id);
    println!("hash:        {}", content_hash);
    println!("sealed_at:   {}", sealed_at);
    println!("root:        {}", root);
    println!("PACK CREATED: {}", pack_name);
}

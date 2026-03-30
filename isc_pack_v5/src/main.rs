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

fn canonical_payload(
    version: u64,
    profile: &str,
    content_id: &str,
    content_hash_alg: &str,
    content_hash_digest: &str,
    parent: &str,
    sealed_at: &str,
) -> String {
    format!(
        r#"{{"content_hash":{{"alg":{},"digest":{}}},"content_id":{},"parent":{},"profile":{},"sealed_at":{},"version":{}}}"#,
        serde_json::to_string(content_hash_alg).unwrap(),
        serde_json::to_string(content_hash_digest).unwrap(),
        serde_json::to_string(content_id).unwrap(),
        serde_json::to_string(parent).unwrap(),
        serde_json::to_string(profile).unwrap(),
        serde_json::to_string(sealed_at).unwrap(),
        version,
    )
}

fn validate_sealed_at(s: &str) -> bool {
    if s.len() != 20 { return false; }
    if !s.ends_with('Z') { return false; }
    if s.as_bytes()[10] != b'T' { return false; }
    if s.as_bytes()[13] != b':' { return false; }
    if s.as_bytes()[16] != b':' { return false; }
    true
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // keygen
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

    // verify
    if args.len() >= 3 && args[1] == "--verify" {
        let pack_path = &args[2];
        let pack_str = fs::read_to_string(pack_path).expect("cannot read pack file");
        let pack: serde_json::Value = serde_json::from_str(&pack_str).expect("invalid JSON");

        let version = pack["version"].as_u64().unwrap_or(0);
        let profile = pack["profile"].as_str().unwrap_or("");
        let content_id = pack["content_id"].as_str().unwrap_or("");
        let ch_alg = pack["content_hash"]["alg"].as_str().unwrap_or("");
        let ch_digest = pack["content_hash"]["digest"].as_str().unwrap_or("");
        let parent = pack["parent"].as_str().unwrap_or("");
        let sealed_at = pack["sealed_at"].as_str().unwrap_or("");
        let root_claim = pack["root"].as_str().unwrap_or("");

        let payload = canonical_payload(version, profile, content_id, ch_alg, ch_digest, parent, sealed_at);
        let root_computed = sha256_hex(payload.as_bytes());

        if root_computed != root_claim {
            eprintln!("FAIL: root mismatch");
            eprintln!("  claimed:  {}", root_claim);
            eprintln!("  computed: {}", root_computed);
            std::process::exit(1);
        }

        let sig_obj = &pack["signatures"][0];
        let pub_hex = sig_obj["public_key"].as_str().unwrap_or("");
        let sig_hex = sig_obj["signature"].as_str().unwrap_or("");

        let pub_bytes: [u8; 32] = hex::decode(pub_hex)
            .expect("bad public key hex")
            .try_into()
            .expect("public key wrong length");
        let sig_bytes: [u8; 64] = hex::decode(sig_hex)
            .expect("bad signature hex")
            .try_into()
            .expect("signature wrong length");

        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let verifying_key = VerifyingKey::from_bytes(&pub_bytes).expect("invalid public key");
        let signature = Signature::from_bytes(&sig_bytes);
        let root_bytes = hex::decode(&root_computed).unwrap();

        match verifying_key.verify(&root_bytes, &signature) {
            Ok(_) => {
                println!("VALID");
                println!("  root:      {}", root_computed);
                println!("  sealed_at: {}", sealed_at);
                println!("  signer:    {}", sig_obj["fingerprint"].as_str().unwrap_or("?"));

                // evidence varsa göster
                if let Some(evidence) = pack["evidence"].as_array() {
                    if evidence.is_empty() {
                        println!("  tsa:       none");
                    } else {
                        for ev in evidence {
                            let ev_type = ev["type"].as_str().unwrap_or("?");
                            let ev_hash = ev["hash"].as_str().unwrap_or("?");
                            let ts = ev["tsa_timestamp"].as_str().unwrap_or("?");
                            println!("  evidence:  type={} tsa_time={} hash={}", ev_type, ts, &ev_hash[..16]);
                        }
                    }
                } else {
                    println!("  tsa:       none");
                }
            }
            Err(_) => {
                eprintln!("FAIL: signature invalid");
                std::process::exit(1);
            }
        }
        return;
    }

    // seal
    if args.len() < 4 {
        eprintln!("Usage:");
        eprintln!("  isc_pack_v5 <content> <profile> <content_id> --key <keyfile> [--parent <hash>] [--sealed-at <YYYY-MM-DDTHH:MM:SSZ>] [--tsa-token-file <file>]");
        eprintln!("  isc_pack_v5 --keygen <keyfile>");
        eprintln!("  isc_pack_v5 --verify <pack.json>");
        std::process::exit(2);
    }

    let content_path = &args[1];
    let profile = &args[2];
    let content_id = &args[3];

    // --key zorunlu
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
        eprintln!("ERROR: --key <keyfile> zorunlu.");
        eprintln!("  Yeni key üretmek için: isc_pack_v5 --keygen <keyfile>");
        std::process::exit(2);
    };

    let parent_hash = if let Some(pos) = args.iter().position(|a| a == "--parent") {
        args.get(pos + 1).cloned().unwrap_or_default()
    } else {
        String::new()
    };

    let sealed_at = if let Some(pos) = args.iter().position(|a| a == "--sealed-at") {
        let s = args.get(pos + 1).expect("--sealed-at değeri eksik").clone();
        if !validate_sealed_at(&s) {
            eprintln!("ERROR: --sealed-at formatı geçersiz. Beklenen: YYYY-MM-DDTHH:MM:SSZ");
            std::process::exit(2);
        }
        s
    } else {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        chrono::DateTime::from_timestamp(now as i64, 0)
            .unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    };

    // --tsa-token-file opsiyonel
    let tsa_token_b64 = if let Some(pos) = args.iter().position(|a| a == "--tsa-token-file") {
        let tsa_file = args.get(pos + 1).expect("--tsa-token-file değeri eksik");
        let tsa_bytes = fs::read(tsa_file).expect("cannot read TSA token file");
        Some(base64_encode(&tsa_bytes))
    } else {
        None
    };

    let public_bytes = signing_key.verifying_key().to_bytes();
    let fingerprint = &sha256_hex(&public_bytes)[..16];

    let content_bytes = fs::read(content_path).expect("cannot read content");
    let content_hash = sha256_hex(&content_bytes);

    let payload = canonical_payload(5, profile, content_id, "sha256", &content_hash, &parent_hash, &sealed_at);
    let root = sha256_hex(payload.as_bytes());
    let sig = signing_key.sign(hex::decode(&root).unwrap().as_slice());

    // evidence — TSA token root üzerinde
    let evidence = if let Some(b64) = tsa_token_b64 {
        let token_hash = sha256_hex(&base64_decode(&b64));
        json!([{
            "type": "rfc3161_tsa",
            "covers": "root",
            "hash": token_hash,
            "token_b64": b64,
            "tsa_timestamp": sealed_at
        }])
    } else {
        json!([])
    };

    let final_pack = json!({
        "version": 5,
        "profile": profile,
        "content_id": content_id,
        "content_hash": { "alg": "sha256", "digest": content_hash },
        "parent": parent_hash,
        "claims": [],
        "sealed_at": sealed_at,
        "root": root,
        "evidence": evidence,
        "signatures": [{
            "alg": "ed25519",
            "public_key": hex::encode(public_bytes),
            "fingerprint": fingerprint,
            "signature": hex::encode(sig.to_bytes()),
            "covers": "canonical_payload_v1"
        }]
    });

    let pack_name = format!("{}_v5_pack.json", content_id.replace("/", "_"));
    fs::write(&pack_name, serde_json::to_string_pretty(&final_pack).unwrap()).unwrap();

    println!("ISCProof Evidence Pack V5");
    println!("profile:     {}", profile);
    println!("content_id:  {}", content_id);
    println!("hash:        {}", content_hash);
    println!("sealed_at:   {}", sealed_at);
    println!("root:        {}", root);
    println!("tsa:         {}", if evidence.as_array().map(|a| !a.is_empty()).unwrap_or(false) { "present" } else { "none" });
    println!("PACK CREATED: {}", pack_name);
}

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        let _ = write!(out, "{}", CHARS[(b0 >> 2)] as char);
        let _ = write!(out, "{}", CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        let _ = write!(out, "{}", if chunk.len() > 1 { CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char } else { '=' });
        let _ = write!(out, "{}", if chunk.len() > 2 { CHARS[b2 & 0x3f] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    fn val(b: u8) -> u8 {
        match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    }
    let mut out = Vec::new();
    for chunk in s.chunks(4) {
        let b0 = val(chunk[0]);
        let b1 = val(chunk[1]);
        out.push((b0 << 2) | (b1 >> 4));
        if chunk.len() > 2 { let b2 = val(chunk[2]); out.push((b1 << 4) | (b2 >> 2)); }
        if chunk.len() > 3 { let b2 = val(chunk[2]); let b3 = val(chunk[3]); out.push((b2 << 6) | b3); }
    }
    out
}

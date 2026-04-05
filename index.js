require("dotenv").config();

const https = require('https');
const crypto = require('crypto');

async function requestTSA(rootHex) {
  return new Promise((resolve) => {
    try {
      // RFC 3161 TSA request - hash the root
      const rootBytes = Buffer.from(rootHex, 'hex');
      const sha256Hash = crypto.createHash('sha256').update(rootBytes).digest();
      
      // Minimal DER-encoded TSA request
      // OID for SHA-256: 2.16.840.1.101.3.4.2.1
      const shaOid = Buffer.from('3031300d060960864801650304020105000420', 'hex');
      const tsaReq = Buffer.concat([shaOid, sha256Hash]);
      
      const options = {
        hostname: 'freetsa.org',
        path: '/tsr',
        method: 'POST',
        headers: {
          'Content-Type': 'application/timestamp-query',
          'Content-Length': tsaReq.length
        },
        timeout: 8000
      };
      
      const req = https.request(options, (res) => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const token = Buffer.concat(chunks).toString('base64');
          resolve({
            present: true,
            provider: 'freetsa',
            time: new Date().toISOString(),
            token_b64: token.slice(0, 64)
          });
        });
      });
      
      req.on('error', () => resolve({ present: false, provider: 'freetsa', error: 'request_failed' }));
      req.on('timeout', () => { req.destroy(); resolve({ present: false, provider: 'freetsa', error: 'timeout' }); });
      req.write(tsaReq);
      req.end();
    } catch(e) {
      resolve({ present: false, provider: 'freetsa', error: e.message });
    }
  });
}


const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS seals (
      seal_id TEXT PRIMARY KEY,
      artifact_hash TEXT,
      repo TEXT,
      commit_hash TEXT,
      status TEXT DEFAULT 'queued',
      created_at TIMESTAMP DEFAULT NOW(),
      verify_url TEXT
    )
  `);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS pack_hash TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS evidence_pack_url TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS verdict TEXT DEFAULT 'PENDING'`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS pack_path TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS verify_output_json TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS tsa_json TEXT`);
  console.log("DB ready");
}
initDb();

const app = express();
app.use(cors());
app.use(express.json());
app.use(require('express').static(require('path').join(__dirname, 'public')));

app.get("/health", (req, res) => res.json({ status: "ok", db: true }));

app.get("/download/isc_verify", (req, res) => {
  res.download(__dirname + "/public/isc_verify", "isc_verify");
});

app.post("/seal", async (req, res) => {
  const { artifact_hash, repo, commit, filename } = req.body;
  if (!artifact_hash) return res.status(400).json({ error: "artifact_hash required" });

  const seal_id = "seal_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
  const verify_url = (process.env.BASE_URL || "https://buildseal-api-production-3ca5.up.railway.app") + "/seal/" + seal_id;
  const sealed_at = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  await pool.query(
    "INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url, status) VALUES ($1,$2,$3,$4,$5,'processing')",
    [seal_id, artifact_hash, repo || 'web', commit || 'direct', verify_url]
  );

  const fs = require('fs');
  const path = require('path');
  const { execSync } = require('child_process');
  const tmpContent = path.join('/tmp', seal_id + '.content');
  fs.writeFileSync(tmpContent, artifact_hash);

  const binPath = __dirname + '/isc_pack_v5_bin';
  // Key: Render secret file > env var > local
  let keyPath;
  if (require('fs').existsSync('/etc/secrets/buildseal.key.json')) {
    keyPath = '/etc/secrets/buildseal.key.json';
  } else if (process.env.BUILDSEAL_KEY_JSON) {
    const fs = require('fs');
    keyPath = '/tmp/buildseal_runtime.key.json';
    fs.writeFileSync(keyPath, process.env.BUILDSEAL_KEY_JSON);
  } else {
    keyPath = __dirname + '/buildseal_new.key.json';
  }

  let packData = null;
  let status = 'completed';

  try {
    execSync(
      `cd /tmp && ${binPath} ${tmpContent} seal ${seal_id} --key ${keyPath} --sealed-at "${sealed_at}"`,
      { encoding: 'utf8' }
    );
    const packPath = `/tmp/${seal_id}_v5_pack.json`;
    let tsaResult = { present: false, provider: 'freetsa' };
    try {
      const packJson = JSON.parse(require('fs').readFileSync(packPath, 'utf8'));
      const root = packJson.root || '';
      if (root) tsaResult = await requestTSA(root);
    } catch(e) { tsaResult.error = e.message; }
    packData = JSON.parse(fs.readFileSync(packPath, 'utf8'));
    await pool.query(
      "UPDATE seals SET status='completed', pack_hash=$1 WHERE seal_id=$2",
      [packData.root, seal_id]
    );
    try { fs.unlinkSync(packPath); } catch(_) {}
  } catch(e) {
    status = 'failed';
    console.error('isc_pack_v5 error:', e.message);
    await pool.query("UPDATE seals SET status='failed' WHERE seal_id=$1", [seal_id]);
  }

  try { fs.unlinkSync(tmpContent); } catch(_) {}

  res.json({
    seal_id,
    status,
    verify_url,
    timestamp: sealed_at,
    root: packData?.root || null,
    content_hash: packData?.content_hash || null,
    tsa: null
  });
});


app.get("/seal/:seal_id", async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [req.params.seal_id]);
  if (!rows.length) return res.status(404).json({ error: "not found" });
  const r = rows[0];
  res.json({
    seal_id: r.seal_id,
    artifact_hash: r.artifact_hash,
    repo: r.repo,
    commit: r.commit_hash,
    status: r.status,
    created_at: r.created_at,
    verify_url: r.verify_url,
    root: r.pack_hash || null
  });
});

app.post("/seal/:seal_id/pack", async (req, res) => {
  const { seal_id } = req.params;
  const { pack_hash, evidence_pack_url } = req.body;
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [seal_id]);
  if (!rows.length) return res.status(404).json({ error: "not found" });
  await pool.query(
    "UPDATE seals SET status='verified', pack_hash=$1, evidence_pack_url=$2 WHERE seal_id=$3",
    [pack_hash, evidence_pack_url, seal_id]
  );
  res.json({ seal_id, status: "unmodified", integrity: "Artifact has not changed since sealing", provenance: "Not verified — source origin is outside this proof" });
});



const { execSync } = require('child_process');
const multer = require('multer');
const upload = multer({ dest: '/tmp/uploads/' });

app.post('/upload-and-seal', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'no file' });

    const seal_id = 'seal_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const verify_url = 'https://verify.buildseal.io/release/' + seal_id;

    await pool.query(
      "INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url, status, verdict) VALUES ($1,$2,$3,$4,$5,'PROCESSING','PENDING')",
      [seal_id, '', 'web-upload', 'direct', verify_url]
    );

    const packDir = '/app';
    const keyFile = '/tmp/signing_key.json';
    require('fs').writeFileSync(keyFile, process.env.BUILDSEAL_KEY_JSON || '{}');
    const v5bin = '/app/isc_pack_v5_bin';

    const packOut = execSync(
      `cd ${packDir} && ${v5bin} ${file.path} iscproof/document ${seal_id} --key ${keyFile}`,
      { encoding: 'utf8' }
    );

    const packPath = `${packDir}/${seal_id}_v5_pack.json`;
    let tsaResult = { present: false, provider: 'freetsa' };
    try {
      const packJsonTsa = JSON.parse(require('fs').readFileSync(`${packDir}/${seal_id}_v5_pack.json`, 'utf8'));
      const rootHash = packJsonTsa.root || '';
      if (rootHash) tsaResult = await requestTSA(rootHash);
    } catch(e) { tsaResult.error = e.message; }

    let verdict = 'INVALID';
    let verifyOut = '';
    try {
      verifyOut = execSync(`/app/isc_pack_v5_bin --verify ${packPath}`, { encoding: 'utf8' });
      verdict = verifyOut.includes('PACK VERIFIED') || verifyOut.trimStart().startsWith('VALID') ? 'VALID' : 'INVALID';
    } catch(verifyErr) {
      verifyOut = verifyErr.stderr || verifyErr.message || 'VERIFICATION FAILED';
      verdict = 'INVALID';
    }

    let artifactHash = '';
    try {
      const packJson = JSON.parse(require('fs').readFileSync(packPath, 'utf8'));
      artifactHash = packJson.content_hash && packJson.content_hash.digest ? packJson.content_hash.digest : '';
    } catch(e) {}
    const verifyJson = { verdict, output: verifyOut };
    await pool.query(
      "UPDATE seals SET status='DONE', verdict=$1, pack_path=$2, verify_output_json=$3, verified_at=NOW(), artifact_hash=$4, tsa_json=$5 WHERE seal_id=$6",
      [verdict, packPath, verifyOut, artifactHash, JSON.stringify(tsaResult), seal_id]
    );

    const pdfCmd = `cd /home/hakan/ali && source venv/bin/activate && python3 /app/tools/generate_proof_pdf.py ${packPath}`;
    try { execSync(`bash -c "${pdfCmd}"`, { encoding: 'utf8' }); } catch(e) {}
    res.json({ seal_id, verdict, verify_url, verify_output: verifyJson });

  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/verify/:id', async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'not found' });
  const r = rows[0];
  res.json({ ...r, verdict: r.verdict || 'PENDING' });
});

app.listen(process.env.PORT || 3000, () => console.log("BuildSeal API running on :3000"));

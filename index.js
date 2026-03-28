require("dotenv").config();
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
  const { artifact_hash, repo, commit } = req.body;
  const seal_id = "seal_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
  const verify_url = "https://verify.buildseal.io/release/" + seal_id;
  await pool.query(
    "INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url) VALUES ($1,$2,$3,$4,$5)",
    [seal_id, artifact_hash, repo, commit, verify_url]
  );
  res.json({ seal_id, status: "queued", verify_url });
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
    verify_url: r.verify_url
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

    const packDir = '/home/hakan/Isc-Core';
    const keyFile = '/home/hakan/Isc-Core/isc_pack_v4/test_key.json';
    const v5bin = '/home/hakan/Isc-Core/isc_pack_v5/target/release/isc_pack_v5';

    const packOut = execSync(
      `cd ${packDir} && ${v5bin} ${file.path} iscproof/document ${seal_id} --key ${keyFile}`,
      { encoding: 'utf8' }
    );

    const packPath = `${packDir}/${seal_id}_v5_pack.json`;

    const verifyOut = execSync(
      `python3 /home/hakan/Isc-Core/tools/verify_pack.py ${packPath}`,
      { encoding: 'utf8' }
    );

    const verifyJson = JSON.parse(verifyOut);
    const verdict = verifyJson.verdict || 'INVALID';

    await pool.query(
      "UPDATE seals SET status='DONE', verdict=$1, pack_path=$2, verify_output_json=$3, verified_at=NOW(), artifact_hash=$4 WHERE seal_id=$5",
      [verdict, packPath, verifyOut, verifyJson.hash || '', seal_id]
    );

    const pdfCmd = `cd /home/hakan/ali && source venv/bin/activate && python3 /home/hakan/Isc-Core/tools/generate_proof_pdf.py ${packPath}`;
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

app.listen(3000, () => console.log("BuildSeal API running on :3000"));

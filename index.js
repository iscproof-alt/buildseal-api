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
  console.log("DB ready");
}
initDb();

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => res.json({ status: "ok", db: true }));

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

app.listen(3000, () => console.log("BuildSeal API running on :3000"));

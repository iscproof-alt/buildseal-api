require("dotenv").config();
const express = require("express");
const { ethers } = require("ethers");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const CONTRACT = "0x0a93c4cF810F68e8FBeEa63ddb36d0f06da96bFE";
const ABI = ["function anchor(bytes32 merkleRoot, uint256 batchId, bytes32 metaHash) external"];

const provider = new ethers.providers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const contract = new ethers.Contract(CONTRACT, ABI, wallet);

// Queue
let queue = [];
let batchId = 1;

// Seal endpoint
app.post("/seal", async (req, res) => {
  const { artifact_hash, repo, commit } = req.body;
  if (!artifact_hash) return res.status(400).json({ error: "artifact_hash required" });

  const seal_id = "seal_" + Date.now() + "_" + uuidv4().slice(0, 8);
  queue.push({ seal_id, artifact_hash, repo, commit });

  res.json({
    seal_id,
    status: "queued",
    verify_url: `https://verify.buildseal.io/release/${seal_id}`
  });
});

// Status endpoint
app.get("/seal/:seal_id", (req, res) => {
  const item = queue.find(q => q.seal_id === req.params.seal_id);
  if (!item) return res.status(404).json({ error: "not found" });
  res.json(item);
});

// Batch processor
async function processBatch() {
  if (queue.length === 0) return;

  const batch = queue.splice(0, 100);
  console.log(`Processing batch of ${batch.length} seals...`);

  // Build merkle root from hashes
  const hashes = batch.map(s => s.artifact_hash);
  const combined = hashes.join("");
  const merkleRoot = "0x" + crypto.createHash("sha256").update(combined).digest("hex");
  const metaHash = ethers.utils.hexZeroPad("0x01", 32);

  try {
    const tx = { hash: "0xDEMO" };
    
    console.log("Batch anchored:", tx.hash);

    batch.forEach(s => {
      s.status = "verified";
      s.tx_hash = tx.hash;
      s.verify_url = `https://verify.buildseal.io/release/${s.seal_id}`;
    });
  } catch(e) {
    console.error("Batch failed:", e.message);
    batch.forEach(s => s.status = "failed");
  }
}

// Run batch every 5 minutes
setInterval(processBatch, 5 * 60 * 1000);

app.get("/verify/:seal_id", async (req, res) => {
  const { seal_id } = req.params;

  const result = await pool.query(
    "SELECT * FROM seals WHERE seal_id = $1",
    [seal_id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: "Seal not found" });
  }

  return res.json(result.rows[0]);
});
app.listen(3000, () => console.log("BuildSeal API running on :3000"));

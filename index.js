const express = require("express");
const { Pool } = require("pg");

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.get("/", (req, res) => {
  res.json({ status: "ok", db: !!process.env.DATABASE_URL });
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy" });
});

app.get("/release/:id", async (req, res) => {
  const id = req.params.id;

  try {
    const r = await pool.query(
      "select id, status, verify_url from releases where id=$1",
      [id]
    );

    if (r.rows.length === 0) {
      return res.send("not found");
    }

    const row = r.rows[0];

    res.send(
      "<h1>BuildSeal Verified</h1>" +
      "<p>ID: " + row.id + "</p>" +
      "<p>Status: " + row.status + "</p>" +
      "<p>URL: " + row.verify_url + "</p>"
    );
  } catch (e) {
    res.send("db error");
  }
});

app.listen(3000, () =>
  console.log("BuildSeal API with DB running on 3000")
);

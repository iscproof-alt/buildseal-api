const express = require("express");

const app = express();

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "buildseal-api" });
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy" });
});

app.get("/release/:id", (req, res) => {
  const id = req.params.id;

  res.send(`
    <html>
      <head>
        <title>BuildSeal Verify</title>
      </head>
      <body style="font-family: Arial; background:#0b0f14; color:#e6edf3; padding:40px;">
        <h1 style="color:#22c55e;">BuildSeal Verified</h1>
        <p>Seal ID: ${id}</p>
        <p>Status: OK</p>
        <p>Mode: demo (DB disabled)</p>
      </body>
    </html>
  `);
});

app.listen(3000, () => console.log("BuildSeal API running on :3000"));

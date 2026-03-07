const express = require("express");

const app = express();

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "buildseal-api" });
});

app.get("/release/:id", (req, res) => {
  const id = req.params.id;

  res.json({
    seal_id: id,
    status: "demo",
    message: "DB disabled demo mode",
    verify_url: "offline only"
  });
});

app.listen(3000, () => console.log("BuildSeal API running on :3000"));

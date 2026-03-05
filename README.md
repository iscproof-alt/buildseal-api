# BuildSeal API

Managed sealing API. Send an artifact hash, get a verification link.

No wallet. No gas. No complexity.

## API

### Seal an artifact

```bash
curl -X POST https://buildseal-api.onrender.com/seal \
  -H "Content-Type: application/json" \
  -d '{"artifact_hash":"sha256:abc123","repo":"org/repo","commit":"abc123"}'
Response:
{
  "seal_id": "seal_1741234567_a3f9c1d2",
  "status": "queued",
  "verify_url": "https://verify.buildseal.io/release/seal_1741234567_a3f9c1d2"
}
Check seal status
curl https://buildseal-api.onrender.com/seal/seal_1741234567_a3f9c1d2
How it works
Send artifact hash → queued
Every 5 minutes — batch anchored
Status becomes verified
Share verify link with auditor
Stack
Node.js + Express
PostgreSQL
Base L2 anchor
→ buildseal.io
License
MIT

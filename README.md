# BOTNEX

Python-only Telegram bot hosting control-plane foundation.

## Current features
- Account registration and login.
- Password hashing using scrypt.
- Signed bearer sessions.
- Subscription expiry checks.
- User-owned bot records (up to 5 per account).
- Python file upload, listing, reading and editing.
- Admin-only 30-day subscription activation endpoint.
- Render Blueprint template.

## Important limitations
This initial version does **not** execute uploaded Python files. Running untrusted customer code inside the web service would expose other users and platform secrets. A separate isolated worker/container runtime with strict CPU, memory, filesystem, network and process limits is required before enabling start/stop/restart.

The current file storage implementation requires persistent storage. The included Render Blueprint provisions a disk and database; review current Render pricing and availability before deploying. No service has been deployed by this repository change.

## Local run
```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `/` for the Arabic login/register page and `/docs` for API documentation.

## Environment
Set `TOKEN_SECRET` and `ADMIN_KEY` to long random secrets. Never commit production secrets.

# Zero-Context Guard — Deployment Checklist

Use this checklist before making the demo instance publicly accessible.
Tick every item before sharing the URL with judges or reviewers.

---

## Pre-launch security

-   [ ] **Auth is enabled.** `FLOWISE_USERNAME` and `FLOWISE_PASSWORD` are set and
        non-trivial (not `admin`/`admin`, not `test`, not blank).
-   [ ] **No real API keys anywhere.** Every credential stored in the Flowise
        credential store holds a fake value (e.g. `sk-FAKE-DEMO-0000000000`).
        Run a quick check: open _Credentials_ in the UI and verify no value looks like
        a real key format (`sk-…`, `ghp_…`, `Bearer …`).
-   [ ] **`HTTP_SECURITY_CHECK=true`.** The SSRF deny list must be active.
        Verify: `curl https://<your-url>/api/v1/ping` returns 200, then confirm the
        env var is set in the platform dashboard.
-   [ ] **No `DEBUG=true`.** Debug mode logs verbose output including tool inputs.
        Leave `DEBUG` unset or set to `false`.
-   [ ] **Telemetry off.** `DISABLE_FLOWISE_TELEMETRY=true` — prevents chatflow
        metadata from reaching Flowise analytics.
-   [ ] **Persistent volume mounted.** `DATABASE_PATH` and `SECRETKEY_PATH` both
        point to the mounted volume (e.g. `/data/.flowise`). Without this, the
        encryption key regenerates on every restart, invalidating all stored credentials.
-   [ ] **Volume ownership.** If the DB fails to initialise on first boot, the
        `/data` directory may be owned by root. Fix with a one-off shell command on
        the platform: `chown -R 1000:1000 /data` (UID 1000 = `node` user in the image).

---

## LLM key billing limits

If you connect a real LLM key to the demo agent (optional — the guard demo works
with fake keys and the echo endpoint):

-   [ ] **Spending cap set.** Enable a hard monthly spending cap in your LLM
        provider dashboard (e.g. OpenAI → Settings → Billing → Usage limits).
        Recommended cap for a 1-week judging window: **$5**.
-   [ ] **Restricted key scope.** Create a project-scoped API key limited to
        inference-only endpoints. Do not use your organisation root key.
-   [ ] **Key rotation plan.** Know how to revoke and rotate the key quickly if
        the demo is abused.

---

## Post-judging rotation

After the judging period ends (or if you suspect the demo password was shared):

1. **Change the demo password:**

    - Render: update the `FLOWISE_PASSWORD` environment variable → redeploy.
    - Railway: update the variable → Railway redeploys automatically.

2. **Revoke any real LLM keys** used in the demo.

3. **Delete or archive the live service** if it is no longer needed — free-tier
   services on Render and Railway still consume quota while running.

4. **Rotate JWT secrets** if you want to invalidate all existing login sessions:
   update `JWT_AUTH_TOKEN_SECRET`, `JWT_REFRESH_TOKEN_SECRET`, and
   `EXPRESS_SESSION_SECRET` then redeploy.

---

## Smoke test after deploy

Run these from your terminal (replace `<URL>` with your deployment URL):

```bash
# 1. Health check
curl -f https://<URL>/api/v1/ping
# Expected: {"ping":"pong"} or 200 OK

# 2. Auth required — unauthenticated request should 401
curl -o /dev/null -w "%{http_code}" https://<URL>/api/v1/chatflows
# Expected: 401

# 3. Authenticated
curl -u demo:<password> https://<URL>/api/v1/chatflows
# Expected: 200 with JSON array (possibly empty before chatflow import)
```

---

_Last updated: 2025-07-30 · Branch: `zero-context-guard`_
